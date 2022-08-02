#!/usr/bin/python
#
# Copyright (c) 2020 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import socket
import json
import time
from ansible.module_utils.common import validation
from ansible.module_utils.connection import Connection


def validate_ip_address_format(type, item, invalid_params):

    if type in ['ipv4_subnet', 'ipv4']:
        addr_type = 'IPv4'
        addr_family = socket.AF_INET
        mask_len = 32
    if type in ['ipv6_subnet', 'ipv6']:
        addr_type = 'IPv6'
        addr_family = socket.AF_INET6
        mask_len = 128

    if (item.strip() != ''):
        address = item.split('/')[0]
        if ('subnet' in type):
            if '/' in item:
                subnet = item.split('/')[1]
                if not subnet or int(subnet) > mask_len:
                    invalid_params.append(f'{item} : Invalid {addr_type} gw/subnet syntax')
            else:
                invalid_params.append(f'{item} : Invalid {addr_type} gw/subnet syntax')
        try:
            socket.inet_pton(addr_family, address)
        except socket.error:
            invalid_params.append(f'{item} : Invalid {addr_type} address syntax')


def validate_list_of_dicts(param_list, spec, module=None):
    """ Validate/Normalize playbook params. Will raise when invalid parameters found.
    param_list: a playbook parameter list of dicts
    spec: an argument spec dict
          e.g. spec = dict(ip=dict(required=True, type='ipv4'),
                           foo=dict(type='str', default='bar'))
    return: list of normalized input data
    """
    v = validation
    normalized = []
    invalid_params = []
    for list_entry in param_list:
        valid_params_dict = {}
        for param in spec:
            item = list_entry.get(param)
            if item is None:
                if spec[param].get('required'):
                    invalid_params.append(f'{param} : Required parameter not found')
                else:
                    item = spec[param].get('default')
            else:
                type = spec[param].get('type')
                if type == 'str':
                    item = v.check_type_str(item)
                    if spec[param].get('length_max'):
                        if 1 <= len(item) <= spec[param].get('length_max'):
                            pass
                        elif param != "vrf_name" or len(item) > spec[param].get(
                            'length_max'
                        ):
                            invalid_params.append(
                                f"{param}:{item} : The string exceeds the allowed range of max {spec[param].get('length_max')} char"
                            )

                elif type == 'int':
                    item = v.check_type_int(item)
                    if spec[param].get('range_max') and not 1 <= item <= spec[
                        param
                    ].get('range_max'):
                        invalid_params.append(
                            f"{param}:{item} : The item exceeds the allowed range of max {spec[param].get('range_max')}"
                        )

                elif type == 'bool':
                    item = v.check_type_bool(item)
                elif type == 'list':
                    item = v.check_type_list(item)
                elif type == 'dict':
                    item = v.check_type_dict(item)
                elif type in ['ipv4_subnet', 'ipv4', 'ipv6_subnet', 'ipv6']:
                    validate_ip_address_format(type, item, invalid_params)

                if choice := spec[param].get('choices'):
                    if item not in choice:
                        invalid_params.append(f'{item} : Invalid choice provided')

                if no_log := spec[param].get('no_log'):
                    if module is not None:
                        module.no_log_values.add(item)
                    else:
                        msg = (
                            f"\n\n'{param}' is a no_log parameter"
                            + "\nAnsible module object must be passed to this "
                        )

                        msg += "\nfunction to ensure it is not logged\n\n"
                        raise Exception(msg)

            valid_params_dict[param] = item
        normalized.append(valid_params_dict)

    return normalized, invalid_params


def get_fabric_inventory_details(module, fabric):

    inventory_data = {}
    rc = False
    method = 'GET'
    path = f'/rest/control/fabrics/{fabric}/inventory'

    count = 1
    while not rc:

        response = dcnm_send(module, method, path)

        if not response.get('RETURN_CODE'):
            rc = True
            module.fail_json(msg=response)

        if response.get('RETURN_CODE') == 404:
            # RC 404 - Object not found
            rc = True
            return inventory_data

        if response.get('RETURN_CODE') == 401:
            if count > 20:
                raise Exception(response)
            count = count + 1
            rc = False
            time.sleep(0.1)
            continue
        elif response.get('RETURN_CODE') >= 400:
            # Handle additional return codes as needed but for now raise
            # for any error other then 404.
            raise Exception(response)

        for device_data in response.get('DATA'):
            key = device_data.get('ipAddress')
            inventory_data[key] = device_data
        rc = True

    return inventory_data


def get_ip_sn_dict(inventory_data):

    ip_sn = {}
    hn_sn = {}

    for device_key in inventory_data.keys():
        ip = inventory_data[device_key].get('ipAddress')
        sn = inventory_data[device_key].get('serialNumber')
        hn = inventory_data[device_key].get('logicalName')
        ip_sn[ip] = sn
        hn_sn[hn] = sn

    return ip_sn, hn_sn


# This call is mainly used while configuraing multisite fabrics.
# It maps the switch IP Address/Serial No. in the multisite inventory
# data to respective member site fabric name to which it was actually added.
def get_ip_sn_fabric_dict(inventory_data):
    """
    Maps the switch IP Address/Serial No. in the multisite inventory
    data to respective member site fabric name to which it was actually added.

    Parameters:
        inventory_data: Fabric inventory data

    Returns:
        dict: Switch ip - fabric_name mapping
        dict: Switch serial_no - fabric_name mapping
    """
    ip_fab = {}
    sn_fab = {}

    for device_key in inventory_data.keys():
        ip = inventory_data[device_key].get('ipAddress')
        sn = inventory_data[device_key].get('serialNumber')
        fabric_name = inventory_data[device_key].get('fabricName')
        ip_fab[ip] = fabric_name
        sn_fab[sn] = fabric_name

    return ip_fab, sn_fab


# sw_elem can be ip_addr, hostname, dns name or serial number. If the given
# sw_elem is ip_addr, then it is returned as is. If DNS or hostname then a DNS
# lookup is performed to get the IP address to be returned. If not ip_sn
# database (if not none) is looked up to find the mapping IP address which is
# returned
def dcnm_get_ip_addr_info(module, sw_elem, ip_sn, hn_sn):

    msg_dict = {'Error': ''}
    msg = 'Given switch elem = "{}" is not a valid one for this fabric\n'
    # Check if the given sw_elem is a v4 ip_addr
    try:
        socket.inet_pton(socket.AF_INET, sw_elem)
        ip_addr = sw_elem
    except socket.error:
        # Check if the given sw_elem is a v6 ip_addr
        try:
            socket.inet_pton(socket.AF_INET6, sw_elem)
            ip_addr = sw_elem
        except socket.error:
            # Not legal
            ip_addr = []
    if not ip_addr:
        msg1 = 'Given switch elem = "{}" cannot be validated, provide a valid ip_sn object\n'

        # Given element is not an IP address. Try DNS or
        # hostname
        try:
            addr_info = socket.getaddrinfo(sw_elem, 0, socket.AF_INET, 0, 0, 0)
            if (None is ip_sn):
                return addr_info[0][4][0]
            if addr_info:
                if (addr_info[0][4][0] in ip_sn.keys()):
                    return addr_info[0][4][0]
                msg_dict['Error'] = msg.format(sw_elem)
                raise module.fail_json(msg=json.dumps(msg_dict))
        except socket.gaierror:
            if (None is ip_sn):
                msg_dict['Error'] = msg1.format(sw_elem)
                raise module.fail_json(msg=json.dumps(msg_dict))
            sno = hn_sn.get(sw_elem, None) if (None is not hn_sn) else None
            if (sno is not None):
                ip_addr = [k for k, v in ip_sn.items() if v == sno]
            else:
                ip_addr = [k for k, v in ip_sn.items() if v == sw_elem]
            if ip_addr:
                return ip_addr[0]
            msg_dict['Error'] = msg.format(sw_elem)
            raise module.fail_json(msg=json.dumps(msg_dict))
    else:
        # Given sw_elem is an ip_addr. check if this is valid
        if (None is ip_sn):
            return ip_addr
        if (ip_addr in ip_sn.keys()):
            return ip_addr
        msg_dict['Error'] = msg.format(sw_elem)
        raise module.fail_json(msg=json.dumps(msg_dict))


# This call is used to get the details of the given fabric from the DCNM
def get_fabric_details(module, fabric):
    """
    Used to get the details of the given fabric from the DCNM

    Parameters:
        module: Data for module under execution
        fabric: Fabric name

    Returns:
        dict: Fabric details
    """
    fabric_data = {}
    rc = False
    method = 'GET'
    path = f'/rest/control/fabrics/{fabric}'

    count = 1
    while not rc:

        response = dcnm_send(module, method, path)

        if not response.get('RETURN_CODE'):
            rc = True
            module.fail_json(msg=response)

        if response.get('RETURN_CODE') == 404:
            # RC 404 - Object not found
            rc = True
            return fabric_data

        if response.get('RETURN_CODE') == 401:
            if count > 20:
                raise Exception(response)
            count = count + 1
            rc = False
            time.sleep(0.1)
            continue
        elif response.get('RETURN_CODE') >= 400:
            # Handle additional return codes as needed but for now raise
            # for any error other then 404.
            raise Exception(response)

        fabric_data = response.get('DATA')
        rc = True

    return fabric_data


def dcnm_send(module, method, path, data=None, data_type='json'):

    conn = Connection(module._socket_path)

    if (data_type == 'json'):
        return conn.send_request(method, path, data)
    elif (data_type == 'text'):
        return conn.send_txt_request(method, path, data)


def dcnm_reset_connection(module):

    conn = Connection(module._socket_path)

    conn.logout()
    return conn.login(conn.get_option("remote_user"), conn.get_option("password"))
