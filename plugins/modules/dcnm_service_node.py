#!/usr/bin/python
#
# Copyright (c) 2021 Cisco and/or its affiliates.
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

import json
import copy
from ansible_collections.cisco.dcnm.plugins.module_utils.network.dcnm.dcnm import get_fabric_inventory_details, \
    dcnm_send, validate_list_of_dicts, dcnm_get_ip_addr_info, get_ip_sn_dict
from ansible.module_utils.basic import AnsibleModule

__author__ = "Karthik Babu Harichandra Babu"

DOCUMENTATION = '''
---
module: dcnm_service_node
short_description: Create/Modify/Delete service node based on type and attached interfaces from a DCNM managed VXLAN fabric.
version_added: "0.9.0"
description:
    - "Create/Modify/Delete service node based on type and attached interfaces from a DCNM managed VXLAN fabric."
author: Karthik Babu Harichandra Babu
options:
  fabric:
    description:
    - 'Name of attached easy fabric to which service node is attached'
    type: str
    required: yes
  service_fabric:
    description:
    - 'Name of external fabric where the service node is located'
    type: str
    required: yes
  state:
    description:
      - The state of DCNM after module completion.
    type: str
    choices:
      - merged
      - replaced
      - overridden
      - deleted
      - query
    default: merged

  config:
    description: 'List of details of service nodes being managed'
    type: list
    elements: dict
    required: true
    note: Not required for state deleted
    suboptions:
      name:
        description: 'Name of service node'
        type: str
        required: true
      type:
        description: 'Name of the service node type'
        type: str
        required: true
        default: 'firewall'
      form_factor:
        description: 'Name of the form factor of the service node'
        type: str
        required: true
        default: 'physical'
      svc_int_name:
        description: 'Name of the service interface'
        type: str
        required: true
      switches:
        description: 'IP address of the switch where service node will be added/deleted'
        type: list
        required: true
      attach_interface:
        description: 'List of switch interfaces where the service node will be attached'
        type: str
        required: true
'''

EXAMPLES = '''
This module supports the following states:

Merged:
  Service Nodes defined in the playbook will be merged into the service fabric.
    - If the service node does not exist it will be added.
    - If the service node exists but properties managed by the playbook are different
      they will be updated if possible.
    - Service Nodes that are not specified in the playbook will be untouched.

Replaced:
  Service Nodes defined in the playbook will be replaced in the service fabric.
    - If the service node does not exist it will be added.
    - If the service node exists but properties managed by the playbook are different
      they will be updated if possible.
    - Properties that can be managed by the module but are not specified
      in the playbook will be deleted or defaulted if possible.
    - Service Nodes that are not specified in the playbook will be untouched.

Overridden:
  Service Node defined in the playbook will be overridden in the service fabric.
    - If the service node does not exist it will be added.
    - If the service node exists but properties managed by the playbook are different
      they will be updated if possible.
    - Properties that can be managed by the module but are not specified
      in the playbook will be deleted or defaulted if possible.
    - Service Nodes that are not specified in the playbook will be deleted.

Deleted:
  Service Node defined in the playbook will be deleted.
  If no Service Nodes are provided in the playbook, all service node present on that DCNM fabric will be deleted.

Query:
  Returns the current DCNM state for the service node listed in the playbook.

- name: Merge Service Nodes
  cisco.dcnm.dcnm_service_node:
    fabric: Fabric1
    service_fabric: external
    state: merged
    config:
    - name: SN-11
      type: firewall
      form_factor: virtual
      svc_int_name: svc1
      attach_interface: Ethernet1/1
      switches:
      - 192.168.1.224
    - name: SN-12
      type: firewall
      form_factor: virtual
      svc_int_name: svc1
      attach_interface: vPC1
      switches:  # up to two switches, if two switches are provided, vpc is only option
      - 192.168.1.224
      - 192.168.1.225

- name: Replace Service Nodes form factor/type parameter
  cisco.dcnm.dcnm_service_node:
    fabric: Fabric1
    service_fabric: external
    state: replaced
    config:
    - name: SN-11
      type: firewall
   #  Replace can only modify the form factor
   #  form_factor: virtual  # the virtual will be changed to new physical
   #  form_factor: physical
      svc_int_name: svc1
      attach_interface: Ethernet1/1
      switches:
      - 192.168.1.224
   #   Nothing will be replaced in the below service node as there is no change
   #   Dont touch this if its present on DCNM
   # - name: SN-12
   #   type: firewall
   #   form_factor: virtual
   #   svc_int_name: svc1
   #   attach_interface: vPC1
   #   switches:  # up to two switches, if two switches are provided, vpc is only option
   #   - 192.168.1.224
   #   - 192.168.1.225

- name: Override Service Nodes
  cisco.dcnm.dcnm_service_node:
    fabric: Fabric1
    service_fabric: external
    state: overridden
    config:
   # Create this service node
     - name: SN-13
      type: firewall
      form_factor: virtual
      svc_int_name: svc1
      attach_interface: Ethernet1/1
      switches:
      - 192.168.1.224
   # Delete this service node from the DCNM
   # - name: SN-11
   #   type: firewall
   #   form_factor: virtual
   #   svc_int_name: svc1
   #   attach_interface: Ethernet1/1
   #   switches:
   #   - 192.168.1.224
   # Delete this service node from the DCNM
   # - name: SN-12
   #   type: firewall
   #   form_factor: virtual
   #   svc_int_name: svc1
   #   attach_interface: vPC1
   #   switches:  # up to two switches, if two switches are provided, vpc is only option
   #   - 192.168.1.224
   #   - 192.168.1.225

- name: Delete selected Service Nodes
   cisco.dcnm.dcnm_service_node:
    fabric: Fabric1
    service_fabric: external
    state: deleted
    config:
    - name: SN-11
      type: firewall
      form_factor: virtual
      svc_int_name: svc1
      attach_interface: Ethernet1/1
      switches:
      - 192.168.1.224
    - name: SN-12
      type: firewall
      form_factor: virtual
      svc_int_name: svc1
      attach_interface: vPC1
      switches:  # up to two switches, if two switches are provided, vpc is only option
      - 192.168.1.224
      - 192.168.1.225

- name: Delete all the Service Nodes
  cisco.dcnm.dcnm_service_node:
    fabric: Fabric1
    service_fabric: external
    state: deleted

- name: Query Service Nodes state for SN-11 and SN-12
  cisco.dcnm.dcnm_service_node:
    fabric: Fabric1
    service_fabric: external
    state: query
    config:
    - name: SN-11
      type: firewall
      form_factor: virtual
      svc_int_name: svc1
      attach_interface: Ethernet1/1
      switches:
      - 192.168.1.224
    - name: SN-12
      type: firewall
      form_factor: virtual
      svc_int_name: svc1
      attach_interface: vPC1
      switches:  # up to two switches, if two switches are provided, vpc is only option
      - 192.168.1.224
      - 192.168.1.225

- name: Query all the Service Nodes
  cisco.dcnm.dcnm_service_node:
    fabric: Fabric1
    service_fabric: external
    state: query
'''


class DcnmServiceNode:

    def __init__(self, module):
        self.module = module
        self.params = module.params
        self.fabric = module.params['fabric']
        self.service_fabric = module.params['service_fabric']
        self.config = copy.deepcopy(module.params.get('config'))
        self.check_mode = False
        self.have_create = []
        self.want_create = []
        self.diff_create = []
        self.diff_replace = []
        self.diff_delete = {}
        self.query = []
        self.validated = []
        self.inventory_data = get_fabric_inventory_details(self.module, self.fabric)
        self.ip_sn, self.hn_sn = get_ip_sn_dict(self.inventory_data)

        self.result = dict(
            changed=False,
            diff=[],
            response=[],
            warnings=[]
        )

        self.failed_to_rollback = False
        self.WAIT_TIME_FOR_DELETE_LOOP = 5  # in seconds

    def update_create_params(self, snode):

        if not snode:
            return snode

        state = self.params['state']

        if state == 'query':
            return {"name": snode['name']}

        serial = []
        for sw in snode['switches']:
            sw = dcnm_get_ip_addr_info(self.module, sw, None, None)
            serial.extend(ser for ip, ser in self.ip_sn.items() if ip == sw)
        if not serial:
            self.module.fail_json(
                msg=f"Fabric: {self.fabric} does not have the switch: {snode['switches']}"
            )


        switchsn = ""
        if len(snode['switches']) == 2:
            switchsn = f"{str(serial[0])},{str(serial[1])}"
            if 'vPC' not in snode['attach_interface']:
                self.module.fail_json(
                    msg=f'Fabric: {self.fabric} - if two switches are provided, vpc is only interface option'
                )

        elif len(snode['switches']) == 1:
            switchsn = str(serial[0])
            if 'vPC' in snode['attach_interface']:
                self.module.fail_json(
                    msg=f'Fabric: {self.fabric} - For 1 switch, vpc is not the interface option'
                )

        else:
            self.module.fail_json(
                msg=f'Fabric: {self.fabric} - Upto 2 switches only allowed'
            )


        if snode['type'] == 'firewall':
            s_type = snode['type'].title()
        elif snode['type'] == 'load_balancer':
            s_type = 'ADC'
        elif snode['type'] == 'virtual_network_function':
            s_type = 'VNF'

        return {
            "name": snode['name'],
            "type": s_type,
            "formFactor": snode['form_factor'].title(),
            "fabricName": self.service_fabric,
            "interfaceName": snode['svc_int_name'],
            "attachedSwitchSn": switchsn,
            "attachedSwitchInterfaceName": snode['attach_interface'],
            "linkTemplateName": "service_link_trunk",
            "nvPairs": {
                "MTU": "jumbo",
                "SPEED": "Auto",
                "ALLOWED_VLANS": "none",
                "BPDUGUARD_ENABLED": "no",
                "PORTTYPE_FAST_ENABLED": "true",
                "ADMIN_STATE": "true",
            },
            "attachedFabricName": self.fabric,
        }

    def get_have(self):

        method = 'GET'
        path = f'/appcenter/Cisco/elasticservice/elasticservice-api/?attached-fabric={self.fabric}'


        snode_objects = dcnm_send(self.module, method, path)
        missing_fabric, not_ok = self.handle_response(snode_objects, 'query_dcnm')

        if missing_fabric or not_ok:
            msg1 = f"Fabric {self.fabric} not present on DCNM"
            msg2 = f"Unable to Service Node under fabric: {self.fabric}"

            self.module.fail_json(msg=msg1 if missing_fabric else msg2)
            return

        if not snode_objects['DATA']:
            return

        have_switch = []
        for snode in snode_objects['DATA']:
            get_snode = {
                'name': snode['name'],
                'formFactor': snode['formFactor'],
                'interfaceName': snode['interfaceName'],
                'type': snode['type'],
                'attachedFabricName': snode['attachedFabricName'],
                'attachedSwitchInterfaceName': snode[
                    'attachedSwitchInterfaceName'
                ],
                'attachedSwitchSn': snode['attachedSwitchSn'],
                'fabricName': snode['fabricName'],
            }

            have_switch.append(get_snode)

        self.have_create = have_switch

    def get_want(self):

        if not self.config:
            return

        want_create = [self.update_create_params(snode) for snode in self.validated]
        self.want_create = want_create

    def get_diff_delete(self):

        diff_delete = []

        if self.config:
            for want_c in self.want_create:
                diff_delete.extend(
                    have_c['name']
                    for have_c in self.have_create
                    if (have_c['name'] == want_c['name'])
                )

        else:
            diff_delete.extend(have_c['name'] for have_c in self.have_create)
        self.diff_delete = diff_delete

    def get_diff_override(self):

        self.get_diff_replace()
        self.get_diff_replace_delete()

        diff_create = self.diff_create
        diff_delete = self.diff_delete

        self.diff_create = diff_create
        self.diff_delete = diff_delete
        self.diff_replace = []

    def get_diff_replace(self):

        self.get_diff_merge()
        diff_replace = self.diff_create

        self.diff_replace = diff_replace

        found = False
        for replace_c in self.diff_replace:
            for have_c in self.have_create:
                if have_c['name'] == replace_c['name']:
                    found = True

        if not found:
            self.diff_replace = []
        else:
            self.diff_create = []

    def get_diff_replace_delete(self):

        diff_delete = []

        for have_c in self.have_create:
            match_found = any(
                want_c['name'] == have_c['name']
                and want_c['type'] == have_c['type']
                and want_c['attachedFabricName'] == have_c['attachedFabricName']
                and want_c['fabricName'] == have_c['fabricName']
                and want_c['attachedSwitchInterfaceName']
                == have_c['attachedSwitchInterfaceName']
                and want_c['attachedSwitchSn'] == have_c['attachedSwitchSn']
                and want_c['interfaceName'] == have_c['interfaceName']
                for want_c in self.want_create
            )

            if match_found:
                continue
            else:
                diff_delete.append(have_c['name'])

        self.diff_delete = diff_delete

    def get_diff_merge(self, replace=False):

        diff_create = []

        for want_c in self.want_create:
            found = any(
                want_c['name'] == have_c['name']
                and want_c['type'] == have_c['type']
                and want_c['attachedFabricName'] == have_c['attachedFabricName']
                and want_c['fabricName'] == have_c['fabricName']
                and want_c['attachedSwitchInterfaceName']
                == have_c['attachedSwitchInterfaceName']
                and want_c['attachedSwitchSn'] == have_c['attachedSwitchSn']
                and want_c['interfaceName'] == have_c['interfaceName']
                and want_c['formFactor'] == have_c['formFactor']
                for have_c in self.have_create
            )

            if not found:
                diff_create.append(want_c)

        self.diff_create = diff_create

    def get_diff_query(self):

        query = []
        method = 'GET'
        path = f'/appcenter/Cisco/elasticservice/elasticservice-api/?attached-fabric={self.fabric}'


        snode_objects = dcnm_send(self.module, method, path)

        missing_fabric, not_ok = self.handle_response(snode_objects, 'query_dcnm')

        if missing_fabric or not_ok:
            msg1 = f"Fabric {self.fabric} not present on DCNM"
            msg2 = f"Unable to find Service Node under fabric: {self.fabric}"

            self.module.fail_json(msg=msg1 if missing_fabric else msg2)
            return

        if not snode_objects['DATA']:
            return

        if self.config:
            for want_c in self.want_create:
                query.extend(
                    snode
                    for snode in snode_objects['DATA']
                    if want_c['name'] == snode['name']
                )

        else:
            query.extend(iter(snode_objects['DATA']))
        self.query = query

    def push_to_remote(self, is_rollback=False):

        method = 'DELETE'
        if self.diff_delete:
            for name in self.diff_delete:
                delete_path = f'/appcenter/Cisco/elasticservice/elasticservice-api/fabrics/{self.service_fabric}/service-nodes/{name}'

                resp = dcnm_send(self.module, method, delete_path)

                self.result['response'].append(resp)
                fail, self.result['changed'] = self.handle_response(resp, "delete")

                if fail:
                    if is_rollback:
                        self.failed_to_rollback = True
                        return
                    self.failure(resp)

        method = 'POST'
        if self.diff_create:
            for create in self.diff_create:
                deploy_path = f'/appcenter/Cisco/elasticservice/elasticservice-api/fabrics/{self.service_fabric}/service-nodes'

                resp = dcnm_send(self.module, method, deploy_path, json.dumps(create))
                self.result['response'].append(resp)
                fail, self.result['changed'] = self.handle_response(resp, "create")

                if fail:
                    if is_rollback:
                        self.failed_to_rollback = True
                        return
                    self.failure(resp)

        method = 'PUT'
        if self.diff_replace:
            for replace in self.diff_replace:
                replace_path = f"/appcenter/Cisco/elasticservice/elasticservice-api/fabrics/{self.service_fabric}/service-nodes/{replace['name']}"

                resp = dcnm_send(self.module, method, replace_path, json.dumps(replace))

                self.result['response'].append(resp)
                fail, self.result['changed'] = self.handle_response(resp, "create")

                if fail:
                    if is_rollback:
                        self.failed_to_rollback = True
                        return
                    self.failure(resp)

    def validate_input(self):

        """Parse the playbook values, validate to param specs."""

        state = self.params['state']

        if state == 'query':

            snode_spec = dict(
                name=dict(required=True, type='str', length_max=64),
            )

            if self.config:
                # Validate service node params
                valid_snode, invalid_params = validate_list_of_dicts(self.config, snode_spec)
                for snode in valid_snode:
                    self.validated.append(snode)

                if invalid_params:
                    msg = 'Invalid parameters in playbook: {}'.format('\n'.join(invalid_params))
                    self.module.fail_json(msg=msg)

        else:

            snode_spec = dict(
                name=dict(required=True, type='str', length_max=64),
                type=dict(required=True, type='str',
                          choices=['firewall', 'load_balancer', 'virtual_network_function'],
                          default='firewall'),
                form_factor=dict(required=True, type='str',
                                 choices=['physical', 'virtual'],
                                 default='physical'),
                svc_int_name=dict(required=True, type='str', length_max=64),
                switches=dict(required=True, type='list'),
                attach_interface=dict(required=True, type='str'),
            )

            msg = None
            if self.config:
                # Validate service node params
                valid_snode, invalid_params = validate_list_of_dicts(self.config, snode_spec)
                for snode in valid_snode:
                    self.validated.append(snode)

                if invalid_params:
                    msg = 'Invalid parameters in playbook: {}'.format('\n'.join(invalid_params))
                    self.module.fail_json(msg=msg)

            else:
                state = self.params['state']
                if state in ['merged', 'overridden', 'replaced']:
                    msg = f"config: element is mandatory for this state {state}"

            if msg:
                self.module.fail_json(msg=msg)

    def handle_response(self, resp, op):

        fail = False
        changed = True

        res = resp.copy()

        if op == 'query_dcnm':
            # This if blocks handles responses to the query APIs against DCNM.
            # Basically all GET operations.
            #
            if res.get('ERROR') == 'Not Found' and res['RETURN_CODE'] == 404:
                return True, False
            if res['RETURN_CODE'] != 200 or res['MESSAGE'] != "":
                return False, True
            return False, False

        # Responses to all other operations POST and PUT are handled here.
        if res.get('MESSAGE') != "" or res.get('RETURN_CODE') != 200:
            fail = True
            changed = False
            return fail, changed

        return fail, changed

    def failure(self, resp):

        # Implementing a per task rollback logic here so that we rollback DCNM to the have state
        # whenever there is a failure in any of the APIs.
        # The idea would be to run overridden state with want=have and have=dcnm_state
        self.want_create = self.have_create
        self.have_create = []
        self.get_have()
        self.get_diff_override()

        self.push_to_remote(True)

        if self.failed_to_rollback:
            msg1 = "FAILED - Attempted rollback of the task has failed, may need manual intervention"
        else:
            msg1 = 'SUCCESS - Attempted rollback of the task has succeeded'

        res = copy.deepcopy(resp)
        res.update({'ROLLBACK_RESULT': msg1})

        if not resp.get('DATA'):
            data = copy.deepcopy(resp.get('DATA'))
            if data.get('stackTrace'):
                data.update({'stackTrace': 'Stack trace is hidden, use \'-vvvvv\' to print it'})
                res.update({'DATA': data})

        if self.module._verbosity >= 5:
            self.module.fail_json(msg=res)

        self.module.fail_json(msg=res)


def main():
    """ main entry point for module execution
    """

    element_spec = dict(
        fabric=dict(required=True, type='str'),
        service_fabric=dict(required=True, type='str'),
        config=dict(required=False, type='list'),
        state=dict(default='merged',
                   choices=['merged', 'replaced', 'deleted', 'overridden', 'query']),
        check_mode=dict(required=False, type="bool", default=False)
    )

    module = AnsibleModule(argument_spec=element_spec,
                           supports_check_mode=True)

    dcnm_snode = DcnmServiceNode(module)

    if not dcnm_snode.ip_sn:
        module.fail_json(
            msg=f"Fabric {dcnm_snode.fabric} missing on DCNM or does not have any switches"
        )


    dcnm_snode.validate_input()

    dcnm_snode.get_want()
    dcnm_snode.get_have()

    if module.params['state'] == 'merged':
        dcnm_snode.get_diff_merge()

    if module.params['state'] == 'replaced':
        dcnm_snode.get_diff_replace()

    if module.params['state'] == 'overridden':
        dcnm_snode.get_diff_override()

    if module.params['state'] == 'deleted':
        dcnm_snode.get_diff_delete()
    #
    if module.params['state'] == 'query':
        dcnm_snode.get_diff_query()
        dcnm_snode.result['response'] = dcnm_snode.query

    if module.params['check_mode']:
        dcnm_snode.result['changed'] = False
        module.exit_json(**dcnm_snode.result)

    if dcnm_snode.diff_create or dcnm_snode.diff_delete or dcnm_snode.diff_replace:
        dcnm_snode.result['changed'] = True
    else:
        module.exit_json(**dcnm_snode.result)

    dcnm_snode.push_to_remote()

    module.exit_json(**dcnm_snode.result)


if __name__ == '__main__':
    main()
