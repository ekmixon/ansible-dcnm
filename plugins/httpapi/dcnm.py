from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
---
author: Mike Wiebe (mikewiebe)
httpapi: dcnm
short_description: Send REST api calls to Data Center Network Manager (DCNM) NX-OS Fabric Controller.
description:
  - This DCNM plugin provides the HTTPAPI transport methods needed to initiate
    a connection to the DCNM controller, send API requests and process the
    respsonse from the controller.
version_added: "2.10"
"""

import json
import re
import collections
import requests
import sys

from ansible.module_utils._text import to_text
from ansible.module_utils.connection import ConnectionError
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import to_list
from ansible.plugins.httpapi import HttpApiBase


class HttpApi(HttpApiBase):

    def __init__(self, *args, **kwargs):
        super(HttpApi, self).__init__(*args, **kwargs)
        self.headers = {
            'Content-Type': "application/json"
        }

    def login(self, username, password):
        ''' DCNM Login Method.  This method is automatically called by the
            Ansible plugin architecture if an active Dcnm-Token is not already
            available.
        '''
        method = 'POST'
        path = '/rest/logon'

        # Ansible expresses the persistent_connect_timeout in seconds.
        # This value needs to be converted to milliseconds for DCNM
        timeout = self.connection.get_option("persistent_connect_timeout") * 1000
        data = "{'expirationTime': %s}" % timeout

        try:
            response, response_data = self.connection.send(path, data, method=method, headers=self.headers, force_basic_auth=True)
            response_value = self._get_response_value(response_data)
            self.connection._auth = {'Dcnm-Token': self._response_to_json(response_value)['Dcnm-Token']}
        except Exception as e:
            msg = 'Error on attempt to connect and authenticate with DCNM controller: {}'.format(e)
            raise ConnectionError(self._return_info(None, method, path, msg))

    def logout(self):
        method = 'POST'
        path = '/rest/logout'

        try:
            response, response_data = self.connection.send(path, {}, method=method, headers=self.headers, force_basic_auth=True)
        except Exception as e:
            msg = 'Error on attempt to logout from DCNM controller: {}'.format(e)
            raise ConnectionError(self._return_info(None, method, path, msg))

        self._verify_response(response, method, path, response_data)
        # Clean up tokens
        self.connection._auth = None

    def send_request(self, method, path, json=None):
        ''' This method handles all DCNM REST API requests other then login '''
        if json is None:
            json = {}

        try:
            # Perform some very basic path input validation.
            path = str(path)
            if path[0] != '/':
                msg = 'Value of <path> does not appear to be formated properly'
                raise ConnectionError(self._return_info(None, method, path, msg))
            response, rdata = self.connection.send(path, json, method=method,
                                                   headers=self.headers,
                                                   force_basic_auth=True)
            return self._verify_response(response, method, path, rdata)
        except Exception as e:
            eargs = e.args[0]
            if isinstance(eargs, dict) and eargs.get('METHOD'):
                return eargs
            raise ConnectionError(str(e))

    def _verify_response(self, response, method, path, rdata):
        ''' Process the return code and response object from DCNM '''

        rv = self._get_response_value(rdata)
        jrd = self._response_to_json(rv)
        rc = response.getcode()
        path = response.geturl()
        msg = response.msg
        if rc >= 200 and rc <= 299:
            return self._return_info(rc, method, path, msg, jrd)
        if rc >= 400:
            # Add future error code processing here
            pass
        else:
            msg = 'Unknown RETURN_CODE: {}'.format(rc)
        raise ConnectionError(self._return_info(rc, method, path, msg, jrd))

    def _get_response_value(self, response_data):
        ''' Extract string data from response_data returned from DCNM '''
        return to_text(response_data.getvalue())

    def _response_to_json(self, response_text):
        ''' Convert response_text to json format '''
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except ValueError:
            return 'Invalid JSON response: {}'.format(response_text)

    def _return_info(self, rc, method, path, msg, json_respond_data=None):
        ''' Format success/error data and return with consistent format '''

        info = {}
        info['RETURN_CODE'] = rc
        info['METHOD'] = method
        info['REQUEST_PATH'] = path
        info['MESSAGE'] = msg
        info['DATA'] = json_respond_data

        return info