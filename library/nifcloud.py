#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2017 FUJITSU CLOUD TECHNOLOGIES LIMITED
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

import base64
import hashlib
import hmac
import time
import xml.etree.ElementTree as etree

import requests
from ansible.module_utils.basic import *  # noqa

try:
    # Python 2
    from urllib import quote, urlencode
except ImportError:
    # Python 3
    from urllib.parse import quote, urlencode

DOCUMENTATION = '''
---
module: nifcloud
short_description: create, start or stop an instance in NIFCLOUD
description:
    - Create, start or stop an instance of NIFCLOUD
version_added: "0.1"
options:
    access_key:
        description:
            - Access key
        required: true
    secret_access_key:
        description:
            - Secret access key
        required: true
    endpoint:
        despcription:
            - API endpoint of target region.
        required: true
    instance_id:
        description:
            - Instance ID
        required: true
    state:
        description:
            - Goal status ("running" or "stopped")
        required: true
    image_id:
        description:
            - Image ID (required for create)
        required: false
        default: null
    key_name:
        description:
            - SSH key name (required for create)
        required: false
        default: null
    security_group:
        description:
            - Member of security group (Firewall group name)
        required: false
        default: null
    instance_type:
        description:
            - Instance type
        required: false
        default: null
    availability_zone:
        description:
            - Availability zone
        required: false
        default: null
    accounting_type:
        description:
            - Accounting type (1: monthly, 2: pay per use)
        required: false
        default: null
    ip_type:
        description:
            - IP Address type (static, elastic or none)
        required: false
        default: null
    public_ip:
        description:
            - Elastic public IP address (required if ip_type = elastic)
        required: false
        default: null
    startup_script:
        description:
            - Startup script template file path
        required: false
        default: null
    startup_script_vars:
        description:
            - Variables for startup script template
        type: Dictionary
        required: false
        default: {}
    network_interface:
        description:
            - NetworkInterface
        type: List
        required: false
        default: []
'''

EXAMPLES = '''
- action: nifcloud access_key="YOUR_ACCESS_KEY" secret_access_key="YOUR_SECRET_ACCESS_KEY" endpoint="west-1.cp.cloud.nifty.com" instance_id="test001" state="running" image_id="26" key_name="YOUR_SSH_KEY_NAME" security_group="webapp" instance_type="mini" availability_zone="west-11" accounting_type="2" ip_type="static"
'''  # noqa


def calculate_signature(secret_access_key, method, endpoint, path, params):
    payload = ""
    for v in sorted(params.items()):
        payload += '&{0}={1}'.format(v[0], quote(str(v[1]), ''))
    payload = payload[1:]

    string_to_sign = [method, endpoint, path, payload]
    digest = hmac.new(
        secret_access_key,
        '\n'.join(string_to_sign),
        hashlib.sha256
    ).digest()

    return base64.b64encode(digest)


def request_to_api(module, method, action, params):
    params['Action'] = action
    params['AccessKeyId'] = module.params['access_key']
    params['SignatureMethod'] = 'HmacSHA256'
    params['SignatureVersion'] = '2'

    path = '/api/'
    endpoint = module.params['endpoint']

    params['Signature'] = calculate_signature(
        module.params['secret_access_key'],
        method,
        endpoint,
        path,
        params
    )

    r = None
    if method == 'GET':
        url = 'https://{0}{1}?{2}'.format(endpoint, path,
                                          urlencode(params))
        r = requests.get(url)
    elif method == 'POST':
        url = 'https://{0}{1}'.format(endpoint, path)
        r = requests.post(url, urlencode(params))
    else:
        module.fail_json(
            status=-1,
            msg='changes failed (un-supported http method)'
        )

    if r is not None:
        body = r.text.encode('utf-8')
        xml = etree.fromstring(body)
        info = dict(
            status=r.status_code,
            xml_body=xml,
            xml_namespace=dict(nc=xml.tag[1:].split('}')[0])
        )
        return info
    else:
        module.fail_json(status=-1, msg='changes failed (http request failed)')


def get_api_error(xml_body):
    info = dict(
        code=xml_body.find('.//Errors/Error/Code').text,
        message=xml_body.find('.//Errors/Error/Message').text
    )
    return info


def get_instance_state(module):
    params = dict()
    params['InstanceId.1'] = module.params['instance_id']
    res = request_to_api(module, 'GET', 'DescribeInstances', params)

    if res['status'] == 200:
        pattern = ('.//{{{nc}}}instanceState/{{{nc}}}code'
                   .format(**res['xml_namespace']))
        return int(res['xml_body'].find(pattern).text)
    else:
        return -1


def configure_user_data(module, params):
    startup_script_path = module.params['startup_script']
    startup_script_vars = module.params['startup_script_vars']

    if not startup_script_path:
        return

    try:
        with open(startup_script_path, 'r') as fp:
            startup_script_template = fp.read()
            startup_script = startup_script_template.format(
                **startup_script_vars
            )
            params['UserData'] = base64.b64encode(startup_script)
            params['UserData.Encoding'] = 'base64'
    except IOError:
        if 'UserData' in params:
            del params['UserData']
        if 'UserData.Encoding' in params:
            del params['UserData.Encoding']


def create_instance(module):

    goal_state = [16, 96]

    if module.params['image_id'] is None:
        module.fail_json(status=-1, msg='missing required arguments: image_id')

    if module.params['key_name'] is None:
        module.fail_json(status=-1, msg='missing required arguments: key_name')

    if module.check_mode:
        return (True, -1, 'created(check mode)')

    params = dict(
        ImageId=module.params['image_id'],
        KeyName=module.params['key_name'],
        InstanceId=module.params['instance_id']
    )

    if module.params['instance_type'] is not None:
        params['InstanceType'] = module.params['instance_type']

    if module.params['accounting_type'] is not None:
        params['AccountingType'] = module.params['accounting_type']

    if module.params['security_group'] is not None:
        params['SecurityGroup.1'] = module.params['security_group']

    if module.params['availability_zone'] is not None:
        params['Placement.AvailabilityZone'] = module.params['availability_zone']  # noqa

    if module.params['ip_type'] is not None:
        params['IpType'] = module.params['ip_type']

    if module.params['public_ip'] is not None:
        params['PublicIp'] = module.params['public_ip']

    enumerated = enumerate(module.params['network_interface'], start=1)
    for n, network_interface in enumerated:
        if network_interface.get('network_id') is not None:
            key = 'NetworkInterface.{0}.NetworkId'.format(n)
            params[key] = network_interface.get('network_id')
        if network_interface.get('network_name') is not None:
            key = 'NetworkInterface.{0}.NetworkName'.format(n)
            params[key] = network_interface.get('network_name')
        if network_interface.get('ipAddress') is not None:
            key = 'NetworkInterface.{0}.IpAddress'.format(n)
            params[key] = network_interface.get('ipAddress')

    configure_user_data(module, params)

    res = request_to_api(module, 'POST', 'RunInstances', params)

    if res['status'] == 200:
        pattern = ('.//{{{nc}}}instanceState/{{{nc}}}code'
                   .format(**res['xml_namespace']))
        current_state = int(res['xml_body'].find(pattern).text)
        retry_count = 10
        while retry_count > 0 and current_state not in goal_state:
            time.sleep(60)
            current_state = get_instance_state(module)
            if current_state < 0:
                retry_count -= 1

        if current_state in goal_state:
            return (True, current_state, 'created')
        else:
            module.fail_json(
                status=-1,
                instance_id=module.params['instance_id'],
                msg='changes failed (create_instance)'
            )
    else:
        error_info = get_api_error(res['xml_body'])
        module.fail_json(
            status=-1,
            instance_id=module.params['instance_id'],
            msg='changes failed (create_instance)',
            error_code=error_info.get('code'),
            error_message=error_info.get('message')
        )


def start_instance(module, current_state):
    goal_state = 16

    if current_state == goal_state:
        return (False, current_state, 'running')
    elif current_state == -1:
        return create_instance(module)
    elif current_state == 80:
        if module.check_mode:
            return (True, current_state, 'running(check mode)')

        params = dict()
        params['InstanceId.1'] = module.params['instance_id']

        if module.params['instance_type'] is not None:
            params['InstanceType.1'] = module.params['instance_type']

        if module.params['accounting_type'] is not None:
            params['AccountingType.1'] = module.params['accounting_type']

        configure_user_data(module, params)

        res = request_to_api(module, 'POST', 'StartInstances', params)

        if res['status'] == 200:
            pattern = ('.//{{{nc}}}currentState/{{{nc}}}code'
                       .format(**res['xml_namespace']))
            current_state = int(res['xml_body'].find(pattern).text)
            retry_count = 10
            while retry_count > 0 and current_state != goal_state:
                time.sleep(60)
                current_state = get_instance_state(module)
                if current_state < 0:
                    retry_count -= 1

            if current_state == goal_state:
                return (True, current_state, 'running')
            else:
                module.fail_json(
                    status=current_state,
                    instance_id=module.params['instance_id'],
                    msg='changes failed (start_instance)'
                )
        else:
            error_info = get_api_error(res['xml_body'])
            module.fail_json(
                status=-1,
                instance_id=module.params['instance_id'],
                msg='changes failed (start_instance)',
                error_code=error_info.get('code'),
                error_message=error_info.get('message')
            )


def stop_instance(module, current_state):
    goal_state = 80

    if current_state == goal_state:
        return (False, current_state, 'stopped')
    elif current_state == -1:
        module.fail_json(
            status=-1,
            instance_id=module.params['instance_id'],
            msg='instance not found'
        )
    elif module.check_mode:
        return (True, current_state, 'stopped(check mode)')

    params = dict()
    params['InstanceId.1'] = module.params['instance_id']

    res = request_to_api(module, 'GET', 'StopInstances', params)

    if res['status'] == 200:
        pattern = ('.//{{{nc}}}currentState/{{{nc}}}code'
                   .format(**res['xml_namespace']))
        current_state = int(res['xml_body'].find(pattern).text)
        retry_count = 10
        while retry_count > 0 and current_state != goal_state:
            time.sleep(60)
            current_state = get_instance_state(module)
            if current_state < 0:
                retry_count -= 1

        if current_state == goal_state:
            return (True, current_state, 'stopped')
        else:
            module.fail_json(
                status=current_state,
                instance_id=module.params['instance_id'],
                msg='changes failed (stop_instance)'
            )
    else:
        error_info = get_api_error(res['xml_body'])
        module.fail_json(
            status=-1,
            instance_id=module.params['instance_id'],
            msg='changes failed (stop_instance)',
            error_code=error_info.get('code'),
            error_message=error_info.get('message')
        )


def restart_instance(module, current_state):
    changed = False

    if module.check_mode:
        return (True, current_state, 'restarted(check mode)')

    if current_state == 16:
        (changed, current_state, msg) = stop_instance(module, current_state)

    if current_state == 80:
        (changed, current_state, msg) = start_instance(module, current_state)

    return (changed, current_state, 'restarted')


def main():
    module = AnsibleModule(  # noqa
        argument_spec=dict(
            access_key=dict(required=True, type='str'),
            secret_access_key=dict(required=True, type='str', no_log=True),
            endpoint=dict(required=True, type='str'),
            instance_id=dict(required=True, type='str'),
            state=dict(required=True, type='str'),
            image_id=dict(required=False, type='str', default=None),
            key_name=dict(required=False, type='str', default=None),
            security_group=dict(required=False, type='str', default=None),
            instance_type=dict(required=False, type='str', default=None),
            availability_zone=dict(required=False, type='str', default=None),
            accounting_type=dict(required=False, type='str', default=None),
            ip_type=dict(required=False, type='str', default=None),
            public_ip=dict(required=False, type='str', default=None),
            startup_script=dict(required=False, type='str', default=None),
            startup_script_vars=dict(required=False, type='dict', default={}),
            network_interface=dict(required=False, type='list', default=[]),
        ),
        supports_check_mode=True
    )

    goal_state = module.params['state']
    instance_id = module.params['instance_id']

    # check current status
    current_state = get_instance_state(module)
    message = ('current state can not continue the process'
               '(current statue = "{0}"'.format(current_state))
    if current_state in [0, 96, 112, 128, 201, 202, 203]:
        module.fail_json(
            status=current_state,
            instance_id=instance_id,
            msg=message
        )

    if goal_state == 'running':
        changed, current_state, msg = start_instance(module, current_state)
    elif goal_state == 'stopped':
        changed, current_state, msg = stop_instance(module, current_state)
    elif goal_state == 'restarted':
        changed, current_state, msg = restart_instance(module, current_state)
    else:
        module.fail_json(
            status=-1,
            instance_id=instance_id,
            msg='invalid state (goal state = "{0}")'.format(goal_state)
        )

    module.exit_json(
        changed=changed,
        instance_id=instance_id,
        status=current_state,
        msg=msg
    )


if __name__ == '__main__':
    main()
