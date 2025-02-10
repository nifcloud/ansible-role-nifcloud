#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright Fujitsu
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
import copy
import hashlib
import hmac
import sys
import time
import xml.etree.ElementTree as etree

import requests
from ansible.module_utils.basic import *  # noqa
from ansible.module_utils.six import text_type

try:
    # Python 2
    from urllib import quote, urlencode
except ImportError:
    # Python 3
    from urllib.parse import quote, urlencode

try:
    # Python 2
    unicode  # noqa
except NameError:
    # Python 3
    unicode = text_type

DOCUMENTATION = '''
---
module: nifcloud_fw
short_description: Create or update, authorize, revoke a firewall group in NIFCLOUD
description:
    - Create or update, authorize, revoke a firewall group.
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
        description:
            - API endpoint of target region
        required: true
    group_name:
        description:
            - Target firewall group ID
        required: true
        aliases: "name"
    description:
        description:
            - Description of target firewall group
        required: false
        default: null
    availability_zone:
        description:
            - Availability zone
        required: false
        default: null
    log_limit:
        description:
            - The upper limit number of logs to retain of communication rejected by the firewall settings rules
        required: false
        default: null
    ip_permissions:
        description:
            - List of rules that allows incoming or outgoing communication to resources
        default: null
    state:
        description:
            - Goal status ("present")
        required: false
        default: "present"
    purge_ip_permissions:
        description:
            - Purge existing ip permissions that are not found in ip permissions
        required: false
        default: 'true'
    authorize_in_bulk:
        description:
            - Authorize ip_permissions for each group. Instead of taking a short time, It will shorten the execution time, but will not guarantee the order of ip_permission instead
        required: false
        default: 'false'
'''  # noqa

EXAMPLES = '''
- action: nifcloud_fw access_key="YOUR_ACCESS_KEY" secret_access_key="YOUR_SECRET_ACCESS_KEY" endpoint="west-1.cp.cloud.nifty.com" group_name="fw001"
'''  # noqa


def calculate_signature(secret_access_key, method, endpoint, path, params):
    payload = ''
    for v in sorted(params.items()):
        payload += '&{0}={1}'.format(v[0], quote(str(v[1]), ''))
    payload = payload[1:]

    string_to_sign = [method, endpoint, path, payload]
    digest = hmac.new(
        secret_access_key.encode('utf-8'),
        '\n'.join(string_to_sign).encode('utf-8'),
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


def fail(module, result, msg, **args):
    current_state = result.get('state')
    created = result.get('created')
    changed_attributes = result.get('changed_attributes')

    module.fail_json(
        status=-1,
        msg=msg,
        current_state=current_state,
        created=created,
        changed_attributes=changed_attributes,
        **args
    )


def contains_ip_permissions(ip_permissions, target_ip_permission):
    tipp = target_ip_permission

    def is_satisfy_to_port_constraint(ipp):
        cons1 = ipp.get('to_port') == tipp.get('to_port')
        cons2 = ((ipp.get('to_port') is None) and
                 (tipp.get('from_port') == tipp.get('to_port')))
        cons3 = ((tipp.get('to_port') is None) and
                 (ipp.get('to_port') == ipp.get('from_port')))

        return cons1 or cons2 or cons3

    for ipp in ip_permissions:
        # dont check description
        if (
                (ipp.get('in_out') == tipp.get('in_out')) and
                (ipp.get('ip_protocol') == tipp.get('ip_protocol')) and
                (ipp.get('group_name') == tipp.get('group_name')) and
                (ipp.get('cidr_ip') == tipp.get('cidr_ip')) and
                (ipp.get('from_port') == tipp.get('from_port')) and
                is_satisfy_to_port_constraint(ipp)
        ):
            return True
    return False


def except_ip_permissions(ip_permissions_a, ip_permissions_b):
    ip_permissions = [
        ip_permission_a for ip_permission_a in ip_permissions_a
        if not contains_ip_permissions(ip_permissions_b, ip_permission_a)
    ]
    return ip_permissions


def describe_security_group(module, result):
    result = copy.deepcopy(result)
    security_group_info = None

    params = dict()
    params['GroupName.1'] = module.params['group_name']

    res = request_to_api(module, 'GET', 'DescribeSecurityGroups', params)

    # get xml element by python 2.6 and 2.7 or more
    # don't use xml.etree.ElementTree.Element.fint(match, namespaces)
    # this is not inplemented by python 2.6
    status = res['xml_body'].find(
        './/{{{nc}}}groupStatus'.format(**res['xml_namespace']))

    if res['status'] != 200 or status is None:
        result['state'] = 'absent'
    elif status.text != 'applied':
        result['state'] = 'processing'
    else:
        result['state'] = 'present'

        # get xml element by python 2.6 and 2.7 or more
        # don't use xml.etree.ElementTree.Element.fint(match, namespaces)
        # this is not inplemented by python 2.6
        group_name = res['xml_body'].find(
            './/{{{nc}}}groupName' .format(**res['xml_namespace']))
        description = res['xml_body'].find(
            './/{{{nc}}}groupDescription'.format(**res['xml_namespace']))
        log_limit = res['xml_body'].find(
            './/{{{nc}}}groupLogLimit'.format(**res['xml_namespace']))
        # net_bios = res['xml_body'].find(
        #     './/{{{nc}}}groupLogFilterNetBios'.format(**res['xml_namespace'])
        # )
        # broadcast = res['xml_body'].find(
        #     './/{{{nc}}}groupLogFilterBroadcast'.format(**res['xml_namespace'])
        # )
        ip_permissions = res['xml_body'].findall(
            './/{{{nc}}}ipPermissions/{{{nc}}}item'
            .format(**res['xml_namespace'])
        )
        # set description
        if description is None or description.text is None:
            description = ''
        elif isinstance(description.text, unicode):
            description = description.text.encode('utf-8')
        else:
            description = description.text

        # set ip_permissions
        ip_permission_list = []
        for ip_permission in (ip_permissions or []):
            # get xml element by python 2.6 and 2.7 or more
            # don't use xml.etree.ElementTree.Element.fint(match, namespaces)
            # this is not inplemented by python 2.6
            _ip_protocol = ip_permission.find(
                './/{{{nc}}}ipProtocol'.format(**res['xml_namespace']))
            _in_out = ip_permission.find(
                './/{{{nc}}}inOut'.format(**res['xml_namespace']))
            _from_port = ip_permission.find(
                './/{{{nc}}}fromPort'.format(**res['xml_namespace']))
            _to_port = ip_permission.find(
                './/{{{nc}}}toPort'.format(**res['xml_namespace']))
            _cidr_ip = ip_permission.find(
                './/{{{nc}}}cidrIp'.format(**res['xml_namespace']))
            _group_name = ip_permission.find(
                './/{{{nc}}}groupName'.format(**res['xml_namespace']))

            ip_permission_list.append(dict(
                ip_protocol=_ip_protocol.text,
                in_out=_in_out.text,
                from_port=(int(_from_port.text)
                           if _from_port is not None else None),
                to_port=int(_to_port.text) if _to_port is not None else None,
                cidr_ip=_cidr_ip.text if _cidr_ip is not None else None,
                group_name=(_group_name.text
                            if _group_name is not None else None)
            ))

        security_group_info = dict(
            group_name=group_name.text,
            log_limit=int(log_limit.text),
            description=description,
            ip_permissions=ip_permission_list,
        )

    return (result, security_group_info)


def wait_for_processing(module, result, goal_state):
    current_method_name = sys._getframe().f_code.co_name
    group_name = module.params['group_name']

    for retry_count in range(10):
        (result, security_group_info) = describe_security_group(module, result)
        current_state = result.get('state')
        if current_state == goal_state:
            break
        else:
            time.sleep(10)

    if current_state != goal_state:
        fail(module, result, 'wait fot processing failed',
             current_method=current_method_name,
             group_name=group_name)

    return (result, security_group_info)


def create_security_group(module, result, security_group_info):
    result = copy.deepcopy(result)
    security_group_info = copy.deepcopy(security_group_info)
    if security_group_info is not None:
        return (result, security_group_info)

    if module.check_mode:
        result['created'] = True
        return (result, security_group_info)

    current_method_name = sys._getframe().f_code.co_name
    goal_state = 'present'
    group_name = module.params['group_name']

    params = dict(
        GroupName=group_name,
        GroupDescription=module.params.get('description', ''),
    )

    if module.params.get('availability_zone') is not None:
        params["Placement.AvailabilityZone"] = module.params['availability_zone']  # noqa

    res = request_to_api(module, 'POST', 'CreateSecurityGroup', params)
    if res['status'] != 200:
        error_info = get_api_error(res['xml_body'])
        fail(module, result, 'changes failed',
             current_method=current_method_name,
             group_name=group_name,
             **error_info)

    # wait for processing
    result, security_group_info = wait_for_processing(module, result,
                                                      goal_state)

    result['created'] = True
    return (result, security_group_info)


def update_security_group_attribute(module, result, security_group_info,
                                    params):
    result = copy.deepcopy(result)
    security_group_info = copy.deepcopy(security_group_info)
    if security_group_info is None:
        return (result, security_group_info)

    current_method_name = sys._getframe().f_code.co_name
    goal_state = 'present'
    group_name = module.params['group_name']

    res = request_to_api(module, 'POST', 'UpdateSecurityGroup', params)
    if res['status'] != 200:
        error_info = get_api_error(res['xml_body'])
        fail(module, result, 'changes failed',
             current_method=current_method_name,
             group_name=group_name,
             **error_info)

    # wait for processing
    result, security_group_info = wait_for_processing(module, result,
                                                      goal_state)

    return (result, security_group_info)


def update_security_group_description(module, result, security_group_info):
    result = copy.deepcopy(result)
    security_group_info = copy.deepcopy(security_group_info)
    if security_group_info is None:
        return (result, security_group_info)

    current_method_name = sys._getframe().f_code.co_name
    group_name = module.params['group_name']

    # skip check
    current_description = security_group_info.get('description')
    goal_description = module.params.get('description')
    if goal_description is None or goal_description == current_description:
        return (result, security_group_info)

    if module.check_mode:
        result['changed_attributes']['description'] = goal_description
        return (result, security_group_info)

    # update description
    params = dict(
        GroupName=group_name,
        GroupDescriptionUpdate=goal_description,
    )
    result, security_group_info = update_security_group_attribute(
        module,
        result,
        security_group_info,
        params
    )

    # update check
    current_description = security_group_info.get('description')
    if goal_description != current_description:
        fail(module, result, 'changes failed',
             current_method=current_method_name,
             group_name=group_name,
             current_info=security_group_info)

    result['changed_attributes']['description'] = goal_description
    return (result, security_group_info)


def update_security_group_log_limit(module, result, security_group_info):
    result = copy.deepcopy(result)
    security_group_info = copy.deepcopy(security_group_info)
    if security_group_info is None:
        return (result, security_group_info)

    current_method_name = sys._getframe().f_code.co_name
    group_name = module.params['group_name']

    # skip check
    current_log_limit = security_group_info.get('log_limit')
    goal_log_limit = module.params.get('log_limit')
    if goal_log_limit is None or goal_log_limit == current_log_limit:
        return (result, security_group_info)

    if module.check_mode:
        result['changed_attributes']['log_limit'] = goal_log_limit
        return (result, security_group_info)

    # update log_limit
    params = dict(
        GroupName=group_name,
        GroupLogLimitUpdate=goal_log_limit,
    )
    result, security_group_info = update_security_group_attribute(
        module,
        result,
        security_group_info,
        params
    )

    # update check
    current_log_limit = security_group_info.get('log_limit')
    if goal_log_limit != current_log_limit:
        fail(module, result, 'changes failed',
             current_method=current_method_name,
             group_name=group_name,
             current_info=security_group_info)

    result['changed_attributes']['log_limit'] = goal_log_limit
    return (result, security_group_info)


def update_security_group(module, result, security_group_info):
    result = copy.deepcopy(result)
    security_group_info = copy.deepcopy(security_group_info)
    if security_group_info is None:
        return (result, security_group_info)

    result, security_group_info = update_security_group_description(
        module,
        result,
        security_group_info
    )

    result, security_group_info = update_security_group_log_limit(
        module,
        result,
        security_group_info
    )

    return (result, security_group_info)


def authorize_security_group(module, result, security_group_info):
    result = copy.deepcopy(result)
    security_group_info = copy.deepcopy(security_group_info)
    if security_group_info is None:
        return (result, security_group_info)

    current_method_name = sys._getframe().f_code.co_name
    group_name = module.params['group_name']

    # get target
    # (goal_ip_permissions - current_ip_permissions = authorize_rules)
    current_ip_permissions = security_group_info.get('ip_permissions')
    goal_ip_permissions = module.params.get('ip_permissions', list())
    authorize_rules = except_ip_permissions(goal_ip_permissions,
                                            current_ip_permissions)

    # skip check
    authorize_rules_size = len(authorize_rules)
    if authorize_rules_size == 0:
        return (result, security_group_info)

    if module.check_mode:
        result['changed_attributes']['number_of_authorize_rules'] = authorize_rules_size  # noqa
        return (result, security_group_info)

    if not module.params.get('authorize_in_bulk'):
        (result, security_group_info) = authorize_security_group_one_by_one(
                                            module,
                                            result,
                                            security_group_info,
                                            authorize_rules,
                                            group_name,
                                            current_method_name
                                        )
    else:
        (result, security_group_info) = authorize_security_group_in_bulk(
                                            module,
                                            result,
                                            security_group_info,
                                            authorize_rules,
                                            group_name,
                                            current_method_name
                                        )

    # update check
    current_ip_permissions = security_group_info.get('ip_permissions')
    authorize_rules = except_ip_permissions(goal_ip_permissions,
                                            current_ip_permissions)
    if len(authorize_rules) != 0:
        fail(module, result, 'changes failed',
             current_method=current_method_name,
             group_name=group_name,
             current_info=security_group_info)

    result['changed_attributes']['number_of_authorize_rules'] = authorize_rules_size  # noqa
    return (result, security_group_info)


def authorize_security_group_one_by_one(module, result, security_group_info,
                                        authorize_rules, group_name,
                                        current_method_name):
    result = copy.deepcopy(result)
    security_group_info = copy.deepcopy(security_group_info)

    goal_state = 'present'

    # update ip_permissions
    # > I want IP permissions to be registered in the specified order.
    # > But, AuthorizeSecurityGroupIngress does not warrants the return order
    # > of response XML by IP permissions specified with one request.
    # > So, I implemented so that all IP permissions to be added
    # > are registered one by one.
    for authorize_rule in authorize_rules:
        params = dict(GroupName=group_name)

        params['IpPermissions.1.InOut'] = authorize_rule.get('in_out')
        params['IpPermissions.1.IpProtocol'] = authorize_rule.get('ip_protocol')  # noqa
        params['IpPermissions.1.Description'] = authorize_rule.get('description', '')  # noqa

        _from_port = authorize_rule.get('from_port')
        if _from_port is not None:
            params['IpPermissions.1.FromPort'] = _from_port

        _to_port = authorize_rule.get('to_port')
        if _to_port is not None:
            params['IpPermissions.1.ToPort'] = _to_port

        _group_name = authorize_rule.get('group_name')
        if _group_name is not None:
            params['IpPermissions.1.Groups.1.GroupName'] = _group_name

        _cidr_ip = authorize_rule.get('cidr_ip')
        if _cidr_ip is not None:
            params['IpPermissions.1.IpRanges.1.CidrIp'] = _cidr_ip

        res = request_to_api(module, 'POST', 'AuthorizeSecurityGroupIngress',
                             params)
        if res['status'] != 200:
            error_info = get_api_error(res['xml_body'])
            fail(module, result, 'changes failed',
                 current_method=current_method_name,
                 group_name=group_name,
                 **error_info)

        # wait for processing
        result, security_group_info = wait_for_processing(module, result,
                                                          goal_state)

    return (result, security_group_info)


def authorize_security_group_in_bulk(module, result, security_group_info,
                                     authorize_rules, group_name,
                                     current_method_name):
    result = copy.deepcopy(result)
    security_group_info = copy.deepcopy(security_group_info)

    goal_state = 'present'
    params = dict(GroupName=group_name)

    for index, authorize_rule in enumerate(authorize_rules):
        ip_permission_param_prefix = 'IpPermissions.{0}.'.format(index + 1)

        params[ip_permission_param_prefix + 'InOut'] = authorize_rule.get('in_out')  # noqa
        params[ip_permission_param_prefix + 'IpProtocol'] = authorize_rule.get('ip_protocol')  # noqa
        params[ip_permission_param_prefix + 'Description'] = authorize_rule.get('description', '')  # noqa

        _from_port = authorize_rule.get('from_port')
        if _from_port is not None:
            params[ip_permission_param_prefix + 'FromPort'] = _from_port

        _to_port = authorize_rule.get('to_port')
        if _to_port is not None:
            params[ip_permission_param_prefix + 'ToPort'] = _to_port

        _group_name = authorize_rule.get('group_name')
        if _group_name is not None:
            params[ip_permission_param_prefix + 'Groups.1.GroupName'] = _group_name  # noqa

        _cidr_ip = authorize_rule.get('cidr_ip')
        if _cidr_ip is not None:
            params[ip_permission_param_prefix + 'IpRanges.1.CidrIp'] = _cidr_ip  # noqa

    res = request_to_api(module, 'POST', 'AuthorizeSecurityGroupIngress',
                         params)

    if res['status'] != 200:
        error_info = get_api_error(res['xml_body'])
        fail(module, result, 'changes failed',
             current_method=current_method_name,
             group_name=group_name,
             **error_info)

    # wait for processing
    result, security_group_info = wait_for_processing(module, result,
                                                      goal_state)
    return (result, security_group_info)


def revoke_security_group(module, result, security_group_info):
    result = copy.deepcopy(result)
    security_group_info = copy.deepcopy(security_group_info)
    if security_group_info is None:
        return (result, security_group_info)

    current_method_name = sys._getframe().f_code.co_name
    goal_state = 'present'
    group_name = module.params['group_name']

    # get target (current_ip_permissions - goal_ip_permissions = revoke_rules)
    current_ip_permissions = security_group_info.get('ip_permissions')
    goal_ip_permissions = module.params.get('ip_permissions', list())
    revoke_rules = except_ip_permissions(current_ip_permissions,
                                         goal_ip_permissions)

    # skip check
    revoke_rules_size = len(revoke_rules)
    if revoke_rules_size == 0:
        return (result, security_group_info)

    # prevent revoke
    purge_ip_permissions = module.params.get('purge_ip_permissions')
    if not purge_ip_permissions:
        return (result, security_group_info)

    if module.check_mode:
        result['changed_attributes']['number_of_revoke_rules'] = revoke_rules_size  # noqa
        return (result, security_group_info)

    # build parameters
    params = dict(
        GroupName=group_name,
    )
    for index, revoke_rule in enumerate(revoke_rules):
        ip_permission_param_prefix = 'IpPermissions.{0}.'.format(index + 1)

        params[ip_permission_param_prefix + 'InOut'] = revoke_rule.get('in_out')  # noqa
        params[ip_permission_param_prefix + 'IpProtocol'] = revoke_rule.get('ip_protocol')  # noqa

        _from_port = revoke_rule.get('from_port')
        if _from_port is not None:
            params[ip_permission_param_prefix + 'FromPort'] = _from_port

        _to_port = revoke_rule.get('to_port')
        if _to_port is not None:
            params[ip_permission_param_prefix + 'ToPort'] = _to_port

        _group_name = revoke_rule.get('group_name')
        if _group_name is not None:
            params[ip_permission_param_prefix + 'Groups.1.GroupName'] = _group_name  # noqa

        _cidr_ip = revoke_rule.get('cidr_ip')
        if _cidr_ip is not None:
            params[ip_permission_param_prefix + 'IpRanges.1.CidrIp'] = _cidr_ip

    # revoke ip_permissions
    res = request_to_api(module, 'POST', 'RevokeSecurityGroupIngress', params)
    if res['status'] != 200:
        error_info = get_api_error(res['xml_body'])
        fail(module, result, 'changes failed',
             current_method=current_method_name,
             group_name=group_name,
             **error_info)

    # wait for processing
    result, security_group_info = wait_for_processing(module, result,
                                                      goal_state)

    # update check
    current_ip_permissions = security_group_info.get('ip_permissions')
    revoke_rules = except_ip_permissions(current_ip_permissions,
                                         goal_ip_permissions)
    if len(revoke_rules) != 0:
        fail(module, result, 'changes failed',
             current_method=current_method_name,
             group_name=group_name,
             current_info=security_group_info)

    result['changed_attributes']['number_of_revoke_rules'] = revoke_rules_size
    return (result, security_group_info)


def run(module):
    result = dict(
        created=False,
        changed_attributes=dict(),
        state='absent',
    )

    result, security_group_info = describe_security_group(module, result)

    result, security_group_info = create_security_group(module, result,
                                                        security_group_info)

    result, security_group_info = update_security_group(module, result,
                                                        security_group_info)

    result, security_group_info = authorize_security_group(module, result,
                                                           security_group_info)

    result, security_group_info = revoke_security_group(module, result,
                                                        security_group_info)

    group_name = module.params['group_name']
    goal_state = module.params['state']
    current_state = result.get('state')
    if current_state != goal_state:
        fail(module, result, 'invalid state',
             group_name=group_name,
             goal_state=goal_state)

    created = result.get('created')
    changed_attributes = result.get('changed_attributes')
    changed = (created or (len(changed_attributes) != 0))
    module.exit_json(changed=changed, **result)


def main():
    module = AnsibleModule(  # noqa
        argument_spec=dict(
            access_key=dict(required=True,  type='str'),
            secret_access_key=dict(required=True,  type='str',  no_log=True),
            endpoint=dict(required=True,  type='str'),
            group_name=dict(required=True,  type='str',  aliases=['name']),
            description=dict(required=False, type='str',  default=None),
            availability_zone=dict(required=False, type='str',  default=None),
            log_limit=dict(required=False, type='int',  default=None),
            ip_permissions=dict(required=False, type='list', default=list()),
            state=dict(required=False, type='str',  default='present',
                       choices=['present']),
            purge_ip_permissions=dict(required=False, type='bool',
                                      default=True),
            authorize_in_bulk=dict(required=False, type='bool', default=False),
        ),
        supports_check_mode=True
    )
    run(module)


if __name__ == '__main__':
    main()
