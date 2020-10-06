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
module: nifcloud_lb
short_description: De-registers or registers an instance from Load Balancer in NIFCLOUD
description:
    - De-registers or registers an instance of NIFCLOUD from Load Balancer.
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
            - API endpoint of target region.
        required: true
    loadbalancer_name:
        description:
            - Target Load Balancer name
        required: true
    loadbalancer_port:
        description:
            - Target Load Balancer port number
        required: true
    instance_port:
        description:
            - Destination port number
        required: true
    balancing_type:
        description:
            - Balancing type (1: Round-Robin or 2: Least-Connection)
        required: false
        default: 1
    network_volume:
        description:
            - Maximum of network volume
        required: false
        default: 10
    ip_version:
        description:
            - IP version ("v4" or "v6")
        required: false
        default: 'v4'
    accounting_type:
        description:
            - Accounting type ("1": monthly, "2": pay per use)
        required: false
        default: '1'
    policy_type:
        description:
            - Encryption policy type ("standard" or "ats")
        required: false
        default: 'standard'
    instance_ids:
        description:
            - List of Instance ID
        required: false
        default: []
    purge_instance_ids:
        description:
            - Purge existing instance ids that are not found in instance_ids
        required: false
        default: true
    filter_ip_addresses:
        description:
            - List of ip addresses that allows/denys incoming communication to resources
        required: false
        default: []
    filter_type:
        description:
            - Filter type that switch to allows/denys for filter ip addresses (1: allow or 2: deny)
        required: false
        default: 1
    purge_filter_ip_addresses:
        description:
            - Purge existing filter ip addresses that are not found in filter_ip_addresses
        required: false
        default: true
    health_check_target:
        description:
            - Health check protocol and port
        required: false
        default: 'ICMP'
    health_check_interval:
        description:
            - Interval of health check (second)
        required: false
        default: 5
    health_check_unhealthy_threshold:
        description:
            - Threshold of unhealthy
        required: false
        default: 1
    ssl_policy_name:
        description:
            - SSL policy template name
        required: false
        default: ''
    state:
        description:
            - Goal status (only "present")
        required: true
'''  # noqa

EXAMPLES = '''
- action: nifcloud_lb access_key="YOUR_ACCESS_KEY" secret_access_key="YOUR_SECRET_ACCESS_KEY" endpoint="west-1.cp.cloud.nifty.com" instance_id="test001" instance_port=80 loadbalancer_name="lb001" loadbalancer_port=80 state="present"
'''  # noqa


ISO8601 = '%Y-%m-%dT%H:%M:%SZ'


class LoadBalancerHealthCheck:
    """Model of NIFCLOUD LoadBalancer HealthCheck """

    def __init__(self, target='ICMP', interval=5, unhealthy_threshold=1):
        self.target = target
        self.interval = interval
        self.unhealthy_threshold = unhealthy_threshold

    def __eq__(self, other):
        if other is None or type(self) != type(other):
            return False

        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        return not self.__eq__(other)

    def parse_describe(self, res):
        health_check = res['xml_body'].find(
            './/{{{nc}}}HealthCheck'.format(**res['xml_namespace']))

        if health_check is not None:
            self.target = health_check.find(
                './/{{{nc}}}Target'.format(**res['xml_namespace'])).text
            self.interval = int(health_check.find(
                './/{{{nc}}}Interval'.format(**res['xml_namespace'])).text)
            self.unhealthy_threshold = int(health_check.find(
                './/{{{nc}}}UnhealthyThreshold'.format(**res['xml_namespace'])).text)  # noqa


class LoadBalancerManager:
    """Handles NIFCLOUD LoadBalancer registration"""

    _ERROR_LB_NAME_NOT_FOUND = 'Client.InvalidParameterNotFound.LoadBalancer'
    _ERROR_LB_PORT_NOT_FOUND = 'Client.InvalidParameterNotFound.LoadBalancerPort'  # noqa

    def __init__(self, module):
        self.module = module

        self.access_key = module.params['access_key']
        self.secret_access_key = module.params['secret_access_key']
        self.endpoint = module.params['endpoint']

        self.loadbalancer_name = module.params['loadbalancer_name']
        self.loadbalancer_port = module.params['loadbalancer_port']
        self.instance_port = module.params['instance_port']
        self.balancing_type = module.params['balancing_type']
        self.network_volume = module.params['network_volume']
        self.ip_version = module.params['ip_version']
        self.accounting_type = module.params['accounting_type']
        self.policy_type = module.params['policy_type']

        self.instance_ids = module.params['instance_ids']
        self.purge_instance_ids = module.params['purge_instance_ids']
        self.filter_ip_addresses = module.params['filter_ip_addresses']
        self.filter_type = module.params['filter_type']
        self.purge_filter_ip_addresses = module.params['purge_filter_ip_addresses']  # noqa
        self.health_check_target = module.params['health_check_target']
        self.health_check_interval = module.params['health_check_interval']
        self.health_check_unhealthy_threshold = module.params['health_check_unhealthy_threshold']  # noqa
        self.ssl_policy_name = module.params['ssl_policy_name']
        self.state = module.params['state']

        self.current_state = ''
        self.changed = False
        self.result = dict()

    def ensure_present(self):
        self.current_state = self._get_state_instance_in_load_balancer()

        if self.current_state == 'absent':
            self._create_load_balancer()
        elif self.current_state == 'port-not-found':
            self._register_port()

        self._sync_filter()
        self._sync_health_check()
        self._sync_instances()

    def _describe_load_balancers(self, params):
        return request_to_api(self.module, 'GET', 'DescribeLoadBalancers',
                              params)

    def _describe_current_load_balancers(self):
        params = dict()
        params['LoadBalancerNames.member.1'] = self.loadbalancer_name
        params['LoadBalancerNames.LoadBalancerPort.1'] = self.loadbalancer_port
        params['LoadBalancerNames.InstancePort.1'] = self.instance_port
        return self._describe_load_balancers(params)

    def _get_state_instance_in_load_balancer(self):
        res = self._describe_current_load_balancers()

        if res['status'] == 200:
            return 'present'
        else:
            error_info = get_api_error(res['xml_body'])

            if error_info.get('code') == self._ERROR_LB_PORT_NOT_FOUND:
                return 'port-not-found'
            elif error_info.get('code') == self._ERROR_LB_NAME_NOT_FOUND:
                return 'absent'

            self._fail_request(res, 'check current state failed')

    def _is_present_in_load_balancer(self):
        return self._get_state_instance_in_load_balancer() == 'present'

    def _is_absent_in_load_balancer(self):
        return self._get_state_instance_in_load_balancer() == 'absent'

    def _create_load_balancer(self):
        params = dict()
        params['LoadBalancerName'] = self.loadbalancer_name
        params['Listeners.member.1.LoadBalancerPort'] = self.loadbalancer_port
        params['Listeners.member.1.InstancePort'] = self.instance_port
        params['Listeners.member.1.BalancingType'] = self.balancing_type
        params['NetworkVolume'] = self.network_volume
        params['IpVersion'] = self.ip_version
        params['AccountingType'] = self.accounting_type
        params['PolicyType'] = self.policy_type

        self.result['create_load_balancer'] = dict(
            loadbalancer_name=self.loadbalancer_name,
        )

        if self.module.check_mode:
            self.changed = True
            return

        api_name = 'CreateLoadBalancer'
        res = request_to_api(self.module, 'POST', api_name, params)

        failed_msg = 'changes failed (create_load_balancer)'
        if res['status'] == 200:
            if self._wait_for_loadbalancer_status('present'):
                self.changed = True
            else:
                self._fail_request(res, failed_msg)
        else:
            self._fail_request(res, failed_msg)

    def _register_port(self):
        params = dict()
        params['LoadBalancerName'] = self.loadbalancer_name
        params['Listeners.member.1.LoadBalancerPort'] = self.loadbalancer_port
        params['Listeners.member.1.InstancePort'] = self.instance_port
        params['Listeners.member.1.BalancingType'] = self.balancing_type

        self.result['register_port'] = dict(
            loadbalancer_name=self.loadbalancer_name,
            loadbalancer_port=self.loadbalancer_port,
            instance_port=self.instance_port,
        )

        if self.module.check_mode:
            self.changed = True
            return

        api_name = 'RegisterPortWithLoadBalancer'
        res = request_to_api(self.module, 'POST', api_name, params)

        failed_msg = 'changes failed (register_port)'
        if res['status'] == 200:
            if self._wait_for_loadbalancer_status('present'):
                self.changed = True
            else:
                self._fail_request(res, failed_msg)
        else:
            self._fail_request(res, failed_msg)

    def _wait_for_loadbalancer_status(self, goal_state):
        self.current_state = self._get_state_instance_in_load_balancer()

        if self.current_state == goal_state:
            return True

        retry_count = 10
        while retry_count > 0 and self.current_state != goal_state:
            time.sleep(60)
            self.current_state = self._get_state_instance_in_load_balancer()
            retry_count -= 1

        return self.current_state == goal_state

    def _sync_filter(self):
        res_desc = self._describe_current_load_balancers()

        current_filter_type = self._parse_filter_type(res_desc)
        (purge_ip_list, merge_ip_list) = self._extract_filter_ip_diff(res_desc)

        if (self.filter_type == current_filter_type) \
           and (len(purge_ip_list) == 0) and (len(merge_ip_list) == 0):
            return

        self.result['sync_filter'] = dict(
            purge_filter_ip_addresses=purge_ip_list,
            merge_filter_ip_addresses=merge_ip_list,
            filter_type=self.filter_type,
        )

        params = dict()
        params['LoadBalancerName'] = self.loadbalancer_name
        params['LoadBalancerPort'] = self.loadbalancer_port
        params['InstancePort'] = self.instance_port
        params['FilterType'] = self.filter_type

        ip_no = 1

        for ip in purge_ip_list:
            params['IPAddresses.member.{0}.IPAddress'.format(ip_no)] = ip
            addon_key = 'IPAddresses.member.{0}.AddOnFilter'.format(ip_no)
            params[addon_key] = 'false'
            ip_no = ip_no + 1

        for ip in merge_ip_list:
            params['IPAddresses.member.{0}.IPAddress'.format(ip_no)] = ip
            addon_key = 'IPAddresses.member.{0}.AddOnFilter'.format(ip_no)
            params[addon_key] = 'true'
            ip_no = ip_no + 1

        if self.module.check_mode:
            self.changed = True
            return

        api_name = 'SetFilterForLoadBalancer'
        res_post = request_to_api(self.module, 'POST', api_name, params)

        if res_post['status'] == 200:
            self.changed = True
        else:
            self._fail_request(res_post, 'changes failed (set_filter)')

    def _parse_filter_type(self, res):
        filter_type = 1

        filter = res['xml_body'].find(
            './/{{{nc}}}Filter'.format(**res['xml_namespace']))

        if filter is not None:
            filter_type = int(filter.find(
                './/{{{nc}}}FilterType'.format(**res['xml_namespace'])).text)

        return filter_type

    def _extract_filter_ip_diff(self, res):
        filter_ip_list = []

        filter = res['xml_body'].find(
            './/{{{nc}}}Filter'.format(**res['xml_namespace']))

        if filter is not None:
            addresses_key = './/{{{nc}}}IPAddresses/{{{nc}}}member/{{{nc}}}IPAddress'.format(**res['xml_namespace'])  # noqa
            address_elements = filter.findall(addresses_key)
            filter_ip_list = [x.text for x in address_elements]

            # DescribeLoadBalancers returns ['*.*.*.*'] when none filter ip.
            filter_ip_list = [x for x in filter_ip_list if x != '*.*.*.*']

        purge_ip_list = []
        if self.purge_filter_ip_addresses:
            purge_ip_list = list(set(filter_ip_list)
                                 - set(self.filter_ip_addresses))

        merge_ip_list = list(set(self.filter_ip_addresses)
                             - set(filter_ip_list))

        return (purge_ip_list, merge_ip_list)

    def _sync_health_check(self):
        res_desc = self._describe_current_load_balancers()

        current = LoadBalancerHealthCheck()
        current.parse_describe(res_desc)

        change = LoadBalancerHealthCheck(
                    target=self.health_check_target,
                    interval=self.health_check_interval,
                    unhealthy_threshold=self.health_check_unhealthy_threshold,
                )

        if current == change:
            return

        self.result['sync_health_check'] = dict(
            health_check_target=change.target,
            health_check_interval=change.interval,
            health_check_unhealthy_threshold=change.unhealthy_threshold,
        )

        if self.module.check_mode:
            self.changed = True
            return

        params = dict()
        params['LoadBalancerName'] = self.loadbalancer_name
        params['LoadBalancerPort'] = self.loadbalancer_port
        params['InstancePort'] = self.instance_port
        params['HealthCheck.Target'] = change.target
        params['HealthCheck.Interval'] = change.interval
        params['HealthCheck.UnhealthyThreshold'] = change.unhealthy_threshold

        api_name = 'ConfigureHealthCheck'
        res_post = request_to_api(self.module, 'POST', api_name, params)

        if res_post['status'] == 200:
            self.changed = True
        else:
            self._fail_request(res_post, 'changes failed (sync_health_check)')

    def _sync_instances(self):
        res = self._describe_current_load_balancers()

        (deregister_instance_ids, register_instance_ids) = \
            self._extract_instance_ids_diff(res)

        if (len(deregister_instance_ids) == 0) \
           and (len(register_instance_ids) == 0):
            return

        self.result['sync_instances'] = dict(
            deregister_instance_ids=deregister_instance_ids,
            register_instance_ids=register_instance_ids,
        )

        if self.module.check_mode:
            self.changed = True
            return

        if len(register_instance_ids) != 0:
            self._register_instances(register_instance_ids)

        if len(deregister_instance_ids) != 0:
            self._deregister_instances(deregister_instance_ids)

    def _extract_instance_ids_diff(self, res):
        instance_ids_key = './/{{{nc}}}Instances/{{{nc}}}member/{{{nc}}}InstanceId'.format(**res['xml_namespace'])  # noqa
        instance_ids_elements = res['xml_body'].findall(instance_ids_key)
        instance_ids = [x.text for x in instance_ids_elements]

        deregister_instance_ids = []
        if self.purge_instance_ids:
            deregister_instance_ids = list(set(instance_ids)
                                           - set(self.instance_ids))

        register_instance_ids = list(set(self.instance_ids)
                                     - set(instance_ids))

        return (deregister_instance_ids, register_instance_ids)

    def _register_instances(self, instance_ids):
        params = dict()
        params['LoadBalancerName'] = self.loadbalancer_name
        params['LoadBalancerPort'] = self.loadbalancer_port
        params['InstancePort'] = self.instance_port

        instance_no = 1
        for instance_id in instance_ids:
            key = 'Instances.member.{0}.InstanceId'.format(instance_no)
            params[key] = instance_id
            instance_no = instance_no + 1

        api_name = 'RegisterInstancesWithLoadBalancer'
        res = request_to_api(self.module, 'POST', api_name, params)

        if res['status'] == 200:
            self.changed = True
        else:
            self._fail_request(res, 'changes failed (register_instances)')

    def _deregister_instances(self, instance_ids):
        params = dict()
        params['LoadBalancerName'] = self.loadbalancer_name
        params['LoadBalancerPort'] = self.loadbalancer_port
        params['InstancePort'] = self.instance_port

        instance_no = 1
        for instance_id in instance_ids:
            key = 'Instances.member.{0}.InstanceId'.format(instance_no)
            params[key] = instance_id
            instance_no = instance_no + 1

        api_name = 'DeregisterInstancesFromLoadBalancer'
        res = request_to_api(self.module, 'POST', api_name, params)

        if res['status'] == 200:
            self.changed = True
        else:
            self._fail_request(res, 'changes failed (deregister_instances)')

    def _fail_request(self, response, msg):
        error_info = get_api_error(response['xml_body'])
        self.module.fail_json(
            status=-1,
            msg=msg,
            error_code=error_info.get('code'),
            error_message=error_info.get('message'),
        )


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
    params['Timestamp'] = time.strftime(ISO8601, time.gmtime())

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


def main():
    module = AnsibleModule(  # noqa
        argument_spec=dict(
            access_key=dict(required=True,  type='str'),
            secret_access_key=dict(required=True,  type='str', no_log=True),
            endpoint=dict(required=True,  type='str'),
            loadbalancer_name=dict(required=True, type='str'),
            loadbalancer_port=dict(required=True, type='int'),
            instance_port=dict(required=True, type='int'),
            balancing_type=dict(required=False, type='int', default=1),
            network_volume=dict(required=False, type='int', default=10),
            ip_version=dict(required=False, type='str', default='v4'),
            accounting_type=dict(required=False, type='str', default='1'),
            policy_type=dict(equired=False, type='str', default='standard'),
            instance_ids=dict(required=False,  type='list', default=list()),
            purge_instance_ids=dict(required=False, type='bool',
                                    default=True),
            filter_ip_addresses=dict(required=False, type='list',
                                     default=list()),
            filter_type=dict(required=False, type='int', default=1),
            purge_filter_ip_addresses=dict(required=False, type='bool',
                                           default=True),
            health_check_target=dict(required=False, type='str',
                                     default='ICMP'),
            health_check_interval=dict(required=False, type='int', default=5),
            health_check_unhealthy_threshold=dict(required=False, type='int',
                                                  default=1),
            ssl_policy_name=dict(required=False, type='str', default=''),
            state=dict(required=True,  type='str'),
        ),
        supports_check_mode=True
    )

    goal_state = module.params['state']

    manager = LoadBalancerManager(module)

    if goal_state == 'present':
        manager.ensure_present()
    else:
        module.fail_json(
            status=-1,
            msg='invalid state (goal state = "{0}")'.format(goal_state)
        )

    module.exit_json(
        changed=manager.changed,
        status=manager.current_state,
        **manager.result
    )


if __name__ == '__main__':
    main()
