#!/usr/bin/env python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: niftycloud_lb
short_description: De-registers or registers an instance from Load Balancer in NIFTY Cloud
description:
	- De-registers or registers an instance of NIFTY Cloud from Load Balancer.
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
	instance_id:
		description:
			- Instance ID
		required: true
        instance_port:
                description:
                        - Destination port number (required for registration)
                required: false
		default: null
        loadbalancer_name:
                description:
                        - Target Load Balancer name (required for registration)
                required: false
		default: null
        loadbalancer_port:
                description:
                        - Target Load Balancer port number (required for registration)
                required: false
		default: null
	state:
		description:
			- Goal status ("present" or "absent")
		required: true
'''

EXAMPLES = '''
- action: niftycloud_lb access_key="YOUR_ACCESS_KEY" secret_access_key="YOUR_SECRET_ACCESS_KEY" endpoint="west-1.cp.cloud.nifty.com" instance_id="test001" instance_port=80 loadbalancer_name="lb001" loadbalancer_port=80 state="present"
'''

def calculate_signature(secret_access_key, method, endpoint, path, params):
	payload = ""
	for v in sorted(params.items()):
		payload += '&{0}={1}'.format(v[0], urllib.quote(str(v[1]), ''))
	payload = payload[1:]

	string_to_sign = [method, endpoint, path, payload]
	digest = hmac.new(secret_access_key, '\n'.join(string_to_sign), hashlib.sha256).digest()

	return base64.b64encode(digest)

def request_to_api(module, method, action, params):
	params['Action']           = action
	params['AccessKeyId']      = module.params['access_key']
	params['SignatureMethod']  = 'HmacSHA256'
	params['SignatureVersion'] = '2'

	path     = '/api/'
	endpoint = module.params['endpoint']

	params['Signature'] = calculate_signature(module.params['secret_access_key'], method, endpoint, path, params)

	r = None
	if method == 'GET':
		url = 'https://{0}{1}?{2}'.format(endpoint, path, urllib.urlencode(params))
		r = requests.get(url)
	elif method == 'POST':
		url = 'https://{0}{1}'.format(endpoint, path)
		r = requests.post(url, urllib.urlencode(params))
	else:
		module.fail_json(status=-1, msg='changes failed (un-supported http method)')


	if r is not None:
		body = r.text.encode('utf-8')
		xml = etree.fromstring(body)
		info = dict(
			status   = r.status_code,
			xml_body = xml,
			xml_namespace = dict(nc = xml.tag[1:].split('}')[0])
		)
		return info
	else:
		module.fail_json(status=-1, msg='changes failed (http request failed)')

def get_api_error(xml_body):
	info = dict(
		code    = xml_body.find('.//Errors/Error/Code').text,
		message = xml_body.find('.//Errors/Error/Message').text
	)
	return info

def describe_load_balancers(module, params):
	return request_to_api(module, 'GET', 'DescribeLoadBalancers', params)

def get_state_instance_in_load_balancer(module):
	params = dict()
        params['LoadBalancerNames.member.1'] = module.params['loadbalancer_name']
        params['LoadBalancerNames.LoadBalancerPort.1'] = module.params['loadbalancer_port']
        params['LoadBalancerNames.InstancePort.1'] = module.params['instance_port']
	res = describe_load_balancers(module, params)

	if res['status'] == 200:
		for instance_id in res['xml_body'].findall('.//{{{nc}}}Instances/{{{nc}}}member/{{{nc}}}InstanceId'.format(**res['xml_namespace'])):
			if instance_id.text == module.params['instance_id']:
				return 'present'
		return 'absent'
	else:
		error_info = get_api_error(res['xml_body'])
		module.fail_json(
			status=-1,
			msg='check current state failed',
			error_code=error_info.get('code'),
			error_message=error_info.get('message')
		)

def is_present_in_load_balancer(module):
	return True if get_state_instance_in_load_balancer(module) == 'present' else False

def is_absent_in_load_balancer(module):
	return True if get_state_instance_in_load_balancer(module) == 'absent' else False

def regist_instance(module):
	if module.params['instance_port'] == None:
		module.fail_json(status=-1, msg='missing required arguments: instance_port')

	if module.params['loadbalancer_name'] == None:
		module.fail_json(status=-1, msg='missing required arguments: loadbalancer_name')

	if module.params['loadbalancer_port'] == None:
		module.fail_json(status=-1, msg='missing required arguments: loadbalancer_port')

	if is_present_in_load_balancer(module):
		return (False, 'present')

	params = dict()
	params['LoadBalancerName']              = module.params['loadbalancer_name']
	params['LoadBalancerPort']              = module.params['loadbalancer_port']
	params['InstancePort']                  = module.params['instance_port']
	params['Instances.member.1.InstanceId'] = module.params['instance_id']

	res = request_to_api(module, 'GET', 'RegisterInstancesWithLoadBalancer', params)

	if res['status'] == 200:
		current_status = get_state_instance_in_load_balancer(module)
		return (True, current_status)
	else:
		error_info = get_api_error(res['xml_body'])
		module.fail_json(
			status=-1,
			msg='changes failed (regist_instance)',
			error_code=error_info.get('code'),
			error_message=error_info.get('message')
		)

def deregist_instance(module):
	params = dict()
	lbs_res = describe_load_balancers(module, params)

	if lbs_res['status'] == 200:
		changed = False
		deregister_lbs = list()
		for member in lbs_res['xml_body'].findall('.//{{{nc}}}LoadBalancerDescriptions/{{{nc}}}member'.format(**lbs_res['xml_namespace'])):
			if member.find('.//{{{nc}}}InstanceId'.format(**lbs_res['xml_namespace'])) is None:
				continue
			instance_id = member.find('.//{{{nc}}}InstanceId'.format(**lbs_res['xml_namespace'])).text
			if instance_id != module.params['instance_id']:
				continue

			loadbalancer_name = member.find('.//{{{nc}}}LoadBalancerName'.format(**lbs_res['xml_namespace'])).text
			if module.params['loadbalancer_name'] is not None and loadbalancer_name != module.params['loadbalancer_name']:
				continue

			loadbalancer_port = int(member.find('.//{{{nc}}}LoadBalancerPort'.format(**lbs_res['xml_namespace'])).text)
			if module.params['loadbalancer_port'] is not None and loadbalancer_port != module.params['loadbalancer_port']:
				continue

			instance_port     = int(member.find('.//{{{nc}}}InstancePort'.format(**lbs_res['xml_namespace'])).text)
			if module.params['instance_port'] is not None and instance_port != module.params['instance_port']:
				continue

			params = dict()
			params['LoadBalancerName'] = loadbalancer_name
			params['LoadBalancerPort'] = loadbalancer_port
			params['InstancePort']     = instance_port
			params['Instances.member.1.InstanceId'] = module.params['instance_id']

			res = request_to_api(module, 'GET', 'DeregisterInstancesFromLoadBalancer', params)

			if res['status'] == 200:
				lb_label = loadbalancer_name + ':' + str(loadbalancer_port) + '->' + str(instance_port)
				deregister_lbs.append(lb_label)
				changed = True
			else:
				error_info = get_api_error(res['xml_body'])
				module.fail_json(
					status=-1,
					msg='changes failed (deregist_instance)',
					error_code=error_info.get('code'),
					error_message=error_info.get('message')
				)
		return (changed, 'absent(' + ','.join(deregister_lbs) + ')')
	else:
		error_info = get_api_error(lbs_res['xml_body'])
		module.fail_json(
			status=-1,
			msg='get load balancers information failed',
			error_code=error_info.get('code'),
			error_message=error_info.get('message')
		)

def main():
	module = AnsibleModule(
		argument_spec = dict(
			access_key          = dict(required=True,  type='str'),
			secret_access_key   = dict(required=True,  type='str', no_log=True),
			endpoint            = dict(required=True,  type='str'),
			instance_id         = dict(required=True,  type='str'),
			instance_port       = dict(required=False, type='int', default=None),
			loadbalancer_name   = dict(required=False, type='str', default=None),
			loadbalancer_port   = dict(required=False, type='int', default=None),
			state               = dict(required=True,  type='str'),
		)
	)

	goal_state  = module.params['state']
	instance_id = module.params['instance_id']

	if goal_state == 'present':
		(changed, current_state) = regist_instance(module)
	elif goal_state == 'absent':
		(changed, current_state) = deregist_instance(module)
	else:
		module.fail_json(status=-1, msg='invalid state (goal state = "{0}")'.format(goal_state))

	module.exit_json(changed=changed, instance_id=instance_id, status=current_state)

from ansible.module_utils.basic import *
import urllib, hmac, hashlib, base64, time, requests
import xml.etree.ElementTree as etree

if __name__ == '__main__':
	main()
