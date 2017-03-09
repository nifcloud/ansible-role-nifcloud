#!/usr/bin/env python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: niftycloud_fw
short_description: Create or update, authorize, revoke a firewall group in NIFTY Cloud
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
	log_filter_net_bios:
		description:
			- Restrain broadcast logs of Windows NetBIOS
		default: null
	log_filter_broadcast:
		description:
			- Restrain broadcast logs in common global network and common private network
		default: null
	ip_permissions:
		description:
			- List of rules that allows incoming or outgoing communication to resources
		default: null
	state:
		description:
			- Goal status ("present" or "absent")
		required: true
'''

EXAMPLES = '''
- action: niftycloud_fw access_key="YOUR_ACCESS_KEY" secret_access_key="YOUR_SECRET_ACCESS_KEY" endpoint="west-1.cp.cloud.nifty.com" group_name="fw001" state="present"
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

def fail(module, result, msg, **args):
	current_state      = result.get('state')
	created            = result.get('created')
	changed_attributes = result.get('changed_attributes')

	module.fail_json(
		status             = -1,
		msg                = msg,
		current_state      = current_state,
		created            = created,
		changed_attributes = changed_attributes,
		**args
	)

def describe_security_group(module, result):
	result              = copy.deepcopy(result)
	security_group_info = None

	# TODO
	return (result, security_group_info)

def create_security_group(module, result, security_group_info):
	result              = copy.deepcopy(result)
	security_group_info = copy.deepcopy(security_group_info)
	if security_group_info is not None:
		return (result, security_group_info)

	# TODO
	return (result, security_group_info)

def update_security_group(module, result, security_group_info):
	result              = copy.deepcopy(result)
	security_group_info = copy.deepcopy(security_group_info)
	if security_group_info is None:
		return (result, security_group_info)

	# TODO
	return (result, security_group_info)

def authorize_security_group(module, result, security_group_info):
	result              = copy.deepcopy(result)
	security_group_info = copy.deepcopy(security_group_info)
	if security_group_info is None:
		return (result, security_group_info)

	# TODO
	return (result, security_group_info)

def revoke_security_group(module, result, security_group_info):
	result              = copy.deepcopy(result)
	security_group_info = copy.deepcopy(security_group_info)
	if security_group_info is None:
		return (result, security_group_info)

	# TODO
	return (result, security_group_info)

def run(module):
	result = dict(
		created            = False,
		changed_attributes = dict(),
		state              = 'absent',
	)

	(result, security_group_info) = describe_security_group(module, result)

	(result, security_group_info) = create_security_group(module, result, security_group_info)

	(result, security_group_info) = update_security_group(module, result, security_group_info)

	(result, security_group_info) = authorize_security_group(module, result, security_group_info)

	(result, security_group_info) = revoke_security_group(module, result, security_group_info)

	group_name    = module.params['group_name']
	goal_state    = module.params['state']
	current_state = result.get('state')
	if current_state != goal_state:
		fail(module, result, 'invalid state',
			group_name = group_name,
			goal_state = goal_state
		)

	created            = result.get('created')
	changed_attributes = result.get('changed_attributes')
	changed            = (created or (len(changed_attributes) != 0))
	module.exit_json(changed=changed, **result)

def main():
	module = AnsibleModule(
		argument_spec = dict(
			access_key        = dict(required=True,  type='str'),
			secret_access_key = dict(required=True,  type='str',  no_log=True),
			endpoint          = dict(required=True,  type='str'),
			group_name        = dict(required=True,  type='str'),
			description       = dict(required=False, type='str',  default=None),
			availability_zone = dict(required=False, type='str',  default=None),
			log_limit         = dict(required=False, type='int',  default=None),
			log_filters       = dict(required=False, type='dict', default=dict()),
			ip_permissions    = dict(required=False, type='list', default=list()),
			state             = dict(required=False, type='str',  default='present', choices=['present', 'absent']),
		)
	)
	run(module)

from ansible.module_utils.basic import *
import urllib, hmac, hashlib, base64, time, requests
import xml.etree.ElementTree as etree
import copy

if __name__ == '__main__':
	main()
