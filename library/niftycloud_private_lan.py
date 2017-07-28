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

DOCUMENTATION = '''
---
module: niftycloud_private_lan
short_description: Create or modify, delete a private lan in NIFTY Cloud
description:
	- Create or modify, delete a private lan.
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
	private_lan_name:
		description:
			- Target private lan name
		required: true
		aliases: "name"
		default: null
	cidr_block:
		description:
			- CIDR block of private lan
		required: true
		default: null
	network_id:
		description:
			- Network ID created private lan
		required: false
		default: null
	accounting_type:
		description:
			- Accounting type
		required: false
		default: null

	availability_zone:
		description:
			- Availability zone
		required: false
		default: null
	state:
		description:
			- Goal status ("present" or "absent")
		required: false
		default: "present"
'''

EXAMPLES = '''
- action: niftycloud_private_lan access_key="YOUR_ACCESS_KEY" secret_access_key="YOUR_SECRET_ACCESS_KEY" endpoint="west-1.cp.cloud.nifty.com" private_lan_name="lan001"
'''
STATUS_ABSENT  = 'absent'
STATUS_PENDING = 'pending'
STATUS_PRESENT = 'present'

API_ACTION_DESCRIVE = 'NiftyDescribePrivateLans'
API_ACTION_CREATE   = 'NiftyCreatePrivateLan'
API_ACTION_MODIFY   = 'NiftyModifyPrivateLanAttribute'
API_ACTION_DELETE   = 'NiftyDeletePrivateLan'

def get_query_string(params):
	query_string = ""
	for v in sorted(params.items()):
		query_string += '&{0}={1}'.format(v[0], urllib.quote(str(v[1]), ''))
	return query_string[1:]

def get_string_to_sign(method, endpoint, path, query_string):
	return method + '\n' + endpoint + '\n' + path + '\n' + query_string

def calculate_signature(secret_access_key, method, endpoint, path, params):
	query_string   = get_query_string(params)
	string_to_sign = get_string_to_sign(method, endpoint, path, query_string)
	hash_msg       = hmac.new(secret_access_key, string_to_sign, hashlib.sha256)
	return base64.b64encode(hash_msg.digest())

def create_request_params(module, endpoint, method, path, action, params):
	params['Action']           = action
	params['AccessKeyId']      = module.params['access_key']
	params['SignatureMethod']  = 'HmacSHA256'
	params['SignatureVersion'] = '2'

	secret_access_key   = module.params['secret_access_key']
	singnature          = calculate_signature(secret_access_key, method, endpoint, path, params)
	params['Signature'] = singnature
	return params

def change_responce_to_dict(res):
	try:
		body = res.text.encode('utf-8')
		xml  = etree.fromstring(body)
		namespace = dict(nc = xml.tag[1:].split('}')[0])
	except:
		module.fail_json(status=-1, msg='changes failed (xml parse error)')

	info = dict(
		status   = res.status_code,
		xml_body = xml,
		xml_namespace = namespace
	)
	return info

def request_to_api_get(module, action, params):
	endpoint = module.params['endpoint']
	method   = 'GET'
	path     = '/api/'
	params   = create_request_params(module, endpoint, method, path, action, params)
	url      = 'https://{0}{1}?{2}'.format(endpoint, path, urllib.urlencode(params))
	res      = requests.get(url)
	return change_responce_to_dict(res)

def request_to_api_post(module, action, params):
	endpoint = module.params['endpoint']
	method   = 'POST'
	path     = '/api/'
	params   = create_request_params(module, endpoint, method, path, action, params)
	url      = 'https://{0}{1}'.format(endpoint, path)
	res      = requests.post(url, urllib.urlencode(params))
	return change_responce_to_dict(res)

def get_api_error(xml_body):
	info = dict(
		code    = xml_body.find('.//Errors/Error/Code').text,
		message = xml_body.find('.//Errors/Error/Message').text
	)
	return info

def get_xml_element(res, tag_name):
	element = res['xml_body'].find(('.//{{{nc}}}' + tag_name).format(**res['xml_namespace']))
	if element is None:
		return ''
	else:
		return element.text

def describe_private_lans(module, result):
	result           = copy.deepcopy(result)
	private_lan_info = None

	params = dict()
	if module.params['network_id'] is not None:
		params['NetworkId.1'] = module.params['network_id']
	else:
		params['PrivateLanName.1'] = module.params['private_lan_name']

	res = request_to_api_get(module, API_ACTION_DESCRIVE, params)

	status = get_xml_element(res, 'state')

	if res['status'] != 200 or status is None:
		result['state'] = STATUS_ABSENT
	elif status == 'pending':
		result['state'] = STATUS_PENDING
	else:
		result['state'] = STATUS_PRESENT

		private_lan_name  = get_xml_element(res, 'privateLanName')
		cidr_block        = get_xml_element(res, 'cidrBlock')
		network_id        = get_xml_element(res, 'networkId')
		availability_zone = get_xml_element(res, 'availabilityZone')
		accounting_type   = get_xml_element(res, 'accountingType')
		description       = get_xml_element(res, 'description')

		if isinstance(description, unicode):
			description = description.encode('utf-8')

		private_lan_info = dict(
			private_lan_name  = private_lan_name,
			cidr_block        = cidr_block,
			network_id        = network_id,
			availability_zone = availability_zone,
			accounting_type   = accounting_type,
			description       = description,
		)

	return(result, private_lan_info)

def wait_for_state(module, result, state):
	current_method_name = sys._getframe().f_code.co_name
	private_lan_name    = module.params['private_lan_name']

	for retry_count in range(10):
		(result, private_lan_info) = describe_private_lans(module, result)
		current_state = result.get('state')
		if current_state == state:
			break
		else:
			time.sleep(10)

	if current_state != state:
		module.fail_json(module, result, 'wait fot state failed',
			current_method   = current_method_name,
			private_lan_name = private_lan_name
		)

	return (result, private_lan_info)

def create_private_lan(module, result, private_lan_info):
	result           = copy.deepcopy(result)
	private_lan_info = copy.deepcopy(private_lan_info)
	if private_lan_info is not None:
		return (result, private_lan_info)

	private_lan_name = module.params['private_lan_name']

	params = dict(
		PrivateLanName = private_lan_name,
		CidrBlock      = module.params['cidr_block'],
		Description    = module.params.get('description', ''),
	)

	if module.params.get('availability_zone') is not None:
		params['AvailabilityZone'] = module.params['availability_zone']

	if module.params.get('accounting_type') is not None:
		params['AccountingType'] = module.params['accounting_type']

	res = request_to_api_get(module, API_ACTION_CREATE, params)
	if res['status'] >= 300:
		current_method_name = sys._getframe().f_code.co_name
		error_info = get_api_error(res['xml_body'])
		module.fail_json(module, result, 'changes failed',
			current_method   = current_method_name,
			private_lan_name = private_lan_name,
			**error_info
		)

	state = STATUS_PRESENT
	(result, private_lan_info) = wait_for_state(module, result, state)

	result['created'] = True
	return (result, private_lan_info)

def modify_private_lan_attribute(module, result, private_lan_info, params):
	result           = copy.deepcopy(result)
	private_lan_info = copy.deepcopy(private_lan_info)
	if private_lan_info is None:
		return (result, private_lan_info)

	private_lan_name = module.params['private_lan_name']

	res = request_to_api_post(module, API_ACTION_MODIFY, params)
	if res['status'] >= 300:
		current_method_name = sys._getframe().f_code.co_name
		error_info = get_api_error(res['xml_body'])
		module.fail_json(module, result, 'changes failed',
			current_method   = current_method_name,
			private_lan_name = private_lan_name,
			**error_info
		)

	state = STATUS_PRESENT
	(result, private_lan_info) = wait_for_state(module, result, state)

	return (result, private_lan_info)

def modify_private_lan_name(module, result, private_lan_info):
	result           = copy.deepcopy(result)
	private_lan_info = copy.deepcopy(private_lan_info)
	if private_lan_info is None:
		return (result, private_lan_info)

	network_id = private_lan_info.get('network_id')

	current_private_lan_name = private_lan_info.get('private_lan_name')
	goal_private_lan_name    = module.params.get('private_lan_name')
	if goal_private_lan_name is None or goal_private_lan_name == current_private_lan_name:
		return (result, private_lan_info)

	params = dict(
		NetworkId = network_id,
		Attribute = 'privateLanName',
		Value     = goal_private_lan_name,
	)
	(result, private_lan_info) = modify_private_lan_attribute(module, result, private_lan_info, params)

	current_private_lan_name = private_lan_info.get('private_lan_name')
	if goal_private_lan_name != current_private_lan_name:
		current_method_name = sys._getframe().f_code.co_name
		module.fail_json(module, result, 'changes failed',
			current_method   = current_method_name,
			private_lan_name = current_private_lan_name,
			current_set      = private_lan_info,
		)

	result['changed_attributes']['private_lan_name'] = goal_private_lan_name
	return (result, private_lan_info)

def modify_private_lan_cidr_block(module, result, private_lan_info):
	result           = copy.deepcopy(result)
	private_lan_info = copy.deepcopy(private_lan_info)
	if private_lan_info is None:
		return (result, private_lan_info)

	private_lan_name = module.params['private_lan_name']
	network_id       = private_lan_info.get('network_id')

	current_cidr_block = private_lan_info.get('cidr_block')
	goal_cidr_block    = module.params.get('cidr_block')
	if goal_cidr_block is None or goal_cidr_block == current_cidr_block:
		return (result, private_lan_info)

	params = dict(
		NetworkId = network_id,
		Attribute = 'cidrBlock',
		Value = goal_cidr_block,
	)
	(result, private_lan_info) = modify_private_lan_attribute(module, result, private_lan_info, params)

	current_cidr_block = private_lan_info.get('cidr_block')
	if goal_cidr_block != current_cidr_block:
		current_method_name = sys._getframe().f_code.co_name
		module.fail_json(module, result, 'changes failed',
			current_method   = current_method_name,
			private_lan_name = private_lan_name,
			current_set      = private_lan_info,
		)

	result['changed_attributes']['cidr_block'] = goal_cidr_block
	return (result, private_lan_info)

def modify_private_lan_accounting_type(module, result, private_lan_info):
	result           = copy.deepcopy(result)
	private_lan_info = copy.deepcopy(private_lan_info)
	if private_lan_info is None:
		return (result, private_lan_info)

	private_lan_name = module.params['private_lan_name']
	network_id       = private_lan_info.get('network_id')

	current_accounting_type = private_lan_info.get('accounting_type')
	goal_accounting_type    = module.params.get('accounting_type')
	if goal_accounting_type is None or goal_accounting_type == current_accounting_type:
		return (result, private_lan_info)

	params = dict(
		NetworkId = network_id,
		Attribute = 'accountingType',
		Value = goal_accounting_type,
	)
	(result, private_lan_info) = modify_private_lan_attribute(module, result, private_lan_info, params)

	current_accounting_type = private_lan_info.get('accounting_type')
	if goal_accounting_type != current_accounting_type:
		current_method_name = sys._getframe().f_code.co_name
		module.fail_json(module, result, 'changes failed',
			current_method   = current_method_name,
			private_lan_name = private_lan_name,
			current_set      = private_lan_info,
		)

	result['changed_attributes']['accounting_type'] = goal_accounting_type
	return (result, private_lan_info)

def modify_private_lan_description(module, result, private_lan_info):
	result           = copy.deepcopy(result)
	private_lan_info = copy.deepcopy(private_lan_info)
	if private_lan_info is None:
		return (result, private_lan_info)

	private_lan_name = module.params['private_lan_name']
	network_id       = private_lan_info.get('network_id')

	current_description = private_lan_info.get('description')
	goal_description    = module.params.get('description')
	if goal_description is None or goal_description == current_description:
		return (result, private_lan_info)

	params = dict(
		NetworkId = network_id,
		Attribute = 'description',
		Value = goal_description,
	)
	(result, private_lan_info) = modify_private_lan_attribute(module, result, private_lan_info, params)

	current_description = private_lan_info.get('description')
	if goal_description != current_description:
		current_method_name = sys._getframe().f_code.co_name
		module.fail_json(module, result, 'changes failed',
			current_method   = current_method_name,
			private_lan_name = private_lan_name,
			current_set      = private_lan_info,
		)

	result['changed_attributes']['description'] = goal_description
	return (result, private_lan_info)

def modify_private_lan(module, result, private_lan_info):
	result           = copy.deepcopy(result)
	private_lan_info = copy.deepcopy(private_lan_info)
	if private_lan_info is None:
		return (result, private_lan_info)

	(result, private_lan_info) = modify_private_lan_name(module, result, private_lan_info)

	(result, private_lan_info) = modify_private_lan_cidr_block(module, result, private_lan_info)

	(result, private_lan_info) = modify_private_lan_accounting_type(module, result, private_lan_info)

	(result, private_lan_info) = modify_private_lan_description(module, result, private_lan_info)

	return (result, private_lan_info)

def delete_private_lan(module, result, private_lan_info):
	result           = copy.deepcopy(result)
	private_lan_info = copy.deepcopy(private_lan_info)
	if private_lan_info is None:
		return (result, private_lan_info)

	private_lan_name = private_lan_info.get('private_lan_name')

	param = dict(
		PrivateLanName = private_lan_name,
	)

	current_method_name = sys._getframe().f_code.co_name
	res = request_to_api_post(module, API_ACTION_DELETE, param)
	if res['status'] >= 300:
		error_info = get_api_error(res['xml_body'])
		module.fail_json(module, result, 'changes failed',
			current_method   = current_method_name,
			private_lan_name = private_lan_name,
			**error_info
		)

	state = STATUS_ABSENT
	(result, private_lan_info) = wait_for_state(module, result, state)

	if private_lan_info is None:
		module.fail_json(module, result, 'changes failed',
			current_method   = current_method_name,
			private_lan_name = private_lan_name,
			current_set      = private_lan_info,
		)

	result['changed_attributes']['private_lan_name'] = private_lan_name
	return (result, private_lan_info)


def run(module):
	result = dict(
		created            = False,
		changed_attributes = dict(),
		state              = STATUS_ABSENT,
	)

	state = module.params['state']
	(result, private_lan_info) = describe_private_lans(module, result)

	if state == STATUS_PRESENT:
		(result, private_lan_info) = create_private_lan(module, result, private_lan_info)
		(result, private_lan_info) = modify_private_lan(module, result, private_lan_info)
	elif state == STATUS_ABSENT:
		(result, private_lan_info) = delete_private_lan(module, result, private_lan_info)
	else:
		module.fail_json(status=-1, msg='invalid state (goal state = "{0}")'.format(state))

	created            = result.get('created')
	changed_attributes = result.get('changed_attributes')
	changed            = (created or (len(changed_attributes) != 0))
	module.exit_json(changed=changed, **result)

def main():

	module = AnsibleModule(
		argument_spec = dict(
			access_key        = dict(required=True,  type='str'),
			secret_access_key = dict(required=True,  type='str', no_log=True),
			endpoint          = dict(required=True,  type='str'),
			cidr_block        = dict(required=True,  type='str', default=None),
			private_lan_name  = dict(required=False, type='str', aliases=['name']),
			network_id        = dict(required=False, type='str', default=None),
			accounting_type   = dict(required=False, type='str', default=None),
			description       = dict(required=False, type='str', default=None),
			availability_zone = dict(required=False, type='str', default=None),
			state             = dict(required=False, type='str', default=STATUS_PRESENT, choices=[STATUS_PRESENT,STATUS_ABSENT]),
		)
	)
	run(module)

from ansible.module_utils.basic import *
import urllib, hmac, hashlib, base64, time, requests, sys
import xml.etree.ElementTree as etree
import copy

if __name__ == '__main__':
	main()

