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

def describe_private_lans(module, result):
	result              = copy.deepcopy(result)
	private_lan_set = None

	params = dict()
	if module.params['network_id'] is not None:
		params['NetworkId.1']   = module.params['network_id']
	else:
		params['PrivateLanName.1']   = module.params['private_lan_name']

	res = request_to_api(module, 'GET', 'NiftyDescribePrivateLans', params)

	# get xml element by python 2.6 and 2.7 or more
	# don't use xml.etree.ElementTree.Element.fint(match, namespaces)
	# this is not inplemented by python 2.6
	status = res['xml_body'].find('.//{{{nc}}}state'.format(**res['xml_namespace']))

	if res['status'] != 200 or status is None:
		result['state'] = 'absent'
	elif status.text != 'available':
		result['state'] = 'pending'
	else:
		result['state'] = 'present'

		# get xml element by python 2.6 and 2.7 or more
		# don't use xml.etree.ElementTree.Element.fint(match, namespaces)
		# this is not inplemented by python 2.6
		private_lan_name  = res['xml_body'].find('.//{{{nc}}}privateLanName'.format(**res['xml_namespace']))
		cidr_block        = res['xml_body'].find('.//{{{nc}}}cidrBlock'.format(**res['xml_namespace']))
		network_id        = res['xml_body'].find('.//{{{nc}}}networkId'.format(**res['xml_namespace']))
		availability_zone = res['xml_body'].find('.//{{{nc}}}availabilityZone'.format(**res['xml_namespace']))
		accounting_type   = res['xml_body'].find('.//{{{nc}}}accountingType'.format(**res['xml_namespace']))
		description       = res['xml_body'].find('.//{{{nc}}}description'.format(**res['xml_namespace']))

		# set description
		if description is None or description.text is None:
			description = ''
		elif isinstance(description.text, unicode):
			description = description.text.encode('utf-8')
		else:
			description = description.text

		private_lan_set = dict(
			private_lan_name  = private_lan_name.text,
			cidr_block        = cidr_block.text,
			network_id        = network_id.text,
			availability_zone = availability_zone.text,
			accounting_type   = accounting_type.text,
			description       = description,
		)

	return(result, private_lan_set)

def wait_for_pending(module, result, goal_state):
	current_method_name = sys._getframe().f_code.co_name
	private_lan_name    = module.params['private_lan_name']

	for retry_count in range(10):
		(result, private_lan_set) = describe_private_lans(module, result)
		current_state = result.get('state')
		if current_state == goal_state:
			break
		else:
			time.sleep(10)

	if current_state != goal_state:
		module.fail_json(module, result, 'wait fot pending failed',
			current_method   = current_method_name,
			private_lan_name = private_lan_name
		)

	return (result, private_lan_set)

def create_private_lan(module, result, private_lan_set):
	result          = copy.deepcopy(result)
	private_lan_set = copy.deepcopy(private_lan_set)
	if private_lan_set is not None:
		return (result, private_lan_set)

	current_method_name = sys._getframe().f_code.co_name
	goal_state          = 'present'
	private_lan_name    = module.params['private_lan_name']

	params = dict(
		PrivateLanName = private_lan_name,
		CidrBlock      = module.params['cidr_block'],
		Description    = module.params.get('description', ''),
	)

	if module.params.get('availability_zone') is not None:
		params['AvailabilityZone']   = module.params['availability_zone']

	if module.params.get('accounting_type') is not None:
		params['AccountingType']   = module.params['accounting_type']

	res = request_to_api(module, 'GET', 'NiftyCreatePrivateLan', params)
	if res['status'] != 200:
		error_info = get_api_error(res['xml_body'])
		module.fail_json(module, result, 'changes failed',
			current_method   = current_method_name,
			private_lan_name = private_lan_name,
			**error_info
		)

	# wait for pending
	(result, private_lan_set) = wait_for_pending(module, result, goal_state)

	result['created'] = True
	return (result, private_lan_set)

def modify_private_lan_attribute(module, result, private_lan_set, params):
	result           = copy.deepcopy(result)
	private_lan_set = copy.deepcopy(private_lan_set)
	if private_lan_set is None:
		return (result, private_lan_set)

	current_method_name = sys._getframe().f_code.co_name
	goal_state          = 'present'
	private_lan_name    = module.params['private_lan_name']

	res = request_to_api(module, 'POST', 'NiftyModifyPrivateLanAttribute', params)
	if res['status'] != 200:
		error_info = get_api_error(res['xml_body'])
		module.fail_json(module, result, 'changes failed',
			current_method   = current_method_name,
			private_lan_name = private_lan_name,
			**error_info
		)

	# wait for pending
	(result, private_lan_set) = wait_for_pending(module, result, goal_state)

	return (result, private_lan_set)

def modify_private_lan_name(module, result, private_lan_set):
	result          = copy.deepcopy(result)
	private_lan_set = copy.deepcopy(private_lan_set)
	if private_lan_set is None:
		return (result, private_lan_set)

	current_method_name = sys._getframe().f_code.co_name
	network_id          = private_lan_set.get('network_id')

	# skip check
	current_private_lan_name = private_lan_set.get('private_lan_name')
	goal_private_lan_name    = module.params.get('private_lan_name')
	if goal_private_lan_name is None or goal_private_lan_name == current_private_lan_name:
		return (result, private_lan_set)

	# update private lan Name
	params = dict(
		NetworkId = network_id,
		Attribute = 'privateLanName',
		Value     = goal_private_lan_name,
	)
	(result, private_lan_set) = modify_private_lan_attribute(module, result, private_lan_set, params)

	# update check
	current_private_lan_name = private_lan_set.get('private_lan_name')
	if goal_private_lan_name != current_private_lan_name:
		module.fail_json(module, result, 'changes failed',
			current_method   = current_method_name,
			private_lan_name = current_private_lan_name,
			current_set      = private_lan_set,
		)

	result['changed_attributes']['private_lan_name'] = goal_private_lan_name
	return (result, private_lan_set)

def modify_private_lan_cidr_block(module, result, private_lan_set):
	result           = copy.deepcopy(result)
	private_lan_set = copy.deepcopy(private_lan_set)
	if private_lan_set is None:
		return (result, private_lan_set)

	current_method_name = sys._getframe().f_code.co_name
	private_lan_name    = module.params['private_lan_name']
	network_id          = private_lan_set.get('network_id')

	# skip check
	current_cidr_block = private_lan_set.get('cidr_block')
	goal_cidr_block    = module.params.get('cidr_block')
	if goal_cidr_block is None or goal_cidr_block == current_cidr_block:
		return (result, private_lan_set)

	# update cidr block
	params = dict(
		NetworkId = network_id,
		Attribute = 'cidrBlock',
		Value = goal_cidr_block,
	)
	(result, private_lan_set) = modify_private_lan_attribute(module, result, private_lan_set, params)

	# update check
	current_cidr_block = private_lan_set.get('cidr_block')
	if goal_cidr_block != current_cidr_block:
		module.fail_json(module, result, 'changes failed',
			current_method   = current_method_name,
			private_lan_name = private_lan_name,
			current_set      = private_lan_set,
		)

	result['changed_attributes']['cidr_block'] = goal_cidr_block
	return (result, private_lan_set)

def modify_private_lan_accounting_type(module, result, private_lan_set):
	result           = copy.deepcopy(result)
	private_lan_set = copy.deepcopy(private_lan_set)
	if private_lan_set is None:
		return (result, private_lan_set)

	current_method_name = sys._getframe().f_code.co_name
	private_lan_name    = module.params['private_lan_name']
	network_id          = private_lan_set.get('network_id')

	# skip check
	current_accounting_type = private_lan_set.get('accounting_type')
	goal_accounting_type    = module.params.get('accounting_type')
	if goal_accounting_type is None or goal_accounting_type == current_accounting_type:
		return (result, private_lan_set)

	# update accounting type
	params = dict(
		NetworkId = network_id,
		Attribute = 'accountingType',
		Value = goal_accounting_type,
	)
	(result, private_lan_set) = modify_private_lan_attribute(module, result, private_lan_set, params)

	# update check
	current_accounting_type = private_lan_set.get('accounting_type')
	if goal_accounting_type != current_accounting_type:
		module.fail_json(module, result, 'changes failed',
			current_method   = current_method_name,
			private_lan_name = private_lan_name,
			current_set      = private_lan_set,
		)

	result['changed_attributes']['accounting_type'] = goal_accounting_type
	return (result, private_lan_set)

def modify_private_lan_description(module, result, private_lan_set):
	result           = copy.deepcopy(result)
	private_lan_set = copy.deepcopy(private_lan_set)
	if private_lan_set is None:
		return (result, private_lan_set)

	current_method_name = sys._getframe().f_code.co_name
	private_lan_name    = module.params['private_lan_name']
	network_id          = private_lan_set.get('network_id')

	# skip check
	current_description = private_lan_set.get('description')
	goal_description    = module.params.get('description')
	if goal_description is None or goal_description == current_description:
		return (result, private_lan_set)

	# update description
	params = dict(
		NetworkId = network_id,
		Attribute = 'description',
		Value = goal_description,
	)
	(result, private_lan_set) = modify_private_lan_attribute(module, result, private_lan_set, params)

	# update check
	current_description = private_lan_set.get('description')
	if goal_description != current_description:
		module.fail_json(module, result, 'changes failed',
			current_method   = current_method_name,
			private_lan_name = private_lan_name,
			current_set      = private_lan_set,
		)

	result['changed_attributes']['description'] = goal_description
	return (result, private_lan_set)

def modify_private_lan(module, result, private_lan_set):
	result           = copy.deepcopy(result)
	private_lan_set = copy.deepcopy(private_lan_set)
	if private_lan_set is None:
		return (result, private_lan_set)

	(result, private_lan_set) = modify_private_lan_name(module, result, private_lan_set)

	(result, private_lan_set) = modify_private_lan_cidr_block(module, result, private_lan_set)

	(result, private_lan_set) = modify_private_lan_accounting_type(module, result, private_lan_set)

	(result, private_lan_set) = modify_private_lan_description(module, result, private_lan_set)

	return (result, private_lan_set)

def delete_private_lan(module, result, private_lan_set):
	result           = copy.deepcopy(result)
	private_lan_set = copy.deepcopy(private_lan_set)
	if private_lan_set is None:
		return (result, private_lan_set)

	current_method_name = sys._getframe().f_code.co_name
	goal_state          = 'absent'
	private_lan_name    = private_lan_set.get('private_lan_name')

	# build parameters
	param = dict(
		PrivateLanName = private_lan_name,
	)

	# delete private_lan
	res = request_to_api(module, 'POST', 'NiftyDeletePrivateLan', param)
	if res['status'] != 200:
		error_info = get_api_error(res['xml_body'])
		module.fail_json(module, result, 'changes failed',
			current_method   = current_method_name,
			private_lan_name = private_lan_name,
			**error_info
		)

	# wait for pending
	(result, private_lan_set) = wait_for_pending(module, result, goal_state)

	# update check
	if private_lan_set is None:
		module.fail_json(module, result, 'changes failed',
			current_method   = current_method_name,
			private_lan_name = private_lan_name,
			current_set      = private_lan_set,
		)

	result['changed_attributes']['private_lan_name'] = private_lan_name
	return (result, private_lan_set)


def run(module):
	result = dict(
		created            = False,
		changed_attributes = dict(),
		state              = 'absent',
	)

	goal_state  = module.params['state']
	(result, private_lan_set) = describe_private_lans(module, result)

	if goal_state == 'present':
		(result, private_lan_set) = create_private_lan(module, result, private_lan_set)
		(result, private_lan_set) = modify_private_lan(module, result, private_lan_set)
	elif goal_state == 'absent':
		(result, private_lan_set) = delete_private_lan(module, result, private_lan_set)
	else:
		module.fail_json(status=-1, msg='invalid state (goal state = "{0}")'.format(goal_state))

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
			state             = dict(required=False, type='str', default='present', choices=['present','absent']),
		)
	)
	run(module)

from ansible.module_utils.basic import *
import urllib, hmac, hashlib, base64, time, requests, sys
import xml.etree.ElementTree as etree
import copy

if __name__ == '__main__':
	main()
