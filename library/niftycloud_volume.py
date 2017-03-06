#!/usr/bin/env python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: niftycloud_volume
short_description: Attach the volume to an instance in NIFTY Cloud
description:
	- Attach the volume an instance of NIFTY Cloud.
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
	size:
		description:
			- Volume size.
		required: true
	volume_id:
		description:
			- Volume name.
		required: false
		default: null
	disk_type:
		description:
			- Volume type.
		required: false
		default: null
	instance_id:
		description:
			- Instance ID
		required: true
	accounting_type:
		description:
			- Accounting type (1: monthly, 2: pay per use)
		required: false
		default: null
	state:
		description:
			- Goal status ("present" or "absent")  * "absent" is not implemented
		required: true
'''

EXAMPLES = '''
- action: niftycloud_lb access_key="YOUR_ACCESS_KEY" secret_access_key="YOUR_SECRET_ACCESS_KEY" endpoint="west-1.cp.cloud.nifty.com" size="100" volume_id="testdisk001" disk_type="3" instance_id="test001" accounting_type="2" state="present"
'''

def calculate_signature(secret_access_key, method, endpoint, path, params):
	payload = ""
	for v in sorted(params.items()):
		payload += '&{0}={1}'.format(v[0], urllib.quote(str(v[1])))
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

def get_volume_state(module):
	params = dict()

	if module.params['volume_id'] is not None:
		params['VolumeId.1'] = module.params['volume_id']
	else:
		return ('absent', None)

	res = request_to_api(module, 'GET', 'DescribeVolumes', params)

	if res['status'] == 200:
		status = res['xml_body'].find('.//{{{nc}}}volumeSet/{{{nc}}}item/{{{nc}}}status'.format(**res['xml_namespace'])).text

		if status == 'in-use':
			conn_instance_id = res['xml_body'].find('.//{{{nc}}}attachmentSet/{{{nc}}}item/{{{nc}}}instanceId'.format(**res['xml_namespace'])).text
			conn_status = res['xml_body'].find('.//{{{nc}}}attachmentSet/{{{nc}}}item/{{{nc}}}status'.format(**res['xml_namespace'])).text
			return (conn_status, conn_instance_id)
		else:
			return (status, None)
	else:
		return ('absent', None)

def create_volume(module):
	params = dict(
		Size       = module.params['size'],
		InstanceId = module.params['instance_id']
	)

	if module.params['volume_id'] is not None:
		params['VolumeId'] = module.params['volume_id']

	if module.params['disk_type'] is not None:
		params['DiskType'] = module.params['disk_type']

	if module.params['accounting_type'] is not None:
		params['AccountingType'] = module.params['accounting_type']

	res = request_to_api(module, 'GET', 'CreateVolume', params)

	if res['status'] == 200:
		(current_state, instance_id) = get_volume_state(module)
		while 'attached' != current_state:
			time.sleep(60)
			(current_state, instance_id) = get_volume_state(module)

		if current_state == 'attached':
			return (True, 'created')
		else:
			module.fail_json(status=-1, instance_id=module.params['instance_id'], msg='changes failed (create_volume)')
	else:
		module.fail_json(status=-1, instance_id=module.params['instance_id'], msg='changes failed (create_volume)')

def attach_volume(module):
	(current_state, instance_id) = get_volume_state(module)

	if current_state == 'absent':
		return create_volume(module)
	elif current_state == 'available':
		params = dict(
			VolumeId   = module.params['volume_id'],
			InstanceId = module.params['instance_id'] 
		)
		res = request_to_api(module, 'GET', 'AttachVolume', params)

		if res['status'] == 200:
			current_state = res['xml_body'].find('.//{{{nc}}}status'.format(**res['xml_namespace'])).text
			while 'attached' != current_state:
				time.sleep(60)
				(current_state, instance_id) = get_volume_state(module)

			if current_state == 'attached':
				return (True, current_state)
			else:
				module.fail_json(status=-1, instance_id=module.params['instance_id'], msg='changes failed (attach_volume)')
		else:
			module.fail_json(status=-1, instance_id=module.params['instance_id'], msg='changes failed (attach_volume)')
	elif current_state == 'attached' and instance_id == module.params['instance_id']:
		return (False, current_state)
	else:
		module.fail_json(status=-1, instance_id=module.params['instance_id'], msg='invalid state (current state = "{0}")'.format(current_state))

def detach_volume(module):
	module.fail_json(status=-1, msg='"absent" is not implemented.')

def main():
	module = AnsibleModule(
		argument_spec = dict(
			access_key          = dict(required=True,  type='str'),
			secret_access_key   = dict(required=True,  type='str'),
			endpoint            = dict(required=True,  type='str'),
			size                = dict(required=True,  type='str'),
			volume_id           = dict(required=False, type='str', default=None),
			disk_type           = dict(required=False, type='str', default=None),
			instance_id         = dict(required=True,  type='str'),
			accounting_type     = dict(required=False, type='str', default=None),
			state               = dict(required=True,  type='str'),
		)
	)

	goal_state  = module.params['state']
	instance_id = module.params['instance_id']

	if goal_state == 'present':
		(changed, current_state) = attach_volume(module)
	elif goal_state == 'absent':
		(changed, current_state) = detach_volume(module)
	else:
		module.fail_json(status=-1, msg='invalid state (goal state = "{0}")'.format(goal_state))

	module.exit_json(changed=changed, instance_id=instance_id, status=current_state)

from ansible.module_utils.basic import *
import urllib, hmac, hashlib, base64, time, requests
import xml.etree.ElementTree as etree

if __name__ == '__main__':
	main()
