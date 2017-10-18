#!/usr/bin/env python
# -*- coding: utf-8 -*-

DOCUMENTATION = '''
---
module: niftycloud_client
short_description: Client of NIFTYCLOUD API
description:
	- Client of NIFTYCLOUD API
version_added: "1.1.1"
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
	path:
		description:
			- API path of request
		required: true
	params:
		description:
			- request parameters of API request
		required: true
'''

import urllib, hmac, hashlib, base64, requests
import xml.etree.ElementTree as etree

def calculate_signature_v2(secret_access_key, method, endpoint, path, params):
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

	params['Signature'] = calculate_signature_v2(module.params['secret_access_key'], method, endpoint, path, params)

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

