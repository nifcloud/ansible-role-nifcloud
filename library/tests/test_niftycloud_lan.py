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

import os
import sys
sys.path.append('.')
sys.path.append('..')

import unittest
import mock
import niftycloud_lan
import xml.etree.ElementTree as etree
import copy

class TestNiftycloud(unittest.TestCase):
	def setUp(self):
		self.mockModule = mock.MagicMock(
			params = dict(
				access_key        = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
				secret_access_key = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
				endpoint          = 'west-1.cp.cloud.nifty.com',
				private_lan_name  = 'lan001',
				cidr_block        = '10.0.1.0/24',
			    network_id        = 'net-0r16fxs1',
				accounting_type   = '1',
                description       = 'sample lan',
                availability_zone = 'west-11',
				state             = 'present',
			),
			fail_json = mock.MagicMock(side_effect=Exception('failed')),
			exit_json = mock.MagicMock(side_effect=Exception('success')),
		)

		self.xmlnamespace = 'https://west-1.cp.cloud.nifty.com/api/'
		self.xml = niftycloud_api_response_sample

		self.result = dict(
			absent = dict(
				created            = False,
				changed_attributes = dict(),
				state              = 'absent',
			),
			present = dict(
				created            = False,
				changed_attributes = dict(),
				state              = 'present',
			),
		)

		self.private_lan_set = dict(
			private_lan_name = 'lan001',
			cidr_block       = '10.0.1.0/16',
			network_id       = 'net-0r16fxs1',
            accounting_type  = '2',
            description      = None,
		)

		self.mockRequestsGetNiftyDescribePrivateLans = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['describePrivateLans']
			))

		self.mockRequestsGetNiftyDescribePrivateLansDescriptionUnicode = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['describePrivateLansDescriptionUnicode']
			))

		self.mockRequestsGetNiftyDescribePrivateLansDescriptionNone = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['describePrivateLansDescriptionNone']
			))

		self.mockRequestsGetNiftyDescribePrivateLansPending = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['describePrivateLansPending']
			))

		self.mockRequestsGetNiftyDescribePrivateLansNotFound = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['describePrivateLansNotFound']
			))

		self.mockRequestsPostNiftyCreatePrivateLan = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['createPrivateLan']
			))

		self.mockRequestsPostModifyPrivateLan = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['modifyPrivateLan']
			))

		self.mockRequestsPostDeletePrivateLan = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['deletePrivateLan']
			))

		self.mockRequestsInternalServerError = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 500,
				text = self.xml['internalServerError']
			))

		self.mockNiftyDescribePrivateLans = mock.MagicMock(
			return_value=dict(
				status = 200,
				xml_body = etree.fromstring(self.xml['describePrivateLans']),
				xml_namespace = dict(nc = self.xmlnamespace)
			))

		self.mockNotFoundPrivateLan = mock.MagicMock(
			return_value=(
				self.result['absent'],
				None
			))

		self.mockDescribePrivateLan = mock.MagicMock(
			return_value=(
				self.result['present'],
				self.private_lan_set,
			))

		self.mockRequestsError = mock.MagicMock(return_value=None)

		patcher = mock.patch('time.sleep')
		self.addCleanup(patcher.stop)
		self.mock_time_sleep = patcher.start()

	# calculate signature
	def test_calculate_signature(self):
		secret_access_key = self.mockModule.params['secret_access_key']
		method            = 'GET'
		endpoint          = self.mockModule.params['endpoint']
		path              = '/api/'
		params            = dict(
			Action           = 'NiftyDescribePrivateLans',
			AccessKeyId      = self.mockModule.params['access_key'],
			SignatureMethod  = 'HmacSHA256',
			SignatureVersion = '2',
			PrivateLanName        = self.mockModule.params['private_lan_name'],
		)

		signature = niftycloud_lan.calculate_signature(secret_access_key, method, endpoint, path, params)
		self.assertEqual(signature, 'l0xdhKPXLRxA9hl23sc6InPSWY2ufyFh6vdloS8GrDI=')

	# calculate signature with string parameter including slash
	def test_calculate_signature_with_slash(self):
		secret_access_key = self.mockModule.params['secret_access_key']
		method = 'GET'
		endpoint = self.mockModule.params['endpoint']
		path = '/api/'
		params = dict(
			Action           = 'NiftyDescribePrivateLans',
			AccessKeyId      = self.mockModule.params['access_key'],
			SignatureMethod  = 'HmacSHA256',
			SignatureVersion = '2',
			PrivateLanName   = self.mockModule.params['private_lan_name'],
			GroupDescription = '/'
		)

		signature = niftycloud_lan.calculate_signature(secret_access_key, method, endpoint, path, params)

		# This constant string is signature calculated by "library/tests/files/calculate_signature_sample.sh".
		# This shell-script calculate with encoding a slash, like "niftycloud.calculate_signature()".
		self.assertEqual(signature, 'hQBt07B35zaGVQwqlQ/UAJXuyyMXG2MG4yEW/8Pp5AQ=')

	# method get
	def test_request_to_api_get(self):
		method = 'GET'
		action = 'NiftyDescribePrivateLans'
		params = dict()
		params["PrivateLanName.1"] = self.mockModule.params['private_lan_name']

		with mock.patch('requests.get', self.mockRequestsGetNiftyDescribePrivateLans):
			info = niftycloud_lan.request_to_api(self.mockModule, method, action, params)

		self.assertEqual(info['status'], 200)
		self.assertEqual(info['xml_namespace'], dict(nc = self.xmlnamespace))
		self.assertEqual(etree.tostring(info['xml_body']),
				 etree.tostring(etree.fromstring(self.xml['describePrivateLans'])))

	# method post
	def test_request_to_api_post(self):
		method = 'POST'
		action = 'NiftyCreatePrivateLan'
		params = dict(
			PrivateLanName = self.mockModule.params['private_lan_name'],
		)

		with mock.patch('requests.post', self.mockRequestsPostNiftyCreatePrivateLan):
			info = niftycloud_lan.request_to_api(self.mockModule, method, action, params)

		self.assertEqual(info['status'], 200)
		self.assertEqual(info['xml_namespace'], dict(nc = self.xmlnamespace))
		self.assertEqual(etree.tostring(info['xml_body']),
				 etree.tostring(etree.fromstring(self.xml['createPrivateLan'])))

	# api error
	def test_request_to_api_error(self):
		method = 'GET'
		action = 'NiftyDescribePrivateLans'
		params = dict()
		params["PrivateLanName.1"] = self.mockModule.params['private_lan_name']

		with mock.patch('requests.get', self.mockRequestsInternalServerError):
			info = niftycloud_lan.request_to_api(self.mockModule, method, action, params)

		self.assertEqual(info['status'], 500)
		self.assertEqual(etree.tostring(info['xml_body']),
				 etree.tostring(etree.fromstring(self.xml['internalServerError'])))

	# method failed
	def test_request_to_api_unknown(self):
		method = 'UNKNOWN'
		action = 'NiftyDescribePrivateLans'
		params = dict()
		params["PrivateLanName.1"] = self.mockModule.params['private_lan_name']

		self.assertRaises(
			Exception,
			niftycloud_lan.request_to_api,
			(self.mockModule, method, action, params)
		)

	# network error
	def test_request_to_api_request_error(self):
		method = 'GET'
		action = 'NiftyDescribePrivateLans'
		params = dict()
		params["PrivateLanName.1"] = self.mockModule.params['private_lan_name']

		with mock.patch('requests.get', self.mockRequestsError):
			self.assertRaises(
				Exception,
				niftycloud_lan.request_to_api,
				(self.mockModule, method, action, params)
			)

	# get api error code & message
	def test_get_api_error(self):
		method = 'GET'
		action = 'NiftyDescribePrivateLans'
		params = dict()
		params["PrivateLanName.1"] = self.mockModule.params['private_lan_name']

		with mock.patch('requests.get', self.mockRequestsInternalServerError):
			info = niftycloud_lan.request_to_api(self.mockModule, method, action, params)

		error_info = niftycloud_lan.get_api_error(info['xml_body'])
		self.assertEqual(error_info['code'],    'Server.InternalError')
		self.assertEqual(error_info['message'], 'An error has occurred. Please try again later.')

	# throw failed
	def test_fail(self):
		with self.assertRaises(Exception) as cm:
			niftycloud_lan.fail(
				self.mockModule,
				self.result['absent'],
				'error message',
				private_lan_name = 'lan001'
			)
		self.assertEqual(cm.exception.message, 'failed')

	# describe present
	def test_describe_private_lans_present(self):
		with mock.patch('requests.get', self.mockRequestsGetNiftyDescribePrivateLans):
			(result, info) = niftycloud_lan.describe_private_lans(self.mockModule, self.result['absent'])

		self.assertEqual(result, dict(
			created            = False,
			changed_attributes = dict(),
			state              = 'present',
		))
		self.assertIsInstance(info, dict)
		self.assertEqual(info['private_lan_name'],  'lan001')
		self.assertIsInstance(info['description'], str)
		self.assertEqual(info['description'], 'sample lan')


	# describe present description unicode
	def test_describe_private_lans_description_unicode(self):
		with mock.patch('requests.get', self.mockRequestsGetNiftyDescribePrivateLansDescriptionUnicode):
			(result, info) = niftycloud_lan.describe_private_lans(self.mockModule, self.result['absent'])

		self.assertEqual(result, dict(
			created            = False,
			changed_attributes = dict(),
			state              = 'present',
		))
		self.assertIsInstance(info, dict)
		self.assertIsInstance(info['description'], str)
		self.assertEqual(info['description'], 'サンプルLAN')

	# describe present description none
	def test_describe_private_lans_description_none(self):
		with mock.patch('requests.get', self.mockRequestsGetNiftyDescribePrivateLansDescriptionNone):
			(result, info) = niftycloud_lan.describe_private_lans(self.mockModule, self.result['absent'])

		self.assertEqual(result, dict(
			created            = False,
			changed_attributes = dict(),
			state              = 'present',
		))
		self.assertIsInstance(info, dict)
		self.assertIsInstance(info['description'], str)
		self.assertEqual(info['description'], '')

	# describe pending
	def test_describe_private_lans_pending(self):
		with mock.patch('requests.get', self.mockRequestsGetNiftyDescribePrivateLansPending):
			(result, info) = niftycloud_lan.describe_private_lans(self.mockModule, self.result['absent'])

		self.assertEqual(result, dict(
			created            = False,
			changed_attributes = dict(),
			state              = 'pending',
		))
		self.assertIsNone(info)

	# describe absent
	def test_describe_private_lans_absent(self):
		with mock.patch('requests.get', self.mockRequestsGetNiftyDescribePrivateLansNotFound):
			(result, info) = niftycloud_lan.describe_private_lans(self.mockModule, self.result['absent'])

		self.assertEqual(result, dict(
			created            = False,
			changed_attributes = dict(),
			state              = 'absent',
		))
		self.assertIsNone(info)

	# describe failed
	def test_describe_private_lans_failed(self):
		with mock.patch('requests.get', self.mockRequestsInternalServerError):
			(result, info) = niftycloud_lan.describe_private_lans(self.mockModule, self.result['absent'])

		self.assertEqual(result, dict(
			created            = False,
			changed_attributes = dict(),
			state              = 'absent',
		))
		self.assertIsNone(info)

	# wait_for_pending success absent
	def test_wait_for_pending_success_absent(self):
		with mock.patch('niftycloud_lan.describe_private_lans', self.mockNotFoundPrivateLan):
			(result, info) = niftycloud_lan.wait_for_pending(self.mockModule, self.result['absent'], 'absent')

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# wait_for_pending success present
	def test_wait_for_pending_success_present(self):
		with mock.patch('niftycloud_lan.describe_private_lans', self.mockDescribePrivateLan):
			(result, info) = niftycloud_lan.wait_for_pending(self.mockModule, self.result['absent'], 'present')

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info,   self.private_lan_set)

	# wait_for_pending unmatch absent
	def test_wait_for_pending_failed_absent(self):
		with mock.patch('niftycloud_lan.describe_private_lans', self.mockDescribePrivateLan):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_lan.wait_for_pending(self.mockModule, self.result['absent'], 'absent')

		self.assertEqual(cm.exception.message, 'failed')

	# wait_for_pending unmatch present
	def test_wait_for_pending_failed_present(self):
		with mock.patch('niftycloud_lan.describe_private_lans', self.mockNotFoundPrivateLan):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_lan.wait_for_pending(self.mockModule, self.result['absent'], 'present')

		self.assertEqual(cm.exception.message, 'failed')

	# create present  * do nothing
	def test_create_private_lan_skip(self):
		(result, info) = niftycloud_lan.create_private_lan(
			self.mockModule,
			self.result['present'],
			self.private_lan_set
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info,   self.private_lan_set)

	# create success
	def test_create_private_lan_success(self):
		with mock.patch('requests.get', self.mockRequestsPostNiftyCreatePrivateLan):
			with mock.patch('niftycloud_lan.describe_private_lans', self.mockDescribePrivateLan):
				(result, info) = niftycloud_lan.create_private_lan(
					self.mockModule,
					self.result['absent'],
					None
				)

		self.assertEqual(result, dict(
			created            = True,
			changed_attributes = dict(),
			state              = 'present',
		))
		self.assertEqual(info, self.private_lan_set)

	# create failed
	def test_create_private_lan_failed(self):
		with mock.patch('requests.post', self.mockRequestsPostNiftyCreatePrivateLan):
			with mock.patch('niftycloud_lan.describe_private_lans', self.mockNotFoundPrivateLan):
				with self.assertRaises(Exception) as cm:
					niftycloud_lan.create_private_lan(
						self.mockModule,
						self.result['absent'],
						None
					)
		self.assertEqual(cm.exception.message, 'failed')

	# create request failed
	def test_create_private_lan_request_failed(self):
		with mock.patch('requests.post', self.mockRequestsInternalServerError):
			with self.assertRaises(Exception) as cm:
				niftycloud_lan.create_private_lan(
					self.mockModule,
					self.result['absent'],
					None
				)
		self.assertEqual(cm.exception.message, 'failed')

	# modify api success
	def test_modify_private_lan_attribute_success(self):
		params = dict(
			NetworkId = self.mockModule.params['network_id'],
			Attribute = 'description',
			Value     = self.mockModule.params['description'],
		)

		with mock.patch('requests.post', self.mockRequestsPostModifyPrivateLan):
			with mock.patch('niftycloud_lan.describe_private_lans', self.mockDescribePrivateLan):
				(result, info) = niftycloud_lan.modify_private_lan_attribute(
					self.mockModule,
					self.result['present'],
					self.private_lan_set,
					params
				)
		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, self.private_lan_set)

	# modify api absent  * do nothing
	def test_modify_private_lan_attribute_absent(self):
		params = dict(
			NetworkId = self.mockModule.params['network_id'],
			Attribute = 'description',
			Value     = self.mockModule.params['description'],
		)

		(result, info) = niftycloud_lan.modify_private_lan_attribute(
			self.mockModule,
			self.result['absent'],
			None,
			params
		)

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# modify api failed
	def test_modify_private_lan_attribute_failed(self):
		params = dict(
			NetworkId = self.mockModule.params['network_id'],
			Attribute = 'description',
			Value     = self.mockModule.params['description'],
		)

		with mock.patch('requests.post', self.mockRequestsPostModifyPrivateLan):
			with mock.patch('niftycloud_lan.describe_private_lans', self.mockNotFoundPrivateLan):
				with self.assertRaises(Exception) as cm:
					(result, info) = niftycloud_lan.modify_private_lan_attribute(
						self.mockModule,
						self.result['present'],
						self.private_lan_set,
						params
					)
		self.assertEqual(cm.exception.message, 'failed')

	# modify api request failed
	def test_modify_private_lan_attribute_request_failed(self):
		params = dict(
			NetworkId = self.mockModule.params['network_id'],
			Attribute = 'description',
			Value     = self.mockModule.params['description'],
		)

		with mock.patch('requests.post', self.mockRequestsInternalServerError):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_lan.modify_private_lan_attribute(
					self.mockModule,
					self.result['present'],
					self.private_lan_set,
					params
				)
		self.assertEqual(cm.exception.message, 'failed')

	# modify description success
	def test_modify_private_lan_description_success(self):
		changed_private_lan_set = dict(
			copy.deepcopy(self.private_lan_set),
			description = self.mockModule.params['description'],
		)
		mock_describe_private_lan = mock.MagicMock(
			return_value=(
				self.result['present'],
				changed_private_lan_set,
			))

		with mock.patch('niftycloud_lan.modify_private_lan_attribute', mock_describe_private_lan):
			(result, info) = niftycloud_lan.modify_private_lan_description(
				self.mockModule,
				self.result['present'],
				self.private_lan_set
			)

		self.assertEqual(result, dict(
			created = False,
			changed_attributes = dict(
				description = self.mockModule.params['description'],
			),
			state = 'present',
		))
		self.assertEqual(info, changed_private_lan_set)

	# modify description absent  * do nothing
	def test_modify_private_lan_description_absent(self):
		(result, info) = niftycloud_lan.modify_private_lan_description(
			self.mockModule,
			self.result['absent'],
			None
		)

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# modify description is None  * do nothing
	def test_modify_private_lan_description_none(self):
		private_lan_set = dict(
			copy.deepcopy(self.private_lan_set),
			description = self.mockModule.params['description'],
		)
		mock_module = mock.MagicMock(
			params = dict(
				copy.deepcopy(self.mockModule.params),
				description = None,
			)
        )

		(result, info) = niftycloud_lan.modify_private_lan_description(
			self.mockModule,
			self.result['present'],
			private_lan_set
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, private_lan_set)

	# modify description is no change  * do nothing
	def test_modify_private_lan_description_skip(self):
		changed_private_lan_set = dict(
			copy.deepcopy(self.private_lan_set),
			description = self.mockModule.params['description'],
		)

		(result, info) = niftycloud_lan.modify_private_lan_description(
			self.mockModule,
			self.result['present'],
			changed_private_lan_set
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, changed_private_lan_set)

	# modify description failed
	def test_modify_private_lan_description_failed(self):
		with mock.patch('niftycloud_lan.modify_private_lan_attribute', self.mockDescribePrivateLan):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_lan.modify_private_lan_description(
					self.mockModule,
					self.result['present'],
					self.private_lan_set
				)
		self.assertEqual(cm.exception.message, 'failed')

	# modify private lan name success
	def test_modify_private_lan_name_success(self):
		changed_private_lan_set = dict(
			copy.deepcopy(self.private_lan_set),
			private_lan_name = 'lan002',
		)
		mack_describe = mock.MagicMock(
			return_value=(
				self.result['present'],
				changed_private_lan_set,
			))
		mock_module = self.mockModule
		mock_module.params['private_lan_name'] = 'lan002'
		
		with mock.patch('niftycloud_lan.modify_private_lan_attribute', mack_describe):
			(result, info) = niftycloud_lan.modify_private_lan_name(
				mock_module,
				self.result['present'],
				self.private_lan_set
			)

		self.assertEqual(result, dict(
			created = False,
			changed_attributes = dict(
				private_lan_name = 'lan002',
			),
			state = 'present',
		))
		self.assertEqual(info, changed_private_lan_set)

	# modify private lan name absent  * do nothing
	def test_modify_private_lan_name_absent(self):
		(result, info) = niftycloud_lan.modify_private_lan_name(
			self.mockModule,
			self.result['absent'],
			None
		)

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# modify private lan name is None  * do nothing
	def test_modify_private_lan_name_none(self):
		private_lan_set = dict(
			copy.deepcopy(self.private_lan_set),
			private_lan_name = self.mockModule.params['private_lan_name'],
		)
		mock_module = mock.MagicMock(
			params = dict(
				copy.deepcopy(self.mockModule.params),
				private_lan_name = None,
			)
    )

		(result, info) = niftycloud_lan.modify_private_lan_name(
			self.mockModule,
			self.result['present'],
			private_lan_set
		)
	
		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, private_lan_set)

	# modify private lan name is no change  * do nothing
	def test_modify_private_lan_name_skip(self):
		changed_private_lan_set = dict(
			copy.deepcopy(self.private_lan_set),
			private_lan_name = self.mockModule.params['private_lan_name'],
		)
	
		(result, info) = niftycloud_lan.modify_private_lan_name(
			self.mockModule,
			self.result['present'],
			changed_private_lan_set
		)
	
		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, changed_private_lan_set)

	# modify private lan name failed
	def test_modify_private_lan_name_failed(self):
		changed_private_lan_set = dict(
			copy.deepcopy(self.private_lan_set),
			private_lan_name = 'lan002',
		)
		mock_module = self.mockModule
		mock_module.params['private_lan_name'] = 'lan002'
		with mock.patch('niftycloud_lan.modify_private_lan_attribute', self.mockDescribePrivateLan):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_lan.modify_private_lan_name(
					mock_module,
					self.result['present'],
					self.private_lan_set
				)
		self.assertEqual(cm.exception.message, 'failed')


	# modify cidr_block success
	def test_modify_private_lan_cidr_block_success(self):
		changed_private_lan_set = dict(
			copy.deepcopy(self.private_lan_set),
			cidr_block = self.mockModule.params['cidr_block'],
		)
		mock_describe_private_lan = mock.MagicMock(
			return_value=(
				self.result['present'],
				changed_private_lan_set,
			))

		with mock.patch('niftycloud_lan.modify_private_lan_attribute', mock_describe_private_lan):
			(result, info) = niftycloud_lan.modify_private_lan_cidr_block(
				self.mockModule,
				self.result['present'],
				self.private_lan_set
			)

		self.assertEqual(result, dict(
			created = False,
			changed_attributes = dict(
				cidr_block = self.mockModule.params['cidr_block'],
			),
			state = 'present',
		))
		self.assertEqual(info, changed_private_lan_set)

	# modify cidr_block absent  * do nothing
	def test_modify_private_lan_cidr_block_absent(self):
		(result, info) = niftycloud_lan.modify_private_lan_cidr_block(
			self.mockModule,
			self.result['absent'],
			None
		)

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# modify cidr_block is None  * do nothing
	def test_modify_private_lan_cidr_block_none(self):
		private_lan_set = dict(
			copy.deepcopy(self.private_lan_set),
			cidr_block = self.mockModule.params['cidr_block'],
		)
		mock_module = mock.MagicMock(
			params = dict(
				copy.deepcopy(self.mockModule.params),
				cidr_block = None,
			)
        )

		(result, info) = niftycloud_lan.modify_private_lan_cidr_block(
			self.mockModule,
			self.result['present'],
			private_lan_set
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, private_lan_set)

	# modify cidr_block is no change  * do nothing
	def test_modify_private_lan_cidr_block_skip(self):
		changed_private_lan_set = dict(
			copy.deepcopy(self.private_lan_set),
			cidr_block = self.mockModule.params['cidr_block'],
		)

		(result, info) = niftycloud_lan.modify_private_lan_cidr_block(
			self.mockModule,
			self.result['present'],
			changed_private_lan_set
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, changed_private_lan_set)

	# modify cidr_block failed
	def test_modify_private_lan_cidr_block_failed(self):
		with mock.patch('niftycloud_lan.modify_private_lan_attribute', self.mockDescribePrivateLan):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_lan.modify_private_lan_cidr_block(
					self.mockModule,
					self.result['present'],
					self.private_lan_set
				)
		self.assertEqual(cm.exception.message, 'failed')

	# modify accounting_type success
	def test_modify_private_lan_accounting_type_success(self):
		changed_private_lan_set = dict(
			copy.deepcopy(self.private_lan_set),
			accounting_type = self.mockModule.params['accounting_type'],
		)
		mock_describe_private_lan = mock.MagicMock(
			return_value=(
				self.result['present'],
				changed_private_lan_set,
			))

		with mock.patch('niftycloud_lan.modify_private_lan_attribute', mock_describe_private_lan):
			(result, info) = niftycloud_lan.modify_private_lan_accounting_type(
				self.mockModule,
				self.result['present'],
				self.private_lan_set
			)

		self.assertEqual(result, dict(
			created = False,
			changed_attributes = dict(
				accounting_type = self.mockModule.params['accounting_type'],
			),
			state = 'present',
		))
		self.assertEqual(info, changed_private_lan_set)

	# modify accounting_type absent  * do nothing
	def test_modify_private_lan_accounting_type_absent(self):
		(result, info) = niftycloud_lan.modify_private_lan_accounting_type(
			self.mockModule,
			self.result['absent'],
			None
		)

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# modify accounting_type is None  * do nothing
	def test_modify_private_lan_accounting_type_none(self):
		private_lan_set = dict(
			copy.deepcopy(self.private_lan_set),
			accounting_type = self.mockModule.params['accounting_type'],
		)
		mock_module = mock.MagicMock(
			params = dict(
				copy.deepcopy(self.mockModule.params),
				accounting_type = None,
			)
        )

		(result, info) = niftycloud_lan.modify_private_lan_accounting_type(
			self.mockModule,
			self.result['present'],
			private_lan_set
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, private_lan_set)

	# modify accounting_type is no change  * do nothing
	def test_modify_private_lan_accounting_type_skip(self):
		changed_private_lan_set = dict(
			copy.deepcopy(self.private_lan_set),
			accounting_type = self.mockModule.params['accounting_type'],
		)

		(result, info) = niftycloud_lan.modify_private_lan_accounting_type(
			self.mockModule,
			self.result['present'],
			changed_private_lan_set
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, changed_private_lan_set)

	# modify accounting_type failed
	def test_modify_private_lan_accounting_type_failed(self):
		with mock.patch('niftycloud_lan.modify_private_lan_attribute', self.mockDescribePrivateLan):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_lan.modify_private_lan_accounting_type(
					self.mockModule,
					self.result['present'],
					self.private_lan_set
				)
		self.assertEqual(cm.exception.message, 'failed')

	# modify
	def test_modify_private_lan(self):
		with mock.patch('niftycloud_lan.modify_private_lan_name', self.mockDescribePrivateLan):
			with mock.patch('niftycloud_lan.modify_private_lan_cidr_block', self.mockDescribePrivateLan):
				with mock.patch('niftycloud_lan.modify_private_lan_accounting_type', self.mockDescribePrivateLan):
					with mock.patch('niftycloud_lan.modify_private_lan_description', self.mockDescribePrivateLan):
						(result, info) = niftycloud_lan.modify_private_lan(
							self.mockModule,
							self.result['present'],
							self.private_lan_set
						)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, self.private_lan_set)

	# modify absent  * do nothing
	def test_modify_private_lan_absent(self):
		(result, info) = niftycloud_lan.modify_private_lan(
			self.mockModule,
			self.result['absent'],
			None
		)

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# delete success
	def test_delete_private_lan_success(self):

		private_lan_set = dict(
			copy.deepcopy(self.private_lan_set),
		)
		mock_private_lan_set = mock.MagicMock(
			return_value=(
				self.result['absent'],
				self.private_lan_set
			))

		with mock.patch('requests.post', self.mockRequestsPostDeletePrivateLan):
			with mock.patch('niftycloud_lan.describe_private_lans', mock_private_lan_set):
				(result, info) = niftycloud_lan.delete_private_lan(
					self.mockModule,
					self.result['present'],
					private_lan_set
				)

		self.assertEqual(result, dict(
			created = False,
			changed_attributes = dict(
				private_lan_name = self.private_lan_set['private_lan_name'],
			),
			state = 'absent',
		))

	# delete absent  * do nothing
	def test_delete_private_lan_absent(self):
		(result, info) = niftycloud_lan.delete_private_lan(
			self.mockModule,
			self.result['absent'],
			None
		)

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# delete failed
	def test_delete_private_lan_failed(self):
		with mock.patch('requests.post', self.mockRequestsPostDeletePrivateLan):
			with mock.patch('niftycloud_lan.describe_private_lans', self.mockDescribePrivateLan):
				with self.assertRaises(Exception) as cm:
					niftycloud_lan.delete_private_lan(
						self.mockModule,
						self.result['present'],
						self.private_lan_set
					)
		self.assertEqual(cm.exception.message, 'failed')

	# delete request failed
	def test_delete_private_lan_request_failed(self):
		with mock.patch('requests.post', self.mockRequestsInternalServerError):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_lan.delete_private_lan(
					self.mockModule,
					self.result['present'],
					self.private_lan_set
				)
		self.assertEqual(cm.exception.message, 'failed')

	# run success (absent - create -> present - other action -> present)
	def test_run_success_absent(self):
		with mock.patch('niftycloud_lan.describe_private_lans', self.mockNotFoundPrivateLan):
			with mock.patch('niftycloud_lan.create_private_lan', self.mockDescribePrivateLan):
				with mock.patch('niftycloud_lan.modify_private_lan', self.mockDescribePrivateLan):
					with mock.patch('niftycloud_lan.delete_private_lan', self.mockDescribePrivateLan):
						with self.assertRaises(Exception) as cm:
							niftycloud_lan.run(self.mockModule)
		self.assertEqual(cm.exception.message, 'success')

	# run success (present - create skip -> present - other action -> present)
	def test_run_success_present(self):
		with mock.patch('niftycloud_lan.describe_private_lans', self.mockDescribePrivateLan):
			with mock.patch('niftycloud_lan.modify_private_lan', self.mockDescribePrivateLan):
				with mock.patch('niftycloud_lan.delete_private_lan', self.mockDescribePrivateLan):
					with self.assertRaises(Exception) as cm:
						niftycloud_lan.run(self.mockModule)
		self.assertEqual(cm.exception.message, 'success')

niftycloud_api_response_sample = dict(
	describePrivateLans = '''
<NiftyDescribePrivateLansResponse xmlns="https://west-1.cp.cloud.nifty.com/api/">
 <requestId>5ec8da0a-6e23-4343-b474-ca0bb5c22a51</requestId>
 <privateLanSet>
  <networkId>net-8db04f81</networkId>
  <privateLanName>lan001</privateLanName>
  <state>available</state>
  <cidrBlock>10.0.1.0/24</cidrBlock>
  <availabilityZone>west-11</availabilityZone>
  <tagSet/>
  <accountingType>1</accountingType>
  <description>sample lan</description>
  <instancesSet/>
  <routerSet/>
  <vpnGatewaySet/>
  <createdTime>2014-10-28T10:16:38+09:00</createdTime>
 </privateLanSet>
</NiftyDescribePrivateLansResponse>
''',
	describePrivateLansDescriptionUnicode = u'''
<NiftyDescribePrivateLansResponse xmlns="https://west-1.cp.cloud.nifty.com/api/">
 <requestId>5ec8da0a-6e23-4343-b474-ca0bb5c22a51</requestId>
 <privateLanSet>
  <networkId>net-8db04f81</networkId>
  <privateLanName>lan002</privateLanName>
  <state>available</state>
  <cidrBlock>10.0.1.0/24</cidrBlock>
  <availabilityZone>west-11</availabilityZone>
  <tagSet/>
  <accountingType>1</accountingType>
  <description>サンプルLAN</description>
  <instancesSet/>
  <routerSet/>
  <vpnGatewaySet/>
  <createdTime>2014-10-28T10:16:38+09:00</createdTime>
 </privateLanSet>
</NiftyDescribePrivateLansResponse>
''',
	describePrivateLansDescriptionNone = '''
<NiftyDescribePrivateLansResponse xmlns="https://west-1.cp.cloud.nifty.com/api/">
 <requestId>5ec8da0a-6e23-4343-b474-ca0bb5c22a51</requestId>
 <privateLanSet>
  <networkId>net-8db04f81</networkId>
  <privateLanName>lan002</privateLanName>
  <state>available</state>
  <cidrBlock>10.0.1.0/24</cidrBlock>
  <availabilityZone>west-11</availabilityZone>
  <tagSet/>
  <accountingType>1</accountingType>
  <description/>
  <instancesSet/>
  <routerSet/>
  <vpnGatewaySet/>
  <createdTime>2014-10-28T10:16:38+09:00</createdTime>
 </privateLanSet>
</NiftyDescribePrivateLansResponse>
''',
	describePrivateLansPending = '''
<NiftyDescribePrivateLansResponse xmlns="https://west-1.cp.cloud.nifty.com/api/">
 <requestId>5ec8da0a-6e23-4343-b474-ca0bb5c22a51</requestId>
 <privateLanSet>
  <networkId>net-8db04f81</networkId>
  <privateLanName>lan002</privateLanName>
  <state>pending</state>
  <cidrBlock>10.0.1.0/24</cidrBlock>
  <availabilityZone>west-11</availabilityZone>
  <tagSet/>
  <accountingType>1</accountingType>
  <description/>
  <instancesSet/>
  <routerSet/>
  <vpnGatewaySet/>
  <createdTime>2014-10-28T10:16:38+09:00</createdTime>
 </privateLanSet>
</NiftyDescribePrivateLansResponse>
''',
	describePrivateLansNotFound = '''
<NiftyDescribePrivateLansResponse xmlns="https://west-1.cp.cloud.nifty.com/api/">
 <requestId>5ec8da0a-6e23-4343-b474-ca0bb5c22a51</requestId>
 <privateLanSet/>
</NiftyDescribePrivateLansResponse>
''',
	createPrivateLan = '''
<NiftyCreatePrivateLanResponse xmlns="https://west-1.cp.cloud.nifty.com/api/">
 <requestId>5ec8da0a-6e23-4343-b474-ca0bb5c22a51</requestId>
 <return>true</return>
</NiftyCreatePrivateLanResponse>
''',
	modifyPrivateLan = '''
<ModifyPrivateLanResponse xmlns="https://west-1.cp.cloud.nifty.com/api/">
 <requestId>5ec8da0a-6e23-4343-b474-ca0bb5c22a51</requestId>
 <return>true</return>
</ModifyPrivateLanResponse>
''',
	deletePrivateLan = '''
<DeletePrivateLanIngressResponse xmlns="https://west-1.cp.cloud.nifty.com/api/">
 <requestId>5ec8da0a-6e23-4343-b474-ca0bb5c22a51</requestId>
 <return>true</return>
</DeletePrivateLanIngressResponse>
''',
	internalServerError = '''
<Response>
 <Errors>
  <Error>
   <Code>Server.InternalError</Code>
   <Message>An error has occurred. Please try again later.</Message>
  </Error>
 </Errors>
 <RequestID>5ec8da0a-6e23-4343-b474-ca0bb5c22a51</RequestID>
</Response>
'''
)

if __name__ == '__main__':
	unittest.main()

