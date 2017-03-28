# -*- coding: utf-8 -*-

import os
import sys
sys.path.append('.')
sys.path.append('..')

import unittest
import mock
import niftycloud_fw
import xml.etree.ElementTree as etree
import copy

class TestNiftycloud(unittest.TestCase):
	def setUp(self):
		self.mockModule = mock.MagicMock(
			params = dict(
				access_key           = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
				secret_access_key    = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
				endpoint             = 'west-1.cp.cloud.nifty.com',
				group_name           = 'fw001',
				description          = 'test firewall',
				availability_zone    = 'west-11',
				log_limit            = 100000,
				state                = 'present',
				log_filters          = dict(
					net_bios  = True,
					broadcast = True,
				),
				ip_permissions       = [
					dict(
						in_out      = 'OUT',
						ip_protocol = 'ANY',
						cidr_ip     = '0.0.0.0/0',
						description = 'all outgoing protocols are allow',
					),
					dict(
						in_out      = 'IN',
						ip_protocol = 'ICMP',
						cidr_ip     = '192.168.0.0/24',
					),
					dict(
						in_out      = 'IN',
						ip_protocol = 'SSH',
						cidr_ip     = '10.0.0.11',
					),
					dict(
						in_out      = 'IN',
						ip_protocol = 'UDP',
						from_port   = 20000,
						to_port     = 29999,
						group_name  = 'admin',
					),
					dict(
						in_out      = 'IN',
						ip_protocol = 'TCP',
						from_port   = 20000,
						to_port     = 29999,
						group_name  = 'admin',
					),
				],
			),
			fail_json = mock.MagicMock(side_effect=Exception('failed')),
			exit_json = mock.MagicMock(side_effect=Exception('success')),
		)

		self.xmlnamespace = 'https://cp.cloud.nifty.com/api/'
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

		self.security_group_info = dict(
			group_name     = 'fw001',
			description    = None,
			log_limit      = 1000,
			log_filters    = dict(
				net_bios  = False,
				broadcast = False,
			),
			ip_permissions = [
				dict(
					in_out      = 'OUT',
					ip_protocol = 'HTTP',
					cidr_ip     = '0.0.0.0/0',
				),
				dict(
					in_out      = 'OUT',
					ip_protocol = 'TCP',
					from_port   = 10000,
					to_port     = 19999,
					group_name  = 'admin',
				),
			],
		)

		self.mockRequestsGetDescribeSecurityGroups = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['describeSecurityGroups']
			))

		self.mockRequestsGetDescribeSecurityGroupsDescriptionUnicode = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['describeSecurityGroupsDescriptionUnicode']
			))

		self.mockRequestsGetDescribeSecurityGroupsDescriptionNone = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['describeSecurityGroupsDescriptionNone']
			))

		self.mockRequestsGetDescribeSecurityGroupsProcessing = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['describeSecurityGroupsProcessing']
			))

		self.mockRequestsGetDescribeSecurityGroupsNotFound = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['describeSecurityGroupsNotFound']
			))

		self.mockRequestsPostCreateSecurityGroup = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['createSecurityGroup']
			))

		self.mockRequestsPostUpdateSecurityGroup = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['updateSecurityGroup']
			))

		self.mockRequestsPostAuthorizeSecurityGroup = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['authorizeSecurityGroup']
			))

		self.mockRequestsPostRevokeSecurityGroup = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['revokeSecurityGroup']
			))

		self.mockRequestsInternalServerError = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 500,
				text = self.xml['internalServerError']
			))

		self.mockDescribeSecurityGroups = mock.MagicMock(
			return_value=dict(
				status = 200,
				xml_body = etree.fromstring(self.xml['describeSecurityGroups']),
				xml_namespace = dict(nc = self.xmlnamespace)
			))

		self.mockNotFoundSecurityGroup = mock.MagicMock(
			return_value=(
				self.result['absent'],
				None
			))

		self.mockDescribeSecurityGroup = mock.MagicMock(
			return_value=(
				self.result['present'],
				self.security_group_info,
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
			Action           = 'DescribeSecurityGroups',
			AccessKeyId      = self.mockModule.params['access_key'],
			SignatureMethod  = 'HmacSHA256',
			SignatureVersion = '2',
			GroupName        = self.mockModule.params['group_name'],
		)

		signature = niftycloud_fw.calculate_signature(secret_access_key, method, endpoint, path, params)
		self.assertEqual(signature, '+05Mgbw/WCN+U6euoFzHIyFi8i9UUTGg1uiNHqYcu38=')

	# method get
	def test_request_to_api_get(self):
		method = 'GET'
		action = 'DescribeSecurityGroups'
		params = dict()
		params["GroupName.1"] = self.mockModule.params['group_name']

		with mock.patch('requests.get', self.mockRequestsGetDescribeSecurityGroups):
			info = niftycloud_fw.request_to_api(self.mockModule, method, action, params)

		self.assertEqual(info['status'], 200)
		self.assertEqual(info['xml_namespace'], dict(nc = self.xmlnamespace))
		self.assertEqual(etree.tostring(info['xml_body']),
				 etree.tostring(etree.fromstring(self.xml['describeSecurityGroups'])))

	# method post
	def test_request_to_api_post(self):
		method = 'POST'
		action = 'CreateSecurityGroup'
		params = dict(
			GroupName = self.mockModule.params['group_name'],
		)

		with mock.patch('requests.post', self.mockRequestsPostCreateSecurityGroup):
			info = niftycloud_fw.request_to_api(self.mockModule, method, action, params)

		self.assertEqual(info['status'], 200)
		self.assertEqual(info['xml_namespace'], dict(nc = self.xmlnamespace))
		self.assertEqual(etree.tostring(info['xml_body']),
				 etree.tostring(etree.fromstring(self.xml['createSecurityGroup'])))

	# api error
	def test_request_to_api_error(self):
		method = 'GET'
		action = 'DescribeSecurityGroups'
		params = dict()
		params["GroupName.1"] = self.mockModule.params['group_name']

		with mock.patch('requests.get', self.mockRequestsInternalServerError):
			info = niftycloud_fw.request_to_api(self.mockModule, method, action, params)

		self.assertEqual(info['status'], 500)
		self.assertEqual(etree.tostring(info['xml_body']),
				 etree.tostring(etree.fromstring(self.xml['internalServerError'])))

	# method failed
	def test_request_to_api_unknown(self):
		method = 'UNKNOWN'
		action = 'DescribeSecurityGroups'
		params = dict()
		params["GroupName.1"] = self.mockModule.params['group_name']

		self.assertRaises(
			Exception,
			niftycloud_fw.request_to_api,
			(self.mockModule, method, action, params)
		)

	# network error
	def test_request_to_api_request_error(self):
		method = 'GET'
		action = 'DescribeSecurityGroups'
		params = dict()
		params["GroupName.1"] = self.mockModule.params['group_name']

		with mock.patch('requests.get', self.mockRequestsError):
			self.assertRaises(
				Exception,
				niftycloud_fw.request_to_api,
				(self.mockModule, method, action, params)
			)

	# get api error code & message
	def test_get_api_error(self):
		method = 'GET'
		action = 'DescribeSecurityGroups'
		params = dict()
		params["GroupName.1"] = self.mockModule.params['group_name']

		with mock.patch('requests.get', self.mockRequestsInternalServerError):
			info = niftycloud_fw.request_to_api(self.mockModule, method, action, params)

		error_info = niftycloud_fw.get_api_error(info['xml_body'])
		self.assertEqual(error_info['code'],    'Server.InternalError')
		self.assertEqual(error_info['message'], 'An error has occurred. Please try again later.')

	# throw failed
	def test_fail(self):
		with self.assertRaises(Exception) as cm:
			niftycloud_fw.fail(
				self.mockModule,
				self.result['absent'],
				'error message',
				group_name = 'fw001'
			)
		self.assertEqual(cm.exception.message, 'failed')

	# contains_ip_permissions true case 1
	def test_contains_ip_permissions_true_case_1(self):
		ip_permissions = [
			dict(
				in_out      = 'OUT',
				ip_protocol = 'ANY',
				cidr_ip     = '0.0.0.0/0',
				description = 'all outgoing protocols are allow',
			),
			dict(
				in_out      = 'IN',
				ip_protocol = 'UDP',
				from_port   = 20000,
				to_port     = 29999,
				group_name  = 'admin',
			),
		]
		ip_permission = dict(
			in_out      = 'OUT',
			ip_protocol = 'ANY',
			cidr_ip     = '0.0.0.0/0',
			description = None,
			from_port   = None,
			to_port     = None,
			group_name  = None,
		)
		self.assertTrue(niftycloud_fw.contains_ip_permissions(ip_permissions, ip_permission))

	# contains_ip_permissions true case 2
	def test_contains_ip_permissions_true_case_2(self):
		ip_permissions = [
			dict(
				in_out      = 'OUT',
				ip_protocol = 'ANY',
				cidr_ip     = '0.0.0.0/0',
				description = 'all outgoing protocols are allow',
			),
			dict(
				in_out      = 'IN',
				ip_protocol = 'UDP',
				from_port   = 20000,
				to_port     = 29999,
				group_name  = 'admin',
			),
		]
		ip_permission = dict(
			in_out      = 'IN',
			ip_protocol = 'UDP',
			from_port   = 20000,
			to_port     = 29999,
			group_name  = 'admin',
			description = 'dummy',
			cidr_ip     = None,
		)
		self.assertTrue(niftycloud_fw.contains_ip_permissions(ip_permissions, ip_permission))

	# contains_ip_permissions true case 3
	def test_contains_ip_permissions_true_case_3(self):
		ip_permissions = [
			dict(
				in_out      = 'OUT',
				ip_protocol = 'ANY',
				cidr_ip     = '0.0.0.0/0',
				description = 'all outgoing protocols are allow',
			),
			dict(
				in_out      = 'IN',
				ip_protocol = 'UDP',
				from_port   = 20000,
				to_port     = 20000,
				group_name  = 'admin',
			),
		]
		ip_permission = dict(
			in_out      = 'IN',
			ip_protocol = 'UDP',
			from_port   = 20000,
			to_port     = None,
			group_name  = 'admin',
			description = 'dummy',
			cidr_ip     = None,
		)
		self.assertTrue(niftycloud_fw.contains_ip_permissions(ip_permissions, ip_permission))

	# contains_ip_permissions true case 4
	def test_contains_ip_permissions_true_case_4(self):
		ip_permissions = [
			dict(
				in_out      = 'OUT',
				ip_protocol = 'ANY',
				cidr_ip     = '0.0.0.0/0',
				description = 'all outgoing protocols are allow',
			),
			dict(
				in_out      = 'IN',
				ip_protocol = 'UDP',
				from_port   = 20000,
				group_name  = 'admin',
			),
		]
		ip_permission = dict(
			in_out      = 'IN',
			ip_protocol = 'UDP',
			from_port   = 20000,
			to_port     = 20000,
			group_name  = 'admin',
			description = 'dummy',
			cidr_ip     = None,
		)
		self.assertTrue(niftycloud_fw.contains_ip_permissions(ip_permissions, ip_permission))

	# has_ip_permission false case 1
	def test_contains_ip_permissions_false_case_1(self):
		ip_permissions = [
			dict(
				in_out      = 'OUT',
				ip_protocol = 'ANY',
				cidr_ip     = '0.0.0.0/0',
				description = 'all outgoing protocols are allow',
			),
			dict(
				in_out      = 'IN',
				ip_protocol = 'TCP',
				from_port   = 20000,
				to_port     = 29999,
				group_name  = 'admin',
			),
		]
		ip_permission = dict(
			in_out      = 'IN',
			ip_protocol = 'ANY',
			cidr_ip     = '0.0.0.0/0',
			description = 'all outgoing protocols are allow',
		)
		self.assertFalse(niftycloud_fw.contains_ip_permissions(ip_permissions, ip_permission))

	# contains_ip_permissions false case 2
	def test_contains_ip_permissions_false_case_2(self):
		ip_permissions = [
			dict(
				in_out      = 'OUT',
				ip_protocol = 'ANY',
				cidr_ip     = '0.0.0.0/0',
				description = 'all outgoing protocols are allow',
			),
			dict(
				in_out      = 'IN',
				ip_protocol = 'TCP',
				from_port   = 20000,
				to_port     = 29999,
				group_name  = 'admin',
			),
		]
		ip_permission = dict(
			in_out      = 'OUT',
			ip_protocol = 'ICMP',
			cidr_ip     = '0.0.0.0/0',
			description = 'all outgoing protocols are allow',
		)
		self.assertFalse(niftycloud_fw.contains_ip_permissions(ip_permissions, ip_permission))

	# contains_ip_permissions false case 3
	def test_contains_ip_permissions_false_case_3(self):
		ip_permissions = [
			dict(
				in_out      = 'OUT',
				ip_protocol = 'ANY',
				cidr_ip     = '0.0.0.0/0',
				description = 'all outgoing protocols are allow',
			),
			dict(
				in_out      = 'IN',
				ip_protocol = 'TCP',
				from_port   = 20000,
				to_port     = 29999,
				group_name  = 'admin',
			),
		]
		ip_permission = dict(
			in_out      = 'OUT',
			ip_protocol = 'ALL',
			cidr_ip     = '10.0.0.0/16',
			description = 'all outgoing protocols are allow',
		)
		self.assertFalse(niftycloud_fw.contains_ip_permissions(ip_permissions, ip_permission))

	# contains_ip_permissions false case 4
	def test_contains_ip_permissions_false_case_3(self):
		ip_permissions = [
			dict(
				in_out      = 'OUT',
				ip_protocol = 'ANY',
				cidr_ip     = '0.0.0.0/0',
				description = 'all outgoing protocols are allow',
			),
			dict(
				in_out      = 'IN',
				ip_protocol = 'TCP',
				from_port   = 20000,
				to_port     = 29999,
				group_name  = 'admin',
			),
		]
		ip_permission = dict(
			in_out      = 'IN',
			ip_protocol = 'TCP',
			from_port   = 10000,
			to_port     = 29999,
			group_name  = 'admin',
		)
		self.assertFalse(niftycloud_fw.contains_ip_permissions(ip_permissions, ip_permission))

	# contains_ip_permissions false case 5
	def test_contains_ip_permissions_false_case_5(self):
		ip_permissions = [
			dict(
				in_out      = 'OUT',
				ip_protocol = 'ANY',
				cidr_ip     = '0.0.0.0/0',
				description = 'all outgoing protocols are allow',
			),
			dict(
				in_out      = 'IN',
				ip_protocol = 'TCP',
				from_port   = 20000,
				to_port     = 29999,
				group_name  = 'admin',
			),
		]
		ip_permission = dict(
			in_out      = 'IN',
			ip_protocol = 'TCP',
			from_port   = 20000,
			to_port     = 30000,
			group_name  = 'admin',
		)
		self.assertFalse(niftycloud_fw.contains_ip_permissions(ip_permissions, ip_permission))

	# contains_ip_permissions false case 6
	def test_contains_ip_permissions_false_case_6(self):
		ip_permissions = [
			dict(
				in_out      = 'OUT',
				ip_protocol = 'ANY',
				cidr_ip     = '0.0.0.0/0',
				description = 'all outgoing protocols are allow',
			),
			dict(
				in_out      = 'IN',
				ip_protocol = 'TCP',
				from_port   = 20000,
				to_port     = 29999,
				group_name  = 'admin',
			),
		]
		ip_permission = dict(
			in_out      = 'IN',
			ip_protocol = 'TCP',
			from_port   = 20000,
			to_port     = 29999,
			group_name  = 'default',
		)
		self.assertFalse(niftycloud_fw.contains_ip_permissions(ip_permissions, ip_permission))

	# except_ip_permissions case 1
	def test_except_ip_permissions_case_1(self):
		ip_permissions_a = [
			dict(
				in_out      = 'OUT',
				ip_protocol = 'ANY',
				cidr_ip     = '0.0.0.0/0',
				description = 'all outgoing protocols are allow',
			),
			dict(
				in_out      = 'IN',
				ip_protocol = 'TCP',
				from_port   = 20000,
				to_port     = 29999,
				group_name  = 'admin',
			),
		]
		ip_permissions_b = []

		self.assertEqual(
			niftycloud_fw.except_ip_permissions(ip_permissions_a, ip_permissions_b),
			ip_permissions_a
		)

	# except_ip_permissions case 2
	def test_except_ip_permissions_case_2(self):
		ip_permissions_a = [
			dict(
				in_out      = 'OUT',
				ip_protocol = 'ANY',
				cidr_ip     = '0.0.0.0/0',
				description = 'all outgoing protocols are allow',
			),
			dict(
				in_out      = 'IN',
				ip_protocol = 'TCP',
				from_port   = 20000,
				to_port     = 29999,
				group_name  = 'admin',
			),
		]
		ip_permissions_b = ip_permissions_a

		self.assertEqual(
			niftycloud_fw.except_ip_permissions(ip_permissions_a, ip_permissions_b),
			[]
		)

	# except_ip_permissions case 3
	def test_except_ip_permissions_case_3(self):
		ip_permissions_a = [
			dict(
				in_out      = 'OUT',
				ip_protocol = 'ANY',
				cidr_ip     = '0.0.0.0/0',
				description = 'all outgoing protocols are allow',
			),
			dict(
				in_out      = 'IN',
				ip_protocol = 'TCP',
				from_port   = 20000,
				to_port     = 29999,
				group_name  = 'admin',
			),
		]
		ip_permissions_b = [
			dict(
				in_out      = 'OUT',
				ip_protocol = 'ANY',
				cidr_ip     = '0.0.0.0/0',
				description = 'all outgoing protocols are allow',
			),
		]

		self.assertEqual(
			niftycloud_fw.except_ip_permissions(ip_permissions_a, ip_permissions_b),
			[
				dict(
					in_out      = 'IN',
					ip_protocol = 'TCP',
					from_port   = 20000,
					to_port     = 29999,
					group_name  = 'admin',
				),
			]
		)

	# except_ip_permissions case 4
	def test_except_ip_permissions_case_4(self):
		ip_permissions_a = [
			dict(
				in_out      = 'OUT',
				ip_protocol = 'ANY',
				cidr_ip     = '0.0.0.0/0',
				description = 'all outgoing protocols are allow',
			),
		]
		ip_permissions_b = [
			dict(
				in_out      = 'OUT',
				ip_protocol = 'ANY',
				cidr_ip     = '0.0.0.0/0',
				description = 'all outgoing protocols are allow',
			),
			dict(
				in_out      = 'IN',
				ip_protocol = 'TCP',
				from_port   = 20000,
				to_port     = 29999,
				group_name  = 'admin',
			),
		]

		self.assertEqual(
			niftycloud_fw.except_ip_permissions(ip_permissions_a, ip_permissions_b),
			[]
		)

	# describe present
	def test_describe_security_group_present(self):
		with mock.patch('requests.get', self.mockRequestsGetDescribeSecurityGroups):
			(result, info) = niftycloud_fw.describe_security_group(self.mockModule, self.result['absent'])

		self.assertEqual(result, dict(
			created            = False,
			changed_attributes = dict(),
			state              = 'present',
		))
		self.assertIsInstance(info, dict)
		self.assertEqual(info['group_name'],  'fw001')
		self.assertIsInstance(info['description'], str)
		self.assertEqual(info['description'], 'sample fw')
		self.assertEqual(info['log_limit'],   100000)
		self.assertEqual(info['log_filters'], dict(
			net_bios  = True,
			broadcast = True,
		))
		self.assertEqual(info['ip_permissions'], [
			dict(
				ip_protocol = 'TCP',
				in_out      = 'IN',
				from_port   = 10000,
				to_port     = 10010,
				cidr_ip     = None,
				group_name  = 'fw002',
			),
			dict(
				ip_protocol = 'ANY',
				in_out      = 'OUT',
				from_port   = None,
				to_port     = None,
				cidr_ip     = '0.0.0.0/0',
				group_name  = None,
			),
		])

	# describe present description unicode
	def test_describe_security_group_description_unicode(self):
		with mock.patch('requests.get', self.mockRequestsGetDescribeSecurityGroupsDescriptionUnicode):
			(result, info) = niftycloud_fw.describe_security_group(self.mockModule, self.result['absent'])

		self.assertEqual(result, dict(
			created            = False,
			changed_attributes = dict(),
			state              = 'present',
		))
		self.assertIsInstance(info, dict)
		self.assertIsInstance(info['description'], str)
		self.assertEqual(info['description'], 'サンプルFW')

	# describe present description none
	def test_describe_security_group_description_none(self):
		with mock.patch('requests.get', self.mockRequestsGetDescribeSecurityGroupsDescriptionNone):
			(result, info) = niftycloud_fw.describe_security_group(self.mockModule, self.result['absent'])

		self.assertEqual(result, dict(
			created            = False,
			changed_attributes = dict(),
			state              = 'present',
		))
		self.assertIsInstance(info, dict)
		self.assertIsInstance(info['description'], str)
		self.assertEqual(info['description'], '')

	# describe processing
	def test_describe_security_group_processing(self):
		with mock.patch('requests.get', self.mockRequestsGetDescribeSecurityGroupsProcessing):
			(result, info) = niftycloud_fw.describe_security_group(self.mockModule, self.result['absent'])

		self.assertEqual(result, dict(
			created            = False,
			changed_attributes = dict(),
			state              = 'processing',
		))
		self.assertIsNone(info)

	# describe absent
	def test_describe_security_group_absent(self):
		with mock.patch('requests.get', self.mockRequestsGetDescribeSecurityGroupsNotFound):
			(result, info) = niftycloud_fw.describe_security_group(self.mockModule, self.result['absent'])

		self.assertEqual(result, dict(
			created            = False,
			changed_attributes = dict(),
			state              = 'absent',
		))
		self.assertIsNone(info)

	# describe failed
	def test_describe_security_group_failed(self):
		with mock.patch('requests.get', self.mockRequestsInternalServerError):
			(result, info) = niftycloud_fw.describe_security_group(self.mockModule, self.result['absent'])

		self.assertEqual(result, dict(
			created            = False,
			changed_attributes = dict(),
			state              = 'absent',
		))
		self.assertIsNone(info)

	# wait_for_processing success absent
	def test_wait_for_processing_success_absent(self):
		with mock.patch('niftycloud_fw.describe_security_group', self.mockNotFoundSecurityGroup):
			(result, info) = niftycloud_fw.wait_for_processing(self.mockModule, self.result['absent'], 'absent')

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# wait_for_processing success present
	def test_wait_for_processing_success_present(self):
		with mock.patch('niftycloud_fw.describe_security_group', self.mockDescribeSecurityGroup):
			(result, info) = niftycloud_fw.wait_for_processing(self.mockModule, self.result['absent'], 'present')

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info,   self.security_group_info)

	# wait_for_processing unmatch absent
	def test_wait_for_processing_failed_absent(self):
		with mock.patch('niftycloud_fw.describe_security_group', self.mockDescribeSecurityGroup):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_fw.wait_for_processing(self.mockModule, self.result['absent'], 'absent')

		self.assertEqual(cm.exception.message, 'failed')

	# wait_for_processing unmatch present
	def test_wait_for_processing_failed_present(self):
		with mock.patch('niftycloud_fw.describe_security_group', self.mockNotFoundSecurityGroup):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_fw.wait_for_processing(self.mockModule, self.result['absent'], 'present')

		self.assertEqual(cm.exception.message, 'failed')

	# create present  * do nothing
	def test_create_security_group_skip(self):
		(result, info) = niftycloud_fw.create_security_group(
			self.mockModule,
			self.result['present'],
			self.security_group_info
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info,   self.security_group_info)

	# create success
	def test_create_security_group_success(self):
		with mock.patch('requests.post', self.mockRequestsPostCreateSecurityGroup):
			with mock.patch('niftycloud_fw.describe_security_group', self.mockDescribeSecurityGroup):
				(result, info) = niftycloud_fw.create_security_group(
					self.mockModule,
					self.result['absent'],
					None
				)

		self.assertEqual(result, dict(
			created            = True,
			changed_attributes = dict(),
			state              = 'present',
		))
		self.assertEqual(info, self.security_group_info)

	# create failed
	def test_create_security_group_failed(self):
		with mock.patch('requests.post', self.mockRequestsPostCreateSecurityGroup):
			with mock.patch('niftycloud_fw.describe_security_group', self.mockNotFoundSecurityGroup):
				with self.assertRaises(Exception) as cm:
					niftycloud_fw.create_security_group(
						self.mockModule,
						self.result['absent'],
						None
					)
		self.assertEqual(cm.exception.message, 'failed')

	# create request failed
	def test_create_security_group_request_failed(self):
		with mock.patch('requests.post', self.mockRequestsInternalServerError):
			with self.assertRaises(Exception) as cm:
				niftycloud_fw.create_security_group(
					self.mockModule,
					self.result['absent'],
					None
				)
		self.assertEqual(cm.exception.message, 'failed')

	# update api success
	def test_update_security_group_attribute_success(self):
		params = dict(
			GroupName              = self.mockModule.params['group_name'],
			GroupDescriptionUpdate = self.mockModule.params['description'],
		)

		with mock.patch('requests.post', self.mockRequestsPostUpdateSecurityGroup):
			with mock.patch('niftycloud_fw.describe_security_group', self.mockDescribeSecurityGroup):
				(result, info) = niftycloud_fw.update_security_group_attribute(
					self.mockModule,
					self.result['present'],
					self.security_group_info,
					params
				)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, self.security_group_info)

	# update api absent  * do nothing
	def test_update_security_group_attribute_absent(self):
		params = dict(
			GroupName              = self.mockModule.params['group_name'],
			GroupDescriptionUpdate = self.mockModule.params['description'],
		)

		(result, info) = niftycloud_fw.update_security_group_attribute(
			self.mockModule,
			self.result['absent'],
			None,
			params
		)

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# update api failed
	def test_update_security_group_attribute_failed(self):
		params = dict(
			GroupName              = self.mockModule.params['group_name'],
			GroupDescriptionUpdate = self.mockModule.params['description'],
		)

		with mock.patch('requests.post', self.mockRequestsPostUpdateSecurityGroup):
			with mock.patch('niftycloud_fw.describe_security_group', self.mockNotFoundSecurityGroup):
				with self.assertRaises(Exception) as cm:
					(result, info) = niftycloud_fw.update_security_group_attribute(
						self.mockModule,
						self.result['present'],
						self.security_group_info,
						params
					)
		self.assertEqual(cm.exception.message, 'failed')

	# update api request failed
	def test_update_security_group_attribute_request_failed(self):
		params = dict(
			GroupName              = self.mockModule.params['group_name'],
			GroupDescriptionUpdate = self.mockModule.params['description'],
		)

		with mock.patch('requests.post', self.mockRequestsInternalServerError):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_fw.update_security_group_attribute(
					self.mockModule,
					self.result['present'],
					self.security_group_info,
					params
				)
		self.assertEqual(cm.exception.message, 'failed')

	# update description success
	def test_update_security_group_description_success(self):
		changed_security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			description = self.mockModule.params['description'],
		)
		mock_describe_security_group = mock.MagicMock(
			return_value=(
				self.result['present'],
				changed_security_group_info,
			))

		with mock.patch('niftycloud_fw.update_security_group_attribute', mock_describe_security_group):
			(result, info) = niftycloud_fw.update_security_group_description(
				self.mockModule,
				self.result['present'],
				self.security_group_info
			)

		self.assertEqual(result, dict(
			created = False,
			changed_attributes = dict(
				description = self.mockModule.params['description'],
			),
			state = 'present',
		))
		self.assertEqual(info, changed_security_group_info)

	# update description absent  * do nothing
	def test_update_security_group_description_absent(self):
		(result, info) = niftycloud_fw.update_security_group_description(
			self.mockModule,
			self.result['absent'],
			None
		)

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# update description is None  * do nothing
	def test_update_security_group_description_none(self):
		security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			description = self.mockModule.params['description'],
		)
                mock_module = mock.MagicMock(
                        params = dict(
				copy.deepcopy(self.mockModule.params),
				description = None,
			)
                )

		(result, info) = niftycloud_fw.update_security_group_description(
			mock_module,
			self.result['present'],
			security_group_info
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, security_group_info)

	# update description is no change  * do nothing
	def test_update_security_group_description_skip(self):
		changed_security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			description = self.mockModule.params['description'],
		)

		(result, info) = niftycloud_fw.update_security_group_description(
			self.mockModule,
			self.result['present'],
			changed_security_group_info
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, changed_security_group_info)

	# update description failed
	def test_update_security_group_description_failed(self):
		with mock.patch('niftycloud_fw.update_security_group_attribute', self.mockDescribeSecurityGroup):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_fw.update_security_group_description(
					self.mockModule,
					self.result['present'],
					self.security_group_info
				)
		self.assertEqual(cm.exception.message, 'failed')

	# update log_limit success
	def test_update_security_group_log_limit_success(self):
		changed_security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			log_limit = self.mockModule.params['log_limit'],
		)
		mock_describe_security_group = mock.MagicMock(
			return_value=(
				self.result['present'],
				changed_security_group_info,
			))

		with mock.patch('niftycloud_fw.update_security_group_attribute', mock_describe_security_group):
			(result, info) = niftycloud_fw.update_security_group_log_limit(
				self.mockModule,
				self.result['present'],
				self.security_group_info
			)

		self.assertEqual(result, dict(
			created = False,
			changed_attributes = dict(
				log_limit = self.mockModule.params['log_limit'],
			),
			state = 'present',
		))
		self.assertEqual(info, changed_security_group_info)

	# update log_limit absent  * do nothing
	def test_update_security_group_log_limit_absent(self):
		(result, info) = niftycloud_fw.update_security_group_log_limit(
			self.mockModule,
			self.result['absent'],
			None
		)

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# update log_limit is None  * do nothing
	def test_update_security_group_log_limit_none(self):
		security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			log_limit = self.mockModule.params['description'],
		)
                mock_module = mock.MagicMock(
                        params = dict(
				copy.deepcopy(self.mockModule.params),
				log_limit = None,
			)
                )

		(result, info) = niftycloud_fw.update_security_group_log_limit(
			mock_module,
			self.result['present'],
			security_group_info
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, security_group_info)

	# update log_limit is no change  * do nothing
	def test_update_security_group_log_limit_skip(self):
		changed_security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			log_limit = self.mockModule.params['log_limit'],
		)

		(result, info) = niftycloud_fw.update_security_group_log_limit(
			self.mockModule,
			self.result['present'],
			changed_security_group_info
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, changed_security_group_info)

	# update log_limit failed
	def test_update_security_group_log_limit_failed(self):
		with mock.patch('niftycloud_fw.update_security_group_attribute', self.mockDescribeSecurityGroup):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_fw.update_security_group_log_limit(
					self.mockModule,
					self.result['present'],
					self.security_group_info
				)
		self.assertEqual(cm.exception.message, 'failed')

	# update log_filter net_bios success
	def test_update_security_group_log_filter_net_bios_success(self):
		changed_security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			log_filters = dict(
				copy.deepcopy(self.security_group_info['log_filters']),
				net_bios = self.mockModule.params['log_filters']['net_bios'],
			),
		)
		mock_describe_security_group = mock.MagicMock(
			return_value=(
				self.result['present'],
				changed_security_group_info,
			))

		with mock.patch('niftycloud_fw.update_security_group_attribute', mock_describe_security_group):
			(result, info) = niftycloud_fw.update_security_group_log_filter_net_bios(
				self.mockModule,
				self.result['present'],
				self.security_group_info
			)

		self.assertEqual(result, dict(
			created = False,
			changed_attributes = dict(
				log_filter_net_bios = self.mockModule.params['log_filters']['net_bios'],
			),
			state = 'present',
		))
		self.assertEqual(info, changed_security_group_info)

	# update log_filter net_bios absent
	def test_update_security_group_log_filter_net_bios_absent(self):
		(result, info) = niftycloud_fw.update_security_group_log_filter_net_bios(
			self.mockModule,
			self.result['absent'],
			None
		)

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# update log_filter net_bios is None  * do nothing
	def test_update_security_group_log_filter_net_bios_none(self):
		security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			log_filters = dict(
				copy.deepcopy(self.security_group_info['log_filters']),
				net_bios = self.mockModule.params['log_filters']['net_bios'],
			),
		)
                mock_module = mock.MagicMock(
                        params = dict(
				copy.deepcopy(self.mockModule.params),
				log_filters = dict(
					copy.deepcopy(self.mockModule.params['log_filters']),
					net_bios = None,
				),
			)
                )

		(result, info) = niftycloud_fw.update_security_group_log_filter_net_bios(
			mock_module,
			self.result['present'],
			security_group_info
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, security_group_info)

	# update log_filter net_bios is no change  * do nothing
	def test_update_security_group_log_filter_net_bios_skip(self):
		changed_security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			log_filters = dict(
				copy.deepcopy(self.security_group_info['log_filters']),
				net_bios = self.mockModule.params['log_filters']['net_bios'],
			),
		)

		(result, info) = niftycloud_fw.update_security_group_log_filter_net_bios(
			self.mockModule,
			self.result['present'],
			changed_security_group_info
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, changed_security_group_info)

	# update log_filter net_bios failed
	def test_update_security_group_log_filter_net_bios_failed(self):
		with mock.patch('niftycloud_fw.update_security_group_attribute', self.mockDescribeSecurityGroup):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_fw.update_security_group_log_filter_net_bios(
					self.mockModule,
					self.result['present'],
					self.security_group_info
				)
		self.assertEqual(cm.exception.message, 'failed')

	# update log_filter broadcast success
	def test_update_security_group_log_filter_broadcast_success(self):
		changed_security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			log_filters = dict(
				copy.deepcopy(self.security_group_info['log_filters']),
				broadcast = self.mockModule.params['log_filters']['broadcast'],
			),
		)
		mock_describe_security_group = mock.MagicMock(
			return_value=(
				self.result['present'],
				changed_security_group_info,
			))

		with mock.patch('niftycloud_fw.update_security_group_attribute', mock_describe_security_group):
			(result, info) = niftycloud_fw.update_security_group_log_filter_broadcast(
				self.mockModule,
				self.result['present'],
				self.security_group_info
			)

		self.assertEqual(result, dict(
			created = False,
			changed_attributes = dict(
				log_filter_broadcast = self.mockModule.params['log_filters']['broadcast'],
			),
			state = 'present',
		))
		self.assertEqual(info, changed_security_group_info)

	# update log_filter broadcast absent
	def test_update_security_group_log_filter_broadcast_absent(self):
		(result, info) = niftycloud_fw.update_security_group_log_filter_broadcast(
			self.mockModule,
			self.result['absent'],
			None
		)

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# update log_filter broadcast is None  * do nothing
	def test_update_security_group_log_filter_broadcast_none(self):
		security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			log_filters = dict(
				copy.deepcopy(self.security_group_info['log_filters']),
				broadcast = self.mockModule.params['log_filters']['broadcast'],
			),
		)
                mock_module = mock.MagicMock(
                        params = dict(
				copy.deepcopy(self.mockModule.params),
				log_filters = dict(
					copy.deepcopy(self.mockModule.params['log_filters']),
					broadcast = None,
				),
			)
                )

		(result, info) = niftycloud_fw.update_security_group_log_filter_broadcast(
			mock_module,
			self.result['present'],
			security_group_info
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, security_group_info)

	# update log_filter broadcast is no change  * do nothing
	def test_update_security_group_log_filter_broadcast_skip(self):
		changed_security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			log_filters = dict(
				copy.deepcopy(self.security_group_info['log_filters']),
				broadcast = self.mockModule.params['log_filters']['broadcast'],
			),
		)

		(result, info) = niftycloud_fw.update_security_group_log_filter_broadcast(
			self.mockModule,
			self.result['present'],
			changed_security_group_info
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, changed_security_group_info)

	# update log_filter broadcast failed
	def test_update_security_group_log_filter_broadcast_failed(self):
		with mock.patch('niftycloud_fw.update_security_group_attribute', self.mockDescribeSecurityGroup):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_fw.update_security_group_log_filter_broadcast(
					self.mockModule,
					self.result['present'],
					self.security_group_info
				)
		self.assertEqual(cm.exception.message, 'failed')

	# update
	def test_update_security_group(self):
		with mock.patch('niftycloud_fw.update_security_group_description', self.mockDescribeSecurityGroup):
			with mock.patch('niftycloud_fw.update_security_group_log_limit', self.mockDescribeSecurityGroup):
				with mock.patch('niftycloud_fw.update_security_group_log_filter_net_bios', self.mockDescribeSecurityGroup):
					with mock.patch('niftycloud_fw.update_security_group_log_filter_broadcast', self.mockDescribeSecurityGroup):
						(result, info) = niftycloud_fw.update_security_group(
							self.mockModule,
							self.result['present'],
							self.security_group_info
						)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, self.security_group_info)

	# update absent  * do nothing
	def test_update_security_group_absent(self):
		(result, info) = niftycloud_fw.update_security_group(
			self.mockModule,
			self.result['absent'],
			None
		)

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# authorize success
	def test_authorize_security_group_success(self):
		changed_security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			ip_permissions = list(
				self.security_group_info['ip_permissions'] + self.mockModule.params['ip_permissions'],
			)
		)
		mock_describe_security_group = mock.MagicMock(
			return_value=(
				self.result['present'],
				changed_security_group_info,
			))

		with mock.patch('requests.post', self.mockRequestsPostAuthorizeSecurityGroup):
			with mock.patch('niftycloud_fw.describe_security_group', mock_describe_security_group):
				(result, info) = niftycloud_fw.authorize_security_group(
					self.mockModule,
					self.result['present'],
					self.security_group_info
				)

		self.assertEqual(result, dict(
			created = False,
			changed_attributes = dict(
				number_of_authorize_rules = len(self.mockModule.params['ip_permissions']),
			),
			state = 'present',
		))
		self.assertEqual(info, changed_security_group_info)

	# authorize ip_permissions are no change  * do nothing
	def test_authorize_security_group_skip(self):
		changed_security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			ip_permissions = self.mockModule.params['ip_permissions'],
		)

		(result, info) = niftycloud_fw.authorize_security_group(
			self.mockModule,
			self.result['present'],
			changed_security_group_info
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, changed_security_group_info)

	# authorize absent  * do nothing
	def test_authorize_security_group_absent(self):
		(result, info) = niftycloud_fw.authorize_security_group(
			self.mockModule,
			self.result['absent'],
			None
		)

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# authorize failed
	def test_authorize_security_group_failed(self):
		with mock.patch('requests.post', self.mockRequestsPostAuthorizeSecurityGroup):
			with mock.patch('niftycloud_fw.describe_security_group', self.mockDescribeSecurityGroup):
				with self.assertRaises(Exception) as cm:
					niftycloud_fw.authorize_security_group(
						self.mockModule,
						self.result['present'],
						self.security_group_info
					)
		self.assertEqual(cm.exception.message, 'failed')

	# authorize request failed
	def test_authorize_security_group_request_failed(self):
		with mock.patch('requests.post', self.mockRequestsInternalServerError):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_fw.authorize_security_group(
					self.mockModule,
					self.result['present'],
					self.security_group_info
				)
		self.assertEqual(cm.exception.message, 'failed')

	# revoke success
	def test_revoke_security_group_success(self):
		security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			ip_permissions = list(
				self.security_group_info['ip_permissions'] + self.mockModule.params['ip_permissions'],
			),
		)
		changed_security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			ip_permissions = self.mockModule.params['ip_permissions'],
		)
		mock_describe_security_group = mock.MagicMock(
			return_value=(
				self.result['present'],
				changed_security_group_info,
			))

		with mock.patch('requests.post', self.mockRequestsPostRevokeSecurityGroup):
			with mock.patch('niftycloud_fw.describe_security_group', mock_describe_security_group):
				(result, info) = niftycloud_fw.revoke_security_group(
					self.mockModule,
					self.result['present'],
					security_group_info
				)

		self.assertEqual(result, dict(
			created = False,
			changed_attributes = dict(
				number_of_revoke_rules = len(self.security_group_info['ip_permissions']),
			),
			state = 'present',
		))
		self.assertEqual(info, changed_security_group_info)

	# revoke ip_permissions are no change  * do nothing
	def test_revoke_security_group_skip(self):
		security_group_info = dict(
			copy.deepcopy(self.security_group_info),
			ip_permissions = self.mockModule.params['ip_permissions'],
		)

		(result, info) = niftycloud_fw.revoke_security_group(
			self.mockModule,
			self.result['present'],
			security_group_info
		)

		self.assertEqual(result, self.result['present'])
		self.assertEqual(info, security_group_info)

	# revoke absent  * do nothing
	def test_revoke_security_group_absent(self):
		(result, info) = niftycloud_fw.revoke_security_group(
			self.mockModule,
			self.result['absent'],
			None
		)

		self.assertEqual(result, self.result['absent'])
		self.assertIsNone(info)

	# revoke failed
	def test_revoke_security_group_failed(self):
		with mock.patch('requests.post', self.mockRequestsPostRevokeSecurityGroup):
			with mock.patch('niftycloud_fw.describe_security_group', self.mockDescribeSecurityGroup):
				with self.assertRaises(Exception) as cm:
					niftycloud_fw.revoke_security_group(
						self.mockModule,
						self.result['present'],
						self.security_group_info
					)
		self.assertEqual(cm.exception.message, 'failed')

	# revoke request failed
	def test_revoke_security_group_request_failed(self):
		with mock.patch('requests.post', self.mockRequestsInternalServerError):
			with self.assertRaises(Exception) as cm:
				(result, info) = niftycloud_fw.revoke_security_group(
					self.mockModule,
					self.result['present'],
					self.security_group_info
				)
		self.assertEqual(cm.exception.message, 'failed')

	# run success (absent - create -> present - other action -> present)
	def test_run_success_absent(self):
		with mock.patch('niftycloud_fw.describe_security_group', self.mockNotFoundSecurityGroup):
			with mock.patch('niftycloud_fw.create_security_group', self.mockDescribeSecurityGroup):
				with mock.patch('niftycloud_fw.update_security_group', self.mockDescribeSecurityGroup):
					with mock.patch('niftycloud_fw.authorize_security_group', self.mockDescribeSecurityGroup):
						with mock.patch('niftycloud_fw.revoke_security_group', self.mockDescribeSecurityGroup):
							with self.assertRaises(Exception) as cm:
								niftycloud_fw.run(self.mockModule)
		self.assertEqual(cm.exception.message, 'success')

	# run success (present - create skip -> present - other action -> present)
	def test_run_success_present(self):
		with mock.patch('niftycloud_fw.describe_security_group', self.mockDescribeSecurityGroup):
			with mock.patch('niftycloud_fw.update_security_group', self.mockDescribeSecurityGroup):
				with mock.patch('niftycloud_fw.authorize_security_group', self.mockDescribeSecurityGroup):
					with mock.patch('niftycloud_fw.revoke_security_group', self.mockDescribeSecurityGroup):
						with self.assertRaises(Exception) as cm:
								niftycloud_fw.run(self.mockModule)
		self.assertEqual(cm.exception.message, 'success')

	# run failed (absent - create -> absent - skip other action -> absent)
	def test_run_failed(self):
		with mock.patch('niftycloud_fw.describe_security_group', self.mockNotFoundSecurityGroup):
			with mock.patch('niftycloud_fw.create_security_group', self.mockNotFoundSecurityGroup):
				with self.assertRaises(Exception) as cm:
					niftycloud_fw.run(self.mockModule)
		self.assertEqual(cm.exception.message, 'failed')

niftycloud_api_response_sample = dict(
	describeSecurityGroups = '''
<DescribeSecurityGroupsResponse xmlns="https://cp.cloud.nifty.com/api/">
 <RequestID>5ec8da0a-6e23-4343-b474-ca0bb5c22a51</RequestID>
 <securityGroupInfo>
  <item>
   <ownerId></ownerId>
   <groupName>fw001</groupName>
   <groupDescription>sample fw</groupDescription>
   <groupStatus>applied</groupStatus>
   <ipPermissions>
    <item>
     <ipProtocol>TCP</ipProtocol>
     <fromPort>10000</fromPort>
     <toPort>10010</toPort>
     <inOut>IN</inOut>
     <groups>
      <item>
       <groupName>fw002</groupName>
      </item>
     </groups>
     <description>TCP (10000 - 10010)</description>
     <addDatetime>2001-02-03T04:05:06.007Z</addDatetime>
    </item>
    <item>
     <ipProtocol>ANY</ipProtocol>
     <inOut>OUT</inOut>
     <ipRanges>
      <item>
       <cidrIp>0.0.0.0/0</cidrIp>
      </item>
     </ipRanges>
     <description>ANY</description>
     <addDatetime>2001-02-03T04:05:06.007Z</addDatetime>
    </item>
   </ipPermissions>
   <instancesSet>
    <item>
     <instanceId>sv001</instanceId>
    </item>
    <item>
     <instanceId>sv002</instanceId>
    </item>
   </instancesSet>
   <instanceUniqueIdsSet>
    <item>
     <instanceUniqueId>i-0a1b2c01</instanceUniqueId>
    </item>
    <item>
     <instanceUniqueId>i-0a1b2c02</instanceUniqueId>
    </item>
   </instanceUniqueIdsSet>
   <groupRuleLimit>100</groupRuleLimit>
   <groupLogLimit>100000</groupLogLimit>
   <groupLogFilterNetBios>true</groupLogFilterNetBios>
   <groupLogFilterBroadcast>true</groupLogFilterBroadcast>
   <availabilityZone>west-12</availabilityZone>
  </item>
 </securityGroupInfo>
</DescribeSecurityGroupsResponse>
''',
	describeSecurityGroupsDescriptionUnicode = u'''
<DescribeSecurityGroupsResponse xmlns="https://cp.cloud.nifty.com/api/">
 <RequestID>5ec8da0a-6e23-4343-b474-ca0bb5c22a51</RequestID>
 <securityGroupInfo>
  <item>
   <ownerId></ownerId>
   <groupName>fw002</groupName>
   <groupDescription>サンプルFW</groupDescription>
   <groupStatus>applied</groupStatus>
   <ipPermissions />
   <instancesSet />
   <instanceUniqueIdsSet />
   <groupRuleLimit>100</groupRuleLimit>
   <groupLogLimit>1000</groupLogLimit>
   <groupLogFilterNetBios>false</groupLogFilterNetBios>
   <groupLogFilterBroadcast>false</groupLogFilterBroadcast>
   <availabilityZone>west-12</availabilityZone>
  </item>
 </securityGroupInfo>
</DescribeSecurityGroupsResponse>
''',
	describeSecurityGroupsDescriptionNone = '''
<DescribeSecurityGroupsResponse xmlns="https://cp.cloud.nifty.com/api/">
 <RequestID>5ec8da0a-6e23-4343-b474-ca0bb5c22a51</RequestID>
 <securityGroupInfo>
  <item>
   <ownerId></ownerId>
   <groupName>fw002</groupName>
   <groupStatus>applied</groupStatus>
   <ipPermissions />
   <instancesSet />
   <instanceUniqueIdsSet />
   <groupRuleLimit>100</groupRuleLimit>
   <groupLogLimit>1000</groupLogLimit>
   <groupLogFilterNetBios>false</groupLogFilterNetBios>
   <groupLogFilterBroadcast>false</groupLogFilterBroadcast>
   <availabilityZone>west-12</availabilityZone>
  </item>
 </securityGroupInfo>
</DescribeSecurityGroupsResponse>
''',
	describeSecurityGroupsProcessing = '''
<DescribeSecurityGroupsResponse xmlns="https://cp.cloud.nifty.com/api/">
 <RequestID>5ec8da0a-6e23-4343-b474-ca0bb5c22a51</RequestID>
 <securityGroupInfo>
  <item>
   <ownerId></ownerId>
   <groupName>fw002</groupName>
   <groupDescription>Case No. 002</groupDescription>
   <groupStatus>processing</groupStatus>
   <ipPermissions />
   <instancesSet />
   <instanceUniqueIdsSet />
   <groupRuleLimit>100</groupRuleLimit>
   <groupLogLimit>1000</groupLogLimit>
   <groupLogFilterNetBios>false</groupLogFilterNetBios>
   <groupLogFilterBroadcast>false</groupLogFilterBroadcast>
   <availabilityZone>west-12</availabilityZone>
  </item>
 </securityGroupInfo>
</DescribeSecurityGroupsResponse>
''',
	describeSecurityGroupsNotFound = '''
<DescribeSecurityGroupsResponse xmlns="https://cp.cloud.nifty.com/api/">
 <RequestID>5ec8da0a-6e23-4343-b474-ca0bb5c22a51</RequestID>
 <securityGroupInfo />
</DescribeSecurityGroupsResponse>
''',
	createSecurityGroup = '''
<CreateSecurityGroupResponse xmlns="https://cp.cloud.nifty.com/api/">
 <requestId>320fc738-a1c7-4a2f-abcb-20813a4e997c</requestId>
 <return>true</return>
</CreateSecurityGroupResponse>
''',
	updateSecurityGroup = '''
<UpdateSecurityGroupResponse xmlns="https://cp.cloud.nifty.com/api/">
 <requestId>320fc738-a1c7-4a2f-abcb-20813a4e997c</requestId>
 <return>true</return>
</UpdateSecurityGroupResponse>
''',
	authorizeSecurityGroup = '''
<AuthorizeSecurityGroupIngressResponse xmlns="https://cp.cloud.nifty.com/api/">
 <requestId>320fc738-a1c7-4a2f-abcb-20813a4e997c</requestId>
 <return>true</return>
</AuthorizeSecurityGroupIngressResponse>
''',
	revokeSecurityGroup = '''
<RevokeSecurityGroupIngressResponse xmlns="https://cp.cloud.nifty.com/api/">
 <requestId>320fc738-a1c7-4a2f-abcb-20813a4e997c</requestId>
 <return>true</return>
</RevokeSecurityGroupIngressResponse>
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
