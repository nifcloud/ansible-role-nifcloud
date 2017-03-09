import os
import sys
sys.path.append('.')
sys.path.append('..')

import unittest
import mock
import niftycloud_fw
import xml.etree.ElementTree as etree

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
			ip_permissions = [],
		)

		self.mockRequestsGetDescribeSecurityGroups = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['describeSecurityGroups']
			))

		self.mockRequestsGetDescribeSecurityGroupsProcessing = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['describeSecurityGroupsProcessing']
			))

		self.mockRequestsPostCreateSecurityGroup = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['createSecurityGroup']
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
	createSecurityGroup = '''
<CreateSecurityGroupResponse xmlns="https://cp.cloud.nifty.com/api/">	
 <requestId>320fc738-a1c7-4a2f-abcb-20813a4e997c</requestId>
 <return>true</return>
</CreateSecurityGroupResponse>
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
