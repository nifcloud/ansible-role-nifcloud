import os
import sys
sys.path.append('.')
sys.path.append('..')

import unittest
import mock
import niftycloud
import xml.etree.ElementTree as etree

class TestNiftycloud(unittest.TestCase):
	def setUp(self):
		self.mockModule = mock.MagicMock(
			params = dict(
				access_key = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
				secret_access_key = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
				endpoint   = 'west-1.cp.cloud.nifty.com',
				instance_id = 'test001',
				state = 'running',
				image_id = '26',
				key_name = 'sshkey',
				security_group = 'appprifw001',
				instance_type = 'mini',
				availability_zone = 'west-11',
				accounting_type = '2',
				ip_type = 'static',
				public_ip = None,
				startup_script = '{0}/files/startup_script'.format(os.path.dirname(__file__)),
				startup_script_vars = dict(debug_var = 'DEBUG'),
			        network_interface = [dict(network_id='net-COMMON_GLOBAL', ipAddress='0.0.0.0'), dict(network_id='net-COMMON_PRIVATE', ipAddress='static')]
			),
			fail_json = mock.MagicMock(side_effect=Exception('failed'))
		)

		self.xmlnamespace = 'https://cp.cloud.nifty.com/api/'
		self.xml = niftycloud_api_response_sample

		self.mockRequestsGetDescribeInstance  = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['describeInstance']
			))

		self.mockRequestsGetStopInstance  = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['stopInstance']
			))

		self.mockRequestsPostRunInstance = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['runInstance']
			))

		self.mockRequestsPostStartInstance = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['startInstance']
			))

		self.mockRequestsInternalServerError = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 500,
				text = self.xml['internalServerError']
			))

		self.mockGetInstanceStateError = mock.MagicMock(return_value=-1)
		self.mockGetInstanceState16 = mock.MagicMock(return_value=16)
		self.mockGetInstanceState80 = mock.MagicMock(return_value=80)

		self.mockStopInstance  = mock.MagicMock(return_value=(True, 80, 'stopped'))
		self.mockStartInstance = mock.MagicMock(return_value=(True, 16, 'running'))

		self.mockRequestsError = mock.MagicMock(return_value=None)

		patcher = mock.patch('time.sleep')
		self.addCleanup(patcher.stop)
		self.mock_time_sleep = patcher.start()
			
	# calculate signature
	def test_calculate_signature(self):
		secret_access_key = self.mockModule.params['secret_access_key']
		method = 'GET'
		endpoint = self.mockModule.params['endpoint']
		path = '/api/'
		params = dict(
			Action = 'DescribeInstances',
			AccessKeyId = self.mockModule.params['access_key'],
			SignatureMethod = 'HmacSHA256',
			SignatureVersion = '2',
			InstanceId = self.mockModule.params['instance_id']
		)

		signature = niftycloud.calculate_signature(secret_access_key, method, endpoint, path, params)
		self.assertEqual(signature, 'Y7/0nc3dCK9UNkp+w5sh08ybJLQjh69mXOgcxJijDEU=')

	# method get
	def test_request_to_api_get(self):
		method = 'GET'
		action = 'DescribeInstances'
		params = dict(
			ImageId = self.mockModule.params['image_id'],
			KeyName = self.mockModule.params['key_name'],
			InstanceId = self.mockModule.params['instance_id']
		)

		with mock.patch('requests.get', self.mockRequestsGetDescribeInstance):
			info = niftycloud.request_to_api(self.mockModule, method, action, params)

		self.assertEqual(info['status'], 200)
		self.assertEqual(info['xml_namespace'], dict(nc = self.xmlnamespace))
		self.assertEqual(etree.tostring(info['xml_body']),
				 etree.tostring(etree.fromstring(self.xml['describeInstance'])))

	# method post
	def test_request_to_api_post(self):
		method = 'POST'
		action = 'RunInstances'
		params = dict(
			ImageId = self.mockModule.params['image_id'],
			KeyName = self.mockModule.params['key_name'],
			InstanceId = self.mockModule.params['instance_id']
		)

		with mock.patch('requests.post', self.mockRequestsPostRunInstance):
			info = niftycloud.request_to_api(self.mockModule, method, action, params)

		self.assertEqual(info['status'], 200)
		self.assertEqual(info['xml_namespace'], dict(nc = self.xmlnamespace))
		self.assertEqual(etree.tostring(info['xml_body']),
				 etree.tostring(etree.fromstring(self.xml['runInstance'])))

	# api error
	def test_request_to_api_error(self):
		method = 'GET'
		action = 'DescribeInstances'
		params = dict(
			ImageId = self.mockModule.params['image_id'],
			KeyName = self.mockModule.params['key_name'],
			InstanceId = self.mockModule.params['instance_id']
		)

		with mock.patch('requests.get', self.mockRequestsInternalServerError):
			info = niftycloud.request_to_api(self.mockModule, method, action, params)

		self.assertEqual(info['status'], 500)
		self.assertEqual(etree.tostring(info['xml_body']),
				 etree.tostring(etree.fromstring(self.xml['internalServerError'])))

	# method failed
	def test_request_to_api_unknown(self):
		method = 'UNKNOWN'
		action = 'DescribeInstances'
		params = dict(
			ImageId = self.mockModule.params['image_id'],
			KeyName = self.mockModule.params['key_name'],
			InstanceId = self.mockModule.params['instance_id']
		)

		self.assertRaises(
			Exception,
			niftycloud.request_to_api,
			(self.mockModule, method, action, params)
		)

	# network error
	def test_request_to_api_request_error(self):
		method = 'GET'
		action = 'DescribeInstances'
		params = dict(
			ImageId = self.mockModule.params['image_id'],
			KeyName = self.mockModule.params['key_name'],
			InstanceId = self.mockModule.params['instance_id']
		)

		with mock.patch('requests.get', self.mockRequestsError):
			self.assertRaises(
				Exception,
				niftycloud.request_to_api,
				(self.mockModule, method, action, params)
			)

	# get api error code & message
	def test_get_api_error(self):
		method = 'GET'
		action = 'DescribeInstances'
		params = dict(
			ImageId = self.mockModule.params['image_id'],
			KeyName = self.mockModule.params['key_name'],
			InstanceId = self.mockModule.params['instance_id']
		)

		with mock.patch('requests.get', self.mockRequestsInternalServerError):
			info = niftycloud.request_to_api(self.mockModule, method, action, params)

		error_info = niftycloud.get_api_error(info['xml_body'])
		self.assertEqual(error_info['code'],    'Server.InternalError')
		self.assertEqual(error_info['message'], 'An error has occurred. Please try again later.')

	# running
	def test_get_instance_state_present(self):
		with mock.patch('requests.get', self.mockRequestsGetDescribeInstance):
			self.assertEqual(16, niftycloud.get_instance_state(self.mockModule))

	# not found
	def test_get_instance_state_absent(self):
		with mock.patch('requests.get', self.mockRequestsInternalServerError):
			self.assertEqual(-1, niftycloud.get_instance_state(self.mockModule))

	# create success
	def test_create_instance_success(self):
		with mock.patch('requests.post', self.mockRequestsPostRunInstance):
			with mock.patch('niftycloud.get_instance_state', self.mockGetInstanceState16):
				self.assertEqual(
					(True, 16, 'created'),
					niftycloud.create_instance(self.mockModule)
				)

	# change state failed
	def test_create_instance_failed(self):
		with mock.patch('requests.post', self.mockRequestsPostRunInstance):
			with mock.patch('niftycloud.get_instance_state', self.mockGetInstanceStateError):
				self.assertRaises(
					Exception,
					niftycloud.create_instance,
					(self.mockModule)
				)

	# internal server error
	def test_create_instance_error(self):
		with mock.patch('requests.post', self.mockRequestsInternalServerError):
			self.assertRaises(
				Exception,
				niftycloud.create_instance,
				(self.mockModule)
			)

	# running(16) -> running(16)  * do nothing
	def test_start_instance_running(self):
		self.assertEqual(
			(False, 16, 'running'),
			niftycloud.start_instance(self.mockModule, 16)
		)

	# absent(-1) -> created(16)
	def test_start_instance_absent(self):
		with mock.patch('requests.post', self.mockRequestsPostRunInstance):
			with mock.patch('niftycloud.get_instance_state', self.mockGetInstanceState16):
				self.assertEqual(
					(True, 16, 'created'),
					niftycloud.start_instance(self.mockModule, -1)
				)

	# stopped(80) -> running(16)
	def test_start_instance_stopped_success(self):
		with mock.patch('requests.post', self.mockRequestsPostStartInstance):
			with mock.patch('niftycloud.get_instance_state', self.mockGetInstanceState16):
				self.assertEqual(
					(True, 16, 'running'),
					niftycloud.start_instance(self.mockModule, 80)
				)

	# change state failed
	def test_start_instance_failed(self):
		with mock.patch('requests.post', self.mockRequestsPostStartInstance):
			with mock.patch('niftycloud.get_instance_state', self.mockGetInstanceState80):
				self.assertRaises(
					Exception,
					niftycloud.start_instance,
					(self.mockModule, 80)
				)

	# internal server error
	def test_start_instance_error(self):
		with mock.patch('requests.post', self.mockRequestsInternalServerError):
			self.assertRaises(
				Exception,
				niftycloud.start_instance,
				(self.mockModule, 80)
			)

	# stopped(80) -> stopped(80)  * do nothing
	def test_stop_instance_stopped(self):
		self.assertEqual(
			(False, 80, 'stopped'),
			niftycloud.stop_instance(self.mockModule, 80)
		)

	# absent(-1)
	def test_stop_instance_absent(self):
		self.assertRaises(
			Exception,
			niftycloud.stop_instance,
			(self.mockModule, -1)
		)

	# running(16) -> stopped(80)
	def test_stop_instance_running(self):
		with mock.patch('requests.get', self.mockRequestsGetStopInstance):
			with mock.patch('niftycloud.get_instance_state', self.mockGetInstanceState80):
				self.assertEqual(
					(True, 80, 'stopped'),
					niftycloud.stop_instance(self.mockModule, 16)
				)

	# change state failed
	def test_stop_instance_failed(self):
		with mock.patch('requests.get', self.mockRequestsGetStopInstance):
			with mock.patch('niftycloud.get_instance_state', self.mockGetInstanceState16):
				self.assertRaises(
					Exception,
					niftycloud.stop_instance,
					(self.mockModule, 16)
				)

	# internal server error
	def test_stop_instance_error(self):
		with mock.patch('requests.get', self.mockRequestsInternalServerError):
			self.assertRaises(
				Exception,
				niftycloud.stop_instance,
				(self.mockModule, 16)
			)

	# running(16) - restart -> running(16)
	def test_restart_instance(self):
		with mock.patch('niftycloud.stop_instance', self.mockStopInstance):
			with mock.patch('niftycloud.start_instance', self.mockStartInstance):
				self.assertEqual(
					(True, 16, 'restarted'),
					niftycloud.restart_instance(self.mockModule, 16)
				)

niftycloud_api_response_sample = dict(
	describeInstance = '''
<DescribeInstancesResponse xmlns="https://cp.cloud.nifty.com/api/">
  <requestId>7da9662b-578a-41fd-b455-c12bac4bc09d</requestId>
  <reservationSet>
    <item>
      <reservationId />
      <ownerId />
      <groupSet />
      <instancesSet>
        <item>
          <instanceId>server01</instanceId>
          <instanceUniqueId>i-efba9876</instanceUniqueId>
          <imageId>1</imageId>
          <instanceState>
            <code>16</code>
            <name>running</name>
          </instanceState>
          <privateDnsName>10.0.5.111</privateDnsName>
          <dnsName>111.171.202.1</dnsName>
          <keyName>sshkey01</keyName>
          <amiLaunchIndex />
          <productCodes>
            <item>
              <productCode />
            </item>
          </productCodes>
          <instanceType>small4</instanceType>
          <launchTime>2010-05-17T11:22:33.456Z</launchTime>
          <placement>
            <availabilityZone>east-11</availabilityZone>
          </placement>
          <kernelId />
          <ramdiskId />
          <platform>centos</platform>
          <imageName>CentOS6.3 64bit server</imageName>
          <monitoring>
            <state>disabled</state>
          </monitoring>
          <subnetId />
          <vpcId />
          <privateIpAddress>10.0.5.111</privateIpAddress>
          <IpAddress>111.171.202.1</IpAddress>
          <privateIpAddressV6 />
          <IpAddressV6 />
          <stateReason>
             <code />
             <message />
          </stateReason>
          <architecture>i386</architecture>
          <rootDeviceType>disk</rootDeviceType>
          <rootDeviceName />
          <blockDeviceMapping>
             <item>
              <deviceName>SCSI(0:1)</deviceName>
              <ebs>
               <volumeId>disk01</volumeId>
               <status>attached</status>
               <attachTime>2010-05-17T11:22:33.456Z</attachTime>
               <deleteOnTermination>false</deleteOnTermination>
               </ebs>
              </item>
          </blockDeviceMapping>
          <instanceLifecycle />
          <spotInstanceRequestId />
          <accountingType>2</accountingType>
          <nextMonthAccountingType>1</nextMonthAccountingType>
          <loadbalancing />
          <ipType>static</ipType>
          <niftyPrivateIpType>elastic</niftyPrivateIpType>
          <description />
          <hotAdd>0</hotAdd>
          <niftySnapshotting>
            <item>
              <state>normal</state>
          </item>
          </niftySnapshotting>
          <niftyPrivateNetworkType>STANDARD</niftyPrivateNetworkType>
          <tenancy>default</tenancy>
          <networkInterfaceSet>
            <item>
             <networkInterfaceId/>
             <subnetId/>
             <vpcId/>
             <description/>
             <ownerId/>
             <niftyNetworkId>net-COMMON_GLOBAL</niftyNetworkId>
             <niftyNetworkName/>
             <status>in-use</status>
             <macAddress>00-00-00-00-00-00</macAddress>
             <privateDnsName/>
             <sourceDestCheck/>
             <groupSet/>
             <attachment>
               <attachmentID/>
               <deviceIndex>0</deviceIndex>
               <status>attached</status>
               <attachTime/>
               <deleteOnTermination>true</deleteOnTermination>
             </attachment>
             <association>
               <publicIp>111.171.202.1</publicIp>
               <publicIpV6/>
               <publicDnsName/>
               <ipOwnerId/>
             </association>
             <privateIpAddressesSet/>
           </item>
           <item>
             <networkInterfaceId/>
             <subnetId/>
             <vpcId/>
             <description/>
             <ownerId/>
             <niftyNetworkId>net-COMMON_PRIVATE</niftyNetworkId>
             <niftyNetworkName/>
             <status>in-use</status>
             <macAddress>00-00-00-00-00-00</macAddress>
             <privateIpAddress>10.0.5.111</privateIpAddress>
             <privateIpAddressV6>2001:0db8:bd05:01d2:288a:1fc0:0001:10ee</privateIpAddressV6>
             <privateDnsName/>
             <sourceDestCheck/>
             <groupSet/>
             <attachment>
               <attachmentID/>
               <deviceIndex>0</deviceIndex>
               <status>attaching</status>
               <attachTime/>
               <deleteOnTermination>true</deleteOnTermination>
             </attachment>
             <association/>
           </item>
         </networkInterfaceSet>
        </item>
      </instancesSet>
    </item>
  </reservationSet>
</DescribeInstancesResponse>
''',
	runInstance = '''
<RunInstancesResponse xmlns="https://cp.cloud.nifty.com/api/">
  <requestId>dd1c39b0-a251-4596-a058-4f4c35069b9d</requestId>
  <reservationId />
  <ownerId />
  <groupSet />
  <instancesSet>
    <item>
      <instanceId>server04</instanceId>
      <instanceUniqueId>i-efgh1234</instanceUniqueId>
      <imageId>CentOS 5.3 32bit Plain</imageId>
      <instanceState>
        <code>0</code>
        <name>pending</name>
      </instanceState>
      <privateDnsName />
      <dnsName/>
      <keyName>sshkey01</keyName>
      <instanceType>medium</instanceType>
      <launchTime>2010-05-17T11:22:33.456Z </launchTime>
      <placement>
        <availabilityZone>east-11</availabilityZone>
      </placement>
      <platform>centos</platform>
      <monitoring>
        <state>monitoring-disable</state>
      </monitoring>
      <privateIpAddress />
      <ipAddress />
      <privateIpAddressV6 />
      <ipAddressV6 />
      <architecture>i386</architecture>
      <rootDeviceType>disk</rootDeviceType>
      <blockDeviceMapping>
        <item>
          <deviceName>SCSI (0:1)</deviceName>
          <ebs>
            <volumeId>disk0001</volumeId>
            <status>attaching</status>
            <deleteOnTermination>false</deleteOnTermination>
          </ebs>
        </item>
      </blockDeviceMapping>
      <accountingType>2</accountingType>
      <ipType>static</ipType>
      <niftyPrivateIpType>static</niftyPrivateIpType>
      <networkInterfaceSet>
        <item>
          <networkInterfaceId/>
          <subnetId/>
          <vpcId/>
          <description/>
          <ownerId/>
          <niftyNetworkId>net-COMMON_GLOBAL</niftyNetworkId>
          <niftyNetworkName/>
          <status>in-use</status>
          <macAddress>00-00-00-00-00-00</macAddress>
          <privateDnsName/>
          <sourceDestCheck/>
          <groupSet/>
          <attachment>
          <attachmentID/>
          <deviceIndex>0</deviceIndex>
          <status>attached</status>
          <attachTime/>
          <deleteOnTermination>true</deleteOnTermination>
        </attachment>
        <association/>
        <privateIpAddressesSet/>
      </item>
      <item>
        <networkInterfaceId/>
        <subnetId/>
        <vpcId/>
        <description/>
        <ownerId/>
        <niftyNetworkId>net-COMMON_PRIVATE</niftyNetworkId>
        <niftyNetworkName/>
        <status>in-use</status>
        <macAddress>00-00-00-00-00-00</macAddress>
        <privateIpAddress/>
        <privateIpAddressV6/>
        <privateDnsName/>
        <sourceDestCheck/>
        <groupSet/>
        <attachment>
          <attachmentID/>
          <deviceIndex>0</deviceIndex>
          <status>attaching</status>
          <attachTime/>
          <deleteOnTermination>true</deleteOnTermination>
        </attachment>
        <association/>
      </item>
      </networkInterfaceSet>
    </item>
  </instancesSet>
</RunInstancesResponse>
''',
	startInstance = '''
<StartInstancesResponse xmlns="https://cp.cloud.nifty.com/api/">
 <requestId>82625b74-ccaf-49d2-9baa-3fc3af444ebe</requestId>
 <instancesSet>
  <item>
   <instanceId>server04</instanceId>
   <instanceUniqueId>i-efba9876</instanceUniqueId>
   <currentState>
    <code>0</code>
    <name>pending</name>
   </currentState>
   <previousState>
    <code>80</code>
    <name>stopped</name>
   </previousState>
  </item>
 </instancesSet>
</StartInstancesResponse>
''',
	stopInstance = '''
<StopInstancesResponse xmlns="https://cp.cloud.nifty.com/api/">
  <requestId>b7ed3f0c-8603-4463-bd9c-8765d5efbaed</requestId>
  <instancesSet>
    <item>
      <instanceId>server04</instanceId>
      <instanceUniqueId>i-efjh1234</instanceUniqueId>
      <currentState>
        <code>0</code>
        <name>pending</name>
      </currentState>
      <previousState>
        <code>16</code>
        <name>running</name>
      </previousState>
    </item>
  </instancesSet>
</StopInstancesResponse>
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
