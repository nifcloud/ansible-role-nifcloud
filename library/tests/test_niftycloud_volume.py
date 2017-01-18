import os
import sys
sys.path.append('.')
sys.path.append('..')

import unittest
import mock
import niftycloud_volume
import xml.etree.ElementTree as etree

class TestNiftycloud(unittest.TestCase):
	def setUp(self):
		self.mockModule = mock.MagicMock(
			params = dict(
				access_key = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
				secret_access_key = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
				endpoint   = 'west-1.cp.cloud.nifty.com',
				size = '100',
				volume_id = 'disk01',
				disk_type = '3',
				instance_id = 'test001',
				accounting_type = '2',
				state = 'present'
			),
			fail_json = mock.MagicMock(side_effect=Exception('failed'))
		)

		self.xmlnamespace = 'https://cp.cloud.nifty.com/api/'
		self.xml = niftycloud_api_response_sample

		self.mockRequestsGetDescribeVolumes = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['describeVolumes']
			))

		self.mockRequestsGetCreateVolume = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['createVolume']
			))

		self.mockRequestsGetAttachVolume = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 200,
				text = self.xml['attachVolume']
			))

		self.mockRequestsInternalServerError = mock.MagicMock(
			return_value=mock.MagicMock(
				status_code = 500,
				text = self.xml['describeVolumes']
			))

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

		signature = niftycloud_volume.calculate_signature(secret_access_key, method, endpoint, path, params)
		self.assertEqual(signature, 'Y7/0nc3dCK9UNkp+w5sh08ybJLQjh69mXOgcxJijDEU=')

	# method get
	def test_request_to_api_get(self):
		method = 'GET'
		action = 'DescribeVolumes'
		params = dict(
			InstanceId = self.mockModule.params['instance_id']
		)

		with mock.patch('requests.get', self.mockRequestsGetDescribeVolumes):
			info = niftycloud_volume.request_to_api(self.mockModule, method, action, params)

		self.assertEqual(info['status'], 200)
		self.assertEqual(info['xml_namespace'], dict(nc = self.xmlnamespace))
		self.assertEqual(etree.tostring(info['xml_body']),
				 etree.tostring(etree.fromstring(self.xml['describeVolumes'])))

	# method failed
	def test_request_to_api_unknown(self):
		method = 'UNKNOWN'
		action = 'DescribeVolumes'
		params = dict(
			InstanceId = self.mockModule.params['instance_id']
		)

		self.assertRaises(
			Exception,
			niftycloud_volume.request_to_api,
			(self.mockModule, method, action, params)
		)

	# network error
	def test_request_to_api_error(self):
		method = 'GET'
		action = 'DescribeVolumes'
		params = dict(
			InstanceId = self.mockModule.params['instance_id']
		)

		with mock.patch('requests.get', self.mockRequestsError):
			self.assertRaises(
				Exception,
				niftycloud_volume.request_to_api,
				(self.mockModule, method, action, params)
			)

	# get volume state present
	def test_get_volume_state_present(self):
		with mock.patch('requests.get', self.mockRequestsGetDescribeVolumes):
			self.assertEqual(
				('attached', 'test001'),
				niftycloud_volume.get_volume_state(self.mockModule)
			)

	# get volume state (volume_id not set)
	def test_get_volume_state_absent(self):
		with mock.patch('requests.get', self.mockRequestsGetDescribeVolumes):
			self.mockModule.params['volume_id'] = None
			self.assertEqual(
				('absent', None),
				niftycloud_volume.get_volume_state(self.mockModule)
			)

	# get volume state error
	def test_get_volume_state_error(self):
		with mock.patch('niftycloud_volume.request_to_api',
				self.mockRequestsInternalServerError):
			self.assertEqual(
				('absent', None),
				niftycloud_volume.get_volume_state(self.mockModule)
			)

	# create volume success
	def test_create_volume_success(self):
		with mock.patch('niftycloud_volume.get_volume_state',
				mock.MagicMock(return_value=('attached', 'test001'))):
			with mock.patch('requests.get',
					self.mockRequestsGetCreateVolume):
				self.assertEqual(
					(True, 'created'),
					niftycloud_volume.create_volume(self.mockModule)
				)

	# create volume failed
	def test_create_volume_failed(self):
		with mock.patch('niftycloud_volume.get_volume_state',
				mock.MagicMock(return_value=('attached', 'test001'))):
			with mock.patch('requests.get',
					self.mockRequestsInternalServerError):
				self.assertRaises(
					Exception,
					niftycloud_volume.create_volume,
					(self.mockModule)
				)

	# attach volume absent (with create failed)
	def test_attach_volume_absent(self):
		with mock.patch('niftycloud_volume.get_volume_state',
				mock.MagicMock(return_value=('absent', 'test001'))):
			with mock.patch('requests.get', self.mockRequestsInternalServerError):
				self.assertRaises(
					Exception,
					niftycloud_volume.attach_volume,
					(self.mockModule)
				)

	# attach volume success
	def test_attach_volume_success(self):
		with mock.patch('niftycloud_volume.get_volume_state',
				mock.MagicMock(return_value=('available', 'test001'))):
			with mock.patch('requests.get', self.mockRequestsGetAttachVolume):
				self.assertEqual(
					(True, 'attached'),
					niftycloud_volume.attach_volume(self.mockModule)
				)

	# attach volume error
	def test_attach_volume_failed(self):
		with mock.patch('niftycloud_volume.get_volume_state',
				mock.MagicMock(return_value=('detached', 'test001'))):
			with mock.patch('requests.get', self.mockRequestsInternalServerError):
				self.assertRaises(
					Exception,
					niftycloud_volume.attach_volume,
					(self.mockModule)
				)

	# attach volume attached
	def test_attach_volume_attached(self):
		with mock.patch('niftycloud_volume.get_volume_state',
				mock.MagicMock(return_value=('attached', 'test001'))):
			self.assertEqual(
				(False, 'attached'),
				niftycloud_volume.attach_volume(self.mockModule)
			)

	# attach volume unknown status
	def test_attach_volume_attached(self):
		with mock.patch('niftycloud_volume.get_volume_state',
				mock.MagicMock(return_value=('unknown', 'test001'))):
			self.assertRaises(
				Exception,
				niftycloud_volume.attach_volume,
				(self.mockModule)
			)

	# detach volume
	def test_detach_volume(self):
		self.assertRaises(
			Exception,
			niftycloud_volume.detach_volume,
			(self.mockModule)
		)

niftycloud_api_response_sample = dict(
	describeVolumes = '''
<DescribeVolumesResponse xmlns="https://cp.cloud.nifty.com/api/">
  <requestId>5f781c9f-ad69-4a20-a0bc-d3ebbeff6c75</requestId>
  <volumeSet>
    <item>
      <volumeId>disk01</volumeId>
      <size>200</size>
      <diskType>High-Speed Storage A</diskType>
      <snapshotId/>
      <availabilityZone>east-11</availabilityZone>
      <accountingType>1</accountingType>
      <nextMonthAccountingType>1</nextMonthAccountingType>
      <status>in-use</status>
      <createTime>2010-05-17T11:22:33.456Z</createTime>
      <attachmentSet>
        <item>
          <volumeId>disk01</volumeId>
          <instanceId>test001</instanceId>
          <instanceUniqueId>i-efgj1234</instanceUniqueId>
          <device>SCSI(0:1)</device>
          <status>attached</status>
          <attachTime>2010-05-17T11:22:33.456Z</attachTime>
        </item>
        <description>Memo</description>
      </attachmentSet>
    </item>
  </volumeSet>
</DescribeVolumesResponse>
''',
	createVolume = '''
<CreateVolumeResponse xmlns="https://cp.cloud.nifty.com/api/">
  <requestId>f6dd8353-eb6b-6b4fd32e4f05</requestId>
  <volumeId>disk01</volumeId>
  <size>200</size>
  <diskType>High-Speed Storage A</diskType>
  <snapshotId />
  <availabilityZone>east-11</availabilityZone>
  <status>creating</status>
  <createTime>2008-05-07T11:51:50.000Z</createTime>
  <accountingType>1</accountingType>
  <description>Memo</description>
</CreateVolumeResponse>
''',
	attachVolume = '''
<AttachVolumeResponse xmlns="https://cp.cloud.nifty.com/api/">
  <requestId>f6dd8353-eb6b-6b4fd32e4f05</requestId>
  <volumeId>disk01</volumeId>
  <instanceUniqueId>i-abfd1234</instanceUniqueId>
  <instanceId>test001</instanceId>
  <device>SCSI(0:1)</device>
  <status>attached</status>
  <attachTime>2010-05-17T11:22:33.456Z</attachTime>
</AttachVolumeResponse>
'''
)

if __name__ == '__main__':
	unittest.main()
