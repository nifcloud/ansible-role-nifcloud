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

import copy
import sys
import time
import unittest
import xml.etree.ElementTree as etree

import mock
import nifcloud_lb

sys.path.append('.')
sys.path.append('..')


class TestNifcloud(unittest.TestCase):
    TARGET_PRESENT_LB = 'nifcloud_lb.LoadBalancerManager._is_present_in_load_balancer'  # noqa
    TARGET_WAIT_LB_STATUS = 'nifcloud_lb.LoadBalancerManager._wait_for_loadbalancer_status'  # noqa
    TARGET_DESCRIBE_CURRENT = 'nifcloud_lb.LoadBalancerManager._describe_current_load_balancers'  # noqa
    TARGET_REGISTER_INSTANCES = 'nifcloud_lb.LoadBalancerManager._register_instances'  # noqa
    TARGET_DEREGISTER_INSTANCES = 'nifcloud_lb.LoadBalancerManager._deregister_instances'  # noqa

    def setUp(self):
        self.mockModule = mock.MagicMock(
            params=dict(
                access_key='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
                secret_access_key='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
                endpoint='west-1.cp.cloud.nifty.com',
                loadbalancer_name='lb001',
                loadbalancer_port=80,
                instance_port=80,
                balancing_type=1,
                network_volume=10,
                ip_version='v4',
                accounting_type='1',
                policy_type='standard',
                instance_ids=['test001'],
                purge_instance_ids=True,
                filter_ip_addresses=['192.168.0.1', '192.168.0.2'],
                filter_type=1,
                purge_filter_ip_addresses=True,
                health_check_target='TCP:80',
                health_check_interval=300,
                health_check_unhealthy_threshold=3,
                ssl_policy_name='',
                state='present'
            ),
            fail_json=mock.MagicMock(side_effect=Exception('failed')),
            check_mode=False,
        )

        self.xmlnamespace = 'https://cp.cloud.nifty.com/api/'
        self.xml = nifcloud_api_response_sample

        self.mockRequestsGetDescribeLoadBalancers = mock.MagicMock(
            return_value=mock.MagicMock(
                status_code=200,
                text=self.xml['describeLoadBalancers']
            ))

        self.mockRequestsGetDescribeLoadBalancersNameNotFound = mock.MagicMock(
            return_value=mock.MagicMock(
                status_code=500,
                text=self.xml['describeLoadBalancersNameNotFound']
            ))

        self.mockRequestsGetDescribeLoadBalancersPortNotFound = mock.MagicMock(
            return_value=mock.MagicMock(
                status_code=500,
                text=self.xml['describeLoadBalancersPortNotFound']
            ))

        self.mockDescribeLoadBalancers = mock.MagicMock(
            return_value=dict(
                status=200,
                xml_body=etree.fromstring(self.xml['describeLoadBalancers']),
                xml_namespace=dict(nc=self.xmlnamespace)
            ))

        self.mockRequestsPostCreateLoadBalancer = mock.MagicMock(
            return_value=mock.MagicMock(
                status_code=200,
                text=self.xml['createLoadBalancer']
            ))

        self.mockRequestsPostSetFilterForLoadBalancer = mock.MagicMock(
            return_value=mock.MagicMock(
                status_code=200,
                text=self.xml['setFilterForLoadBalancer']
            ))

        self.mockRequestsPostRegisterPortWithLoadBalancer = mock.MagicMock(
            return_value=mock.MagicMock(
                status_code=200,
                text=self.xml['registerPortWithLoadBalancer']
            ))

        self.mockRequestsPostRegisterInstancesWithLoadBalancer = mock.MagicMock(  # noqa
            return_value=mock.MagicMock(
                status_code=200,
                text=self.xml['registerInstancesWithLoadBalancer']
            ))

        self.mockRequestsPostDeregisterInstancesFromLoadBalancer = mock.MagicMock(  # noqa
            return_value=mock.MagicMock(
                status_code=200,
                text=self.xml['deregisterInstancesFromLoadBalancer']
            ))

        self.mockRequestsPostConfigureHealthCheck = mock.MagicMock(  # noqa
            return_value=mock.MagicMock(
                status_code=200,
                text=self.xml['configureHealthCheck']
            ))

        self.mockRequestsInternalServerError = mock.MagicMock(
            return_value=mock.MagicMock(
                status_code=500,
                text=self.xml['internalServerError']
            ))

        self.mockRequestsError = mock.MagicMock(return_value=None)
        self.mockGmtime = mock.MagicMock(return_value=time.gmtime(0))
        self.mockEmpty = mock.MagicMock()

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
            Action='DescribeLoadBalancers',
            AccessKeyId=self.mockModule.params['access_key'],
            SignatureMethod='HmacSHA256',
            SignatureVersion='2',
        )

        with mock.patch('time.gmtime', self.mockGmtime):
            signature = nifcloud_lb.calculate_signature(
                secret_access_key,
                method,
                endpoint,
                path,
                params
            )
            self.assertEqual(signature,
                             b'spq6n8gdx5j17CnUXsR2U5OdehAHs1jJMJ42kiGnZMw=')

    # calculate signature with string parameter including slash
    def test_calculate_signature_with_slash(self):
        secret_access_key = self.mockModule.params['secret_access_key']
        method = 'GET'
        endpoint = self.mockModule.params['endpoint']
        path = '/api/'
        params = dict(
            Action='DescribeLoadBalancers',
            AccessKeyId=self.mockModule.params['access_key'],
            SignatureMethod='HmacSHA256',
            SignatureVersion='2',
            Description='/'
        )

        signature = nifcloud_lb.calculate_signature(
            secret_access_key,
            method,
            endpoint,
            path,
            params
        )

        # This constant string is signature calculated by
        # "library/tests/files/calculate_signature_sample.sh".
        # This shell-script calculate with encoding a slash,
        # like "nifcloud.calculate_signature()".
        self.assertEqual(signature,
                         b'xDRKZSHLjnS1fW5xBMZoZD5T+tQ7Hk3A3ZXWT4HuNnM=')

    # method get
    def test_request_to_api_get(self):
        method = 'GET'
        action = 'DescribeLoadBalancers'
        params = dict()

        with mock.patch('requests.get',
                        self.mockRequestsGetDescribeLoadBalancers):
            info = nifcloud_lb.request_to_api(self.mockModule, method,
                                              action, params)

        self.assertEqual(info['status'], 200)
        self.assertEqual(info['xml_namespace'], dict(nc=self.xmlnamespace))
        self.assertEqual(
            etree.tostring(info['xml_body']),
            etree.tostring(etree.fromstring(self.xml['describeLoadBalancers']))
        )

    # api error
    def test_request_to_api_error(self):
        method = 'GET'
        action = 'DescribeLoadBalancers'
        params = dict()

        with mock.patch('requests.get', self.mockRequestsInternalServerError):
            info = nifcloud_lb.request_to_api(self.mockModule, method,
                                              action, params)

        self.assertEqual(info['status'], 500)
        self.assertEqual(
            etree.tostring(info['xml_body']),
            etree.tostring(etree.fromstring(self.xml['internalServerError']))
        )

    # method failed
    def test_request_to_api_unknown(self):
        method = 'UNKNOWN'
        action = 'DescribeLoadBalancers'
        params = dict()

        self.assertRaises(
            Exception,
            nifcloud_lb.request_to_api,
            (self.mockModule, method, action, params)
        )

    # network error
    def test_request_to_api_request_error(self):
        method = 'GET'
        action = 'DescribeLoadBalancers'
        params = dict()

        with mock.patch('requests.get', self.mockRequestsError):
            self.assertRaises(
                Exception,
                nifcloud_lb.request_to_api,
                (self.mockModule, method, action, params)
            )

    # get api error code & message
    def test_get_api_error(self):
        method = 'GET'
        action = 'DescribeLoadBalancers'
        params = dict()

        with mock.patch('requests.get', self.mockRequestsInternalServerError):
            info = nifcloud_lb.request_to_api(self.mockModule, method,
                                              action, params)

        error_info = nifcloud_lb.get_api_error(info['xml_body'])
        self.assertEqual(error_info['code'],    'Server.InternalError')
        self.assertEqual(error_info['message'],
                         'An error has occurred. Please try again later.')

    # describe
    def test_describe_load_balancers(self):
        with mock.patch('requests.get',
                        self.mockRequestsGetDescribeLoadBalancers):
            manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
            info = manager._describe_load_balancers(dict())
        self.assertEqual(info['status'], 200)
        self.assertEqual(info['xml_namespace'], dict(nc=self.xmlnamespace))
        self.assertEqual(
            etree.tostring(info['xml_body']),
            etree.tostring(etree.fromstring(self.xml['describeLoadBalancers']))
        )

    # present
    def test_get_state_instance_in_load_balancer_present(self):
        with mock.patch('requests.get',
                        self.mockRequestsGetDescribeLoadBalancers):
            manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
            self.assertEqual(
                'present',
                manager._get_state_instance_in_load_balancer()
            )

    # port-not-found
    def test_get_state_instance_in_load_balancer_port_not_found(self):
        with mock.patch('requests.get',
                        self.mockRequestsGetDescribeLoadBalancersPortNotFound):
            manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
            self.assertEqual(
                'port-not-found',
                manager._get_state_instance_in_load_balancer()
            )

    # absent
    def test_get_state_instance_in_load_balancer_absent(self):
        with mock.patch('requests.get',
                        self.mockRequestsGetDescribeLoadBalancersNameNotFound):
            manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
            self.assertEqual(
                'absent',
                manager._get_state_instance_in_load_balancer()
            )

    # internal server error
    def test_get_state_instance_in_load_balancer_error(self):
        with mock.patch('requests.get', self.mockRequestsInternalServerError):
            manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
            self.assertRaises(
                Exception,
                manager._get_state_instance_in_load_balancer,
            )

    # is present load balancer (present)
    def test_is_present_in_load_balancer_present(self):
        with mock.patch('requests.get',
                        self.mockRequestsGetDescribeLoadBalancers):
            manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
            self.assertEqual(
                True,
                manager._is_present_in_load_balancer()
            )

    # is present load balancer (absent)
    def test_is_present_in_load_balancer_absent(self):
        with mock.patch('requests.get',
                        self.mockRequestsGetDescribeLoadBalancersNameNotFound):
            manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
            self.assertEqual(
                False,
                manager._is_present_in_load_balancer()
            )

    # internal server error
    def test_is_present_in_load_balancer_error(self):
        with mock.patch('requests.get', self.mockRequestsInternalServerError):
            manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
            self.assertRaises(
                Exception,
                manager._is_present_in_load_balancer,
            )

    # is absent load balancer (present)
    def test_is_absent_in_load_balancer_present(self):
        with mock.patch('requests.get',
                        self.mockRequestsGetDescribeLoadBalancers):
            manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
            self.assertEqual(
                False,
                manager._is_absent_in_load_balancer()
            )

    # is absent load balancer (absent)
    def test_is_absent_in_load_balancer_absent(self):
        with mock.patch('requests.get',
                        self.mockRequestsGetDescribeLoadBalancersNameNotFound):
            manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
            self.assertEqual(
                True,
                manager._is_absent_in_load_balancer()
            )

    # internal server error
    def test_is_absent_in_load_balancer_error(self):
        with mock.patch('requests.get', self.mockRequestsInternalServerError):
            manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
            self.assertRaises(
                Exception,
                manager._is_absent_in_load_balancer,
            )

    # _create_loadbalancer success
    def test_create_loadbalancer_success(self):
        with mock.patch('requests.post',
                        self.mockRequestsPostCreateLoadBalancer):

            with mock.patch(self.TARGET_WAIT_LB_STATUS,
                            mock.MagicMock(return_value=True)):
                manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
                manager._create_load_balancer()
                self.assertEqual(True, manager.changed)

    # _create_loadbalancer wait failed
    def test_create_loadbalancer_wait_failed(self):
        with mock.patch('requests.post',
                        self.mockRequestsPostCreateLoadBalancer):

            with mock.patch(self.TARGET_WAIT_LB_STATUS,
                            mock.MagicMock(return_value=False)):
                manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
                self.assertRaises(
                    Exception,
                    manager._create_load_balancer,
                )

    # _create_loadbalancer internal error
    def test_create_loadbalancer_internal_error(self):
        with mock.patch('requests.post',
                        self.mockRequestsInternalServerError):

            with mock.patch(self.TARGET_WAIT_LB_STATUS,
                            mock.MagicMock(return_value=False)):
                manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
                self.assertRaises(
                    Exception,
                    manager._create_load_balancer,
                )

    # _register_port success
    def test_register_port_success(self):
        with mock.patch('requests.post',
                        self.mockRequestsPostRegisterPortWithLoadBalancer):

            with mock.patch(self.TARGET_WAIT_LB_STATUS,
                            mock.MagicMock(return_value=True)):
                manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
                manager._register_port()
                self.assertEqual(True, manager.changed)

    # _register_port wait failed
    def test_register_port_wait_failed(self):
        with mock.patch('requests.post',
                        self.mockRequestsPostRegisterPortWithLoadBalancer):

            with mock.patch(self.TARGET_WAIT_LB_STATUS,
                            mock.MagicMock(return_value=False)):
                manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
                self.assertRaises(
                    Exception,
                    manager._register_port,
                )

    # _register_port internal error
    def test_register_port_internal_error(self):
        with mock.patch('requests.post',
                        self.mockRequestsInternalServerError):

            with mock.patch(self.TARGET_WAIT_LB_STATUS,
                            mock.MagicMock(return_value=False)):
                manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
                self.assertRaises(
                    Exception,
                    manager._register_port,
                )

    # _sync_filter no change
    def test_sync_filter_no_change(self):
        with mock.patch('requests.post',
                        self.mockRequestsPostSetFilterForLoadBalancer):

            with mock.patch(self.TARGET_DESCRIBE_CURRENT,
                            self.mockDescribeLoadBalancers):
                manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
                manager._sync_filter()
                self.assertEqual(False, manager.changed)

    # _sync_filter change ip
    def test_sync_filter_change_ip(self):
        mockModule = mock.MagicMock(
            params=copy.deepcopy(self.mockModule.params),
            fail_json=self.mockModule.fail_json,
            check_mode=False,
        )
        addresses = ['192.168.0.3']
        mockModule.params['filter_ip_addresses'] = addresses

        with mock.patch('requests.post',
                        self.mockRequestsPostSetFilterForLoadBalancer):

            with mock.patch(self.TARGET_DESCRIBE_CURRENT,
                            self.mockDescribeLoadBalancers):
                manager = nifcloud_lb.LoadBalancerManager(mockModule)
                manager._sync_filter()
                self.assertEqual(True, manager.changed)

    # _sync_filter change filter type
    def test_sync_filter_change_type(self):
        mockModule = mock.MagicMock(
            params=copy.deepcopy(self.mockModule.params),
            fail_json=self.mockModule.fail_json,
            check_mode=False,
        )
        mockModule.params['filter_type'] = 2

        with mock.patch('requests.post',
                        self.mockRequestsPostSetFilterForLoadBalancer):

            with mock.patch(self.TARGET_DESCRIBE_CURRENT,
                            self.mockDescribeLoadBalancers):
                manager = nifcloud_lb.LoadBalancerManager(mockModule)
                manager._sync_filter()
                self.assertEqual(True, manager.changed)

    # _sync_filter not purge
    def test_sync_filter_not_purge(self):
        mockModule = mock.MagicMock(
            params=copy.deepcopy(self.mockModule.params),
            fail_json=self.mockModule.fail_json,
            check_mode=False,
        )
        addresses = []
        mockModule.params['filter_ip_addresses'] = addresses
        mockModule.params['purge_filter_ip_addresses'] = False

        with mock.patch('requests.post',
                        self.mockRequestsPostSetFilterForLoadBalancer):

            with mock.patch(self.TARGET_DESCRIBE_CURRENT,
                            self.mockDescribeLoadBalancers):
                manager = nifcloud_lb.LoadBalancerManager(mockModule)
                manager._sync_filter()
                self.assertEqual(False, manager.changed)

    # _sync_filter internal error
    def test_sync_filter_internal_error(self):
        mockModule = mock.MagicMock(
            params=copy.deepcopy(self.mockModule.params),
            fail_json=self.mockModule.fail_json,
            check_mode=False,
        )
        addresses = ['192.168.0.1']
        mockModule.params['filter_ip_addresses'] = addresses

        with mock.patch('requests.post',
                        self.mockRequestsInternalServerError):

            with mock.patch(self.TARGET_DESCRIBE_CURRENT,
                            self.mockDescribeLoadBalancers):
                manager = nifcloud_lb.LoadBalancerManager(mockModule)
                self.assertRaises(
                    Exception,
                    manager._sync_filter,
                )

    # _sync_instances no change
    def test_sync_instances_no_change(self):
        with mock.patch(self.TARGET_DESCRIBE_CURRENT,
                        self.mockDescribeLoadBalancers):
            with mock.patch(self.TARGET_REGISTER_INSTANCES,
                            self.mockEmpty):
                with mock.patch(self.TARGET_DEREGISTER_INSTANCES,
                                self.mockEmpty):

                    manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
                    manager._sync_instances()
                    self.assertEqual(False, manager.changed)

    # _sync_instances register instance
    def test_sync_instances_register_instance(self):
        mockModule = mock.MagicMock(
            params=copy.deepcopy(self.mockModule.params),
            fail_json=self.mockModule.fail_json,
            check_mode=False,
        )
        instance_ids = ['test001', 'test002']
        mockModule.params['instance_ids'] = instance_ids

        with mock.patch(self.TARGET_DESCRIBE_CURRENT,
                        self.mockDescribeLoadBalancers):
            with mock.patch('requests.post',
                            self.mockRequestsPostRegisterInstancesWithLoadBalancer):  # noqa
                with mock.patch(self.TARGET_DEREGISTER_INSTANCES,
                                self.mockEmpty):

                    manager = nifcloud_lb.LoadBalancerManager(mockModule)
                    manager._sync_instances()
                    self.assertEqual(True, manager.changed)

    # _sync_instances deregister instance
    def test_sync_instances_deregister_instance(self):
        mockModule = mock.MagicMock(
            params=copy.deepcopy(self.mockModule.params),
            fail_json=self.mockModule.fail_json,
            check_mode=False,
        )
        instance_ids = []
        mockModule.params['instance_ids'] = instance_ids

        with mock.patch(self.TARGET_DESCRIBE_CURRENT,
                        self.mockDescribeLoadBalancers):
            with mock.patch(self.TARGET_REGISTER_INSTANCES,
                            self.mockEmpty):
                with mock.patch('requests.post',
                                self.mockRequestsPostDeregisterInstancesFromLoadBalancer):  # noqa

                    manager = nifcloud_lb.LoadBalancerManager(mockModule)
                    manager._sync_instances()
                    self.assertEqual(True, manager.changed)

    # _sync_instances not purge
    def test_sync_instances_not_purge(self):
        mockModule = mock.MagicMock(
            params=copy.deepcopy(self.mockModule.params),
            fail_json=self.mockModule.fail_json,
            check_mode=False,
        )
        instance_ids = []
        mockModule.params['instance_ids'] = instance_ids
        mockModule.params['purge_instance_ids'] = False

        with mock.patch(self.TARGET_DESCRIBE_CURRENT,
                        self.mockDescribeLoadBalancers):
            with mock.patch(self.TARGET_REGISTER_INSTANCES,
                            self.mockEmpty):
                with mock.patch('requests.post',
                                self.mockRequestsPostDeregisterInstancesFromLoadBalancer):  # noqa

                    manager = nifcloud_lb.LoadBalancerManager(mockModule)
                    manager._sync_instances()
                    self.assertEqual(False, manager.changed)

    # _register_instances internal error
    def test_register_instances_internal_error(self):
        with mock.patch('requests.post',
                        self.mockRequestsPostRegisterInstancesWithLoadBalancer):  # noqa
            manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
            self.assertRaises(
                Exception,
                manager._register_instances,
            )

    # _deregister_instances internal error
    def test_deregister_instances_internal_error(self):
        with mock.patch('requests.post',
                        self.mockRequestsPostDeregisterInstancesFromLoadBalancer):  # noqa
            manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
            self.assertRaises(
                Exception,
                manager._deregister_instances,
            )

    # _health_check no change
    def test_sync_health_check_no_change(self):
        with mock.patch('requests.post',
                        self.mockRequestsPostConfigureHealthCheck):

            with mock.patch(self.TARGET_DESCRIBE_CURRENT,
                            self.mockDescribeLoadBalancers):
                manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
                manager._sync_health_check()
                self.assertEqual(False, manager.changed)

    # _sync_helth_check changed
    def test_sync_health_check_changed(self):
        mockModule = mock.MagicMock(
            params=copy.deepcopy(self.mockModule.params),
            fail_json=self.mockModule.fail_json,
            check_mode=False,
        )
        mockModule.params['health_check_target'] = 'ICMP'
        mockModule.params['health_check_interval'] = 5
        mockModule.params['health_check_unhealthy_threshold'] = 10

        with mock.patch('requests.post',
                        self.mockRequestsPostConfigureHealthCheck):

            with mock.patch(self.TARGET_DESCRIBE_CURRENT,
                            self.mockDescribeLoadBalancers):
                manager = nifcloud_lb.LoadBalancerManager(mockModule)
                manager._sync_health_check()
                self.assertEqual(True, manager.changed)

    # _sync_health_checl internal error
    def test_sync_health_check_internal_error(self):
        mockModule = mock.MagicMock(
            params=copy.deepcopy(self.mockModule.params),
            fail_json=self.mockModule.fail_json,
            check_mode=False,
        )

        mockModule.params['health_check_target'] = 'ICMP'

        with mock.patch('requests.post',
                        self.mockRequestsInternalServerError):

            with mock.patch(self.TARGET_DESCRIBE_CURRENT,
                            self.mockDescribeLoadBalancers):
                manager = nifcloud_lb.LoadBalancerManager(mockModule)
                self.assertRaises(
                    Exception,
                    manager._sync_health_check,
                )

    # _sync_ssl_policy no change
    def test_sync_ssl_policy_no_change(self):
        with mock.patch('requests.post',
                        self.mockRequestsPostConfigureHealthCheck):

            with mock.patch(self.TARGET_DESCRIBE_CURRENT,
                            self.mockDescribeLoadBalancers):
                manager = nifcloud_lb.LoadBalancerManager(self.mockModule)
                manager._sync_ssl_policy()
                self.assertEqual(False, manager.changed)

    # _sync_ssl_policy changed
    def test_sync_ssl_policy_changed(self):
        mockModule = mock.MagicMock(
            params=copy.deepcopy(self.mockModule.params),
            fail_json=self.mockModule.fail_json,
            check_mode=False,
        )
        mockModule.params['ssl_policy_name'] = 'Standard Ciphers A ver1'

        with mock.patch('requests.post',
                        self.mockRequestsPostConfigureHealthCheck):

            with mock.patch(self.TARGET_DESCRIBE_CURRENT,
                            self.mockDescribeLoadBalancers):
                manager = nifcloud_lb.LoadBalancerManager(mockModule)
                manager._sync_ssl_policy()
                self.assertEqual(True, manager.changed)

    # _sync_ssl_policy internal error
    def test_sync_ssl_policy_internal_error(self):
        mockModule = mock.MagicMock(
            params=copy.deepcopy(self.mockModule.params),
            fail_json=self.mockModule.fail_json,
            check_mode=False,
        )
        mockModule.params['ssl_policy_name'] = 'Standard Ciphers A ver1'

        with mock.patch('requests.post',
                        self.mockRequestsInternalServerError):

            with mock.patch(self.TARGET_DESCRIBE_CURRENT,
                            self.mockDescribeLoadBalancers):
                manager = nifcloud_lb.LoadBalancerManager(mockModule)
                self.assertRaises(
                    Exception,
                    manager._sync_ssl_policy,
                )

nifcloud_api_response_sample = dict(
    describeLoadBalancers='''
<DescribeLoadBalancersResponse xmlns="https://cp.cloud.nifty.com/api/">
<DescribeLoadBalancersResult>
 <LoadBalancerDescriptions>
  <member>
  <LoadBalancerName>lb000</LoadBalancerName>
  <DNSName>111.171.200.1</DNSName>
  <NetworkVolume>10</NetworkVolume>
  <ListenerDescriptions>
   <member>
   <Listener>
    <Protocol>HTTP</Protocol>
    <LoadBalancerPort>80</LoadBalancerPort>
    <InstancePort>80</InstancePort>
    <balancingType>1</balancingType>
    <SSLCertificateId>100</SSLCertificateId>
   </Listener>
   </member>
  </ListenerDescriptions>
  <Policies>
   <AppCookieStickinessPolicies>
    <member>
     <PolicyName/>
     <CookieName/>
    </member>
   </AppCookieStickinessPolicies>
   <LBCookieStickinessPolicies>
    <member>
     <PolicyName/>
     <CookieExpirationPeriod/>
    </member>
   </LBCookieStickinessPolicies>
  </Policies>
  <AvailabilityZones>
   <member>east-11</member>
  </AvailabilityZones>
  <Instances>
  </Instances>
  <HealthCheck>
   <Target>TCP:80</Target>
   <Interval>300</Interval>
   <Timeout>900</Timeout>
   <UnhealthyThreshold>3</UnhealthyThreshold>
   <HealthyThreshold>1</HealthyThreshold>
  </HealthCheck>
  <Filter>
   <FilterType>1</FilterType>
   <IPAddresses>
    <member>
     <IPAddress>192.168.0.1</IPAddress>
     <IPAddress>192.168.0.2</IPAddress>
    </member>
   </IPAddresses>
  </Filter>
  <CreatedTime>2010-05-17T11:22:33.456Z</CreatedTime>
  <AccountingType>1</AccountingType>
  <NextMonthAccountingType>1</NextMonthAccountingType>
  <Option>
    <SessionStickinessPolicy>
      <Enabled>true</Enabled>
      <ExpirationPeriod>10</ExpirationPeriod>
    </SessionStickinessPolicy>
    <SorryPage>
      <Enabled>true</Enabled>
      <StatusCode>200</StatusCode>
    </SorryPage>
  </Option>
  </member>
  <member>
  <LoadBalancerName>lb001</LoadBalancerName>
  <DNSName>111.171.200.1</DNSName>
  <NetworkVolume>10</NetworkVolume>
  <ListenerDescriptions>
   <member>
   <Listener>
    <Protocol>HTTP</Protocol>
    <LoadBalancerPort>80</LoadBalancerPort>
    <InstancePort>80</InstancePort>
    <balancingType>1</balancingType>
    <SSLCertificateId>100</SSLCertificateId>
   </Listener>
   </member>
  </ListenerDescriptions>
  <Policies>
   <AppCookieStickinessPolicies>
    <member>
     <PolicyName/>
     <CookieName/>
    </member>
   </AppCookieStickinessPolicies>
   <LBCookieStickinessPolicies>
    <member>
     <PolicyName/>
     <CookieExpirationPeriod/>
    </member>
   </LBCookieStickinessPolicies>
  </Policies>
  <AvailabilityZones>
   <member>east-11</member>
  </AvailabilityZones>
  <Instances>
   <member>
   <InstanceId>test001</InstanceId>
   <InstanceUniqueId>i-asdg1234</InstanceUniqueId>
   </member>
  </Instances>
  <HealthCheck>
   <Target>TCP:80</Target>
   <Interval>300</Interval>
   <Timeout>900</Timeout>
   <UnhealthyThreshold>3</UnhealthyThreshold>
   <HealthyThreshold>1</HealthyThreshold>
   <InstanceStates>
    <member>
     <InstanceId>Server001</InstanceId>
     <InstanceUniqueId>i-12345678</InstanceUniqueId>
     <State>InService</State>
     <ResponseCode />
     <Description />
    </member>
   </InstanceStates>
  </HealthCheck>
  <Filter>
   <FilterType>1</FilterType>
   <IPAddresses>
    <member>
     <IPAddress>111.111.111.111</IPAddress>
     <IPAddress>111.111.111.112</IPAddress>
    </member>
   </IPAddresses>
  </Filter>
  <CreatedTime>2010-05-17T11:22:33.456Z</CreatedTime>
  <AccountingType>1</AccountingType>
  <NextMonthAccountingType>1</NextMonthAccountingType>
  <Option>
    <SessionStickinessPolicy>
      <Enabled>true</Enabled>
      <ExpirationPeriod>10</ExpirationPeriod>
    </SessionStickinessPolicy>
    <SorryPage>
      <Enabled>true</Enabled>
      <StatusCode>200</StatusCode>
    </SorryPage>
  </Option>
  </member>
 </LoadBalancerDescriptions>
 </DescribeLoadBalancersResult>
  <ResponseMetadata>
    <RequestId>f6dd8353-eb6b-6b4fd32e4f05</RequestId>
  </ResponseMetadata>
</DescribeLoadBalancersResponse>
''',
    describeLoadBalancersNameNotFound='''
<Response>
 <Errors>
  <Error>
   <Code>Client.InvalidParameterNotFound.LoadBalancer</Code>
   <Message>The LoadBalancerName 'lb001' does not exist.</Message>
  </Error>
 </Errors>
 <RequestID>5ec8da0a-6e23-4343-b474-ca0bb5c22a51</RequestID>
</Response>
''',
    describeLoadBalancersPortNotFound='''
<Response>
 <Errors>
  <Error>
   <Code>Client.InvalidParameterNotFound.LoadBalancerPort</Code>
   <Message>The requested LoadBalancer 'lb001' does not have this port (loadBalancerPort:80,instancePort:80).</Message>
  </Error>
 </Errors>
 <RequestID>5ec8da0a-6e23-4343-b474-ca0bb5c22a51</RequestID>
</Response>
''',  # noqa
    registerInstancesWithLoadBalancer='''
<RegisterInstancesWithLoadBalancerResponse xmlns="https://cp.cloud.nifty.com/api/">
  <RegisterInstancesWithLoadBalancerResult>
    <Instances>
      <member>
        <InstanceId>test001</InstanceId>
        <instanceUniqueId>i-asda1234</instanceUniqueId>
      </member>
    </Instances>
  </RegisterInstancesWithLoadBalancerResult>
  <ResponseMetadata>
    <RequestId>f6dd8353-eb6b-6b4fd32e4f05</RequestId>
  </ResponseMetadata>
</RegisterInstancesWithLoadBalancerResponse>
''',  # noqa
    createLoadBalancer='''
<CreateLoadBalancerResponse xmlns="https://cp.cloud.nifty.com/api/">
  <CreateLoadBalancerResult>
    <DNSName>111.171.200.1</DNSName>
  </CreateLoadBalancerResult>
  <ResponseMetadata>
    <RequestId>ac501097-4c8d-475b-b06b-a90048ec181c</RequestId>
  </ResponseMetadata>
</CreateLoadBalancerResponse>
''',
    setFilterForLoadBalancer='''
<SetFilterForLoadBalancerResponse xmlns="https://cp.cloud.nifty.com/api/">
  <SetFilterForLoadBalancerResult>
    <Filter>
      <FilterType>1</FilterType>
      <IPAddresses>
        <member>
          <IPAddress>192.168.0.1</IPAddress>
          <IPAddress>192.168.0.2</IPAddress>
        </member>
      </IPAddresses>
    </Filter>
  </SetFilterForLoadBalancerResult>
  <ResponseMetadata>
    <RequestId>ac501097-4c8d-475b-b06b-a90048ec181c</RequestId>
  </ResponseMetadata>
</SetFilterForLoadBalancerResponse>
''',
    registerPortWithLoadBalancer='''
<RegisterPortWithLoadBalancerResponse xmlns="https://cp.cloud.nifty.com/api/">
  <RegisterPortWithLoadBalancerResult>
    <Listeners>
      <member>
        <Protocol>HTTP</Protocol>
        <LoadBalancerPort>80</LoadBalancerPort>
        <InstancePort>80</InstancePort>
        <BalancingType>1</BalancingType>
      </member>
    </Listeners>
  </RegisterPortWithLoadBalancerResult>
  <ResponseMetadata>
    <RequestId>ac501097-4c8d-475b-b06b-a90048ec181c</RequestId>
  </ResponseMetadata>
</RegisterPortWithLoadBalancerResponse>
''',
    deregisterInstancesFromLoadBalancer='''
<DeregisterInstancesFromLoadBalancerResponse xmlns="https://cp.cloud.nifty.com/api/">
  <DeregisterInstancesFromLoadBalancerResult>
    <Instances>
      <member>
        <InstanceId>test001</InstanceId>
        <instanceUniqueId>i-abvf1234</instanceUniqueId>
      </member>
    </Instances>
  </DeregisterInstancesFromLoadBalancerResult>
  <ResponseMetadata>
    <RequestId>f6dd8353-eb6b-6b4fd32e4f05</RequestId>
  </ResponseMetadata>
</DeregisterInstancesFromLoadBalancerResponse>
''',  # noqa
    configureHealthCheck='''
<ConfigureHealthCheckResponse xmlns="https://cp.cloud.nifty.com/api/">
  <ConfigureHealthCheckResult>
    <HealthCheck>
      <Target>ICMP</Target>
      <Interval>5</Interval>
      <Timeout>900</Timeout>
      <UnhealthyThreshold>1</UnhealthyThreshold>
      <HealthyThreshold>1</HealthyThreshold>
    </HealthCheck>
  </ConfigureHealthCheckResult>
  <ResponseMetadata>
    <RequestId>ac501097-4c8d-475b-b06b-a90048ec181c</RequestId>
  </ResponseMetadata>
</ConfigureHealthCheckResponse>
''',  # noqa
    internalServerError='''
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
