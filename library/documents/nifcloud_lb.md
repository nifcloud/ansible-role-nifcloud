# nifcloud_lb - De-registers or registers an instance from Load Balancer in NIFCLOUD

* [Synopsis](#synopsis)
* [Requirements](#requirements)
* [Options](#options)
* [Examples](#examples)

## Synopsis

Create, update filter, register/deregister instances a load balancer of NIFCLOUD.

## Requirements

* python >= 2.6
* requests (if python 2.6, requests must be 2.5.3.)

## Options

| parameter                        | required | default    | type | choices               | comments                                                                              |
|----------------------------------|----------|------------|------|-----------------------|---------------------------------------------------------------------------------------|
| access_key                       | yes      |            | str  |                       | NIFCLOUD API access key                                                               |
| secret_access_key                | yes      |            | str  |                       | NIFCLOUD API secret access key                                                        |
| endpoint                         | yes      |            | str  |                       | API endpoint of target region                                                         |
| loadbalancer_name                | yes      |            | str  |                       | Target Load Balancer Name (required for registration)                                 |
| loadbalancer_port                | yes      |            | int  |                       | Target Load Balancer Port (required for registration)                                 |
| instance_port                    | yes      |            | int  |                       | Destination Port  (required for registraiton)                                         |
| balancing_type                   | no       | 1          | int  |                       | Balancing type (1: Round-Robin or 2: Least-Connection)                                |
| network_volume                   | no       | 10         | int  |                       | Maximum of network volume                                                             |
| ip_version                       | no       | "v4"       | str  |                       | IP version ("v4" or "v6")                                                             |
| accounting_type                  | no       | "1"        | str  |                       | Accounting type ("1": monthly, "2": pay per use)                                      |
| policy_type                      | no       | "standard" | str  |                       | Encryption policy type ("standard" or "ats")                                          |
| instance_ids                     | no       | []         | list |                       | List of Instance ID                                                                   |
| purge_instance_ids               | no       | True       | bool |                       | Purge existing instance ids that are not found in instance_ids                        |
| filter_ip_addresses              | no       | []         | list |                       | List of ip addresses that allows/denys incoming communication to resources            |
| filter_type                      | no       | 1          | int  |                       | Filter type that switch to allows/denys for filter ip addresses (1: allow or 2: deny) |
| purge_filter_ip_addresses        | no       | True       | bool |                       | Purge existing filter ip addresses that are not found in filter_ip_addresses          |
| health_check_target              | no       | "ICMP"     | str  |                       | Health check protocol and port                                                        |
| health_check_interval            | no       | 5          | int  |                       | Interval of health check (second)                                                     |
| health_check_unhealthy_threshold | no       | 1          | int  |                       | Threshold of unhealthy                                                                |
| state                            | yes      |            | str  | "present" only        | Goal status                                                                           |

## Examples

```yaml
- name: Install (Requests) python package
  local_action:
    module: pip
    name: requests

- name: Ensured load balancer
  local_action:
    module: nifcloud_lb
    access_key: "YOUR ACCESS KEY"
    secret_access_key: "YOUR SECRET ACCESS KEY"
    endpoint: "west-1.cp.cloud.nifty.com"
    loadbalancer_name: "lb001"
    loadbalancer_port: 80
    instance_port: 80
    balancing_type: 1
    network_volume: 10
    accounting_type: "1"
    policy_type: "standard"
    instance_ids:
      - test001
    purge_instance_ids: True
    filter_ip_addresses:
      - 192.0.2.0
    filter_type: 1
    purge_filter_ip_addresses: True
    state: "present"
```
