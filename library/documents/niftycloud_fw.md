# niftycloud_fw - Create or update, authorize, revoke a firewall group in NIFTY Cloud

* [Synopsis](#synopsis)
* [Requirements](#requirements)
* [Options](#options)
* [Examples](#examples)

## Synopsis

Create or update, authorize, revoke a firewall group.

## Requirements

* python >= 2.6
* requests (if python 2.6, requests must be 2.5.3.)

## Options

| parameter            | required | default    | type | choices   | aliases | comments                                                                                          |
|----------------------|----------|------------|------|-----------|---------|---------------------------------------------------------------------------------------------------|
| access_key           | yes      |            | str  |           |         | NIFTY Cloud API access key                                                                        |
| secret_access_key    | yes      |            | str  |           |         | NIFTY Cloud API secret access key                                                                 |
| endpoint             | yes      |            | str  |           |         | API endpoint of target region                                                                     |
| group_name           | yes      |            | str  |           | name    | Target firewall group ID                                                                          |
| description          | no       |            | str  |           |         | Description of target firewall group                                                              |
| availability_zone    | no       |            | str  |           |         | Availability zone                                                                                 |
| log_limit            | no       |            | int  |           |         | The upper limit number of logs to retain of communication rejected by the firewall settings rules |
| log_filters          | no       | dict()     | dict |           |         | Options for restrain broadcast logs                                                               |
| ip_permissions       | no       | list()     | list |           |         | List of rules that allows incoming or outgoing communication to resources                         |
| state                | no       | "present"  | str  | "present" |         | Goal status                                                                                       |
| purge_ip_permissions | no       | True       | bool |           |         | Purge existing ip permissions that are not found in ip permissions                                |

## Examples

```yaml
- name: Install (Requests) python package
  local_action:
    module: pip
    name: requests

- name: Regist server to load balancer
  local_action:
    module: niftycloud
    access_key: "YOUR ACCESS KEY"
    secret_access_key: "YOUR SECRET ACCESS KEY"
    endpoint: "west-1.cp.cloud.nifty.com"
    group_name: "fw001"
    description: "test firewall"
    availability_zone: "west-11"
    log_limit: 100000
    log_filters:
      net_bios: True
      broadcast: True
    ip_permissions:
      - ip_protocol: "ANY"
        in_out: "OUT"
        cidr_ip: "0.0.0.0/0"
        description: "all outgoing protocols are allow"
      - ip_protocol: "ICMP"
        in_out: "IN"
        cidr_ip: "192.168.0.0/24"
      - ip_protocol: "SSH"
        in_out: "IN"
        cidr_ip: "10.0.0.11"
      - ip_protocol: "UDP"
        from_port: 20000
        to_port: 29999
        in_out: "IN"
        group_name: "fw002"
      - ip_protocol: "TCP"
        from_port: 20000
        to_port: 29999
        in_out: "IN"
        group_name: "fw002"
    state: "present"
```
