# niftycloud_lb - De-registers or registers an instance from Load Balancer in NIFTY Cloud

* [Synopsis](#synopsis)
* [Requirements](#requirements)
* [Options](#options)
* [Examples](#examples)

## Synopsis

De-registers or registers an instance of NIFTY Cloud from Load Balancer.

## Requirements

* python >= 2.6
* requests (if python 2.6, requests must be 2.5.3.)

## Options

| parameter           | required | default    | type | choices               | comments                                              |
|---------------------|----------|------------|------|-----------------------|-------------------------------------------------------|
| access_key          | yes      |            | str  |                       | NIFTY Cloud API access key                            |
| secret_access_key   | yes      |            | str  |                       | NIFTY Cloud API secret access key                     |
| endpoint            | yes      |            | str  |                       | API endpoint of target region                         |
| instance_id         | yes      |            | str  |                       | Instacen ID                                           |
| instance_port       | no       | None       | int  |                       | Destination Port  (required for registraiton)         |
| loadbalancer_name   | no       | None       | str  |                       | Target Load Balancer Name (required for registration) |
| loadbalancer_port   | no       | None       | int  |                       | Target Load Balancer Port (required for registration) |
| state               | yes      |            | str  | "present" or "absent" | Goal status                                           |

## Examples

```yaml
- name: Install (Requests) python package
  local_action:
    module: pip
    name: requests

- name: Regist server to load balancer
  local_action:
    module: niftycloud_lb
    access_key: "YOUR ACCESS KEY"
    secret_access_key: "YOUR SECRET ACCESS KEY"
    endpoint: "west-1.cp.cloud.nifty.com"
    instance_id: "web001"
    instance_port: 80
    loadbalancer_name: "lb001"
    loadbalancer_port: 80
    state: "present"
```
