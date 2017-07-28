# niftycloud_private_lan - Create or modify, delete a private lan in NIFTY Cloud

* [Synopsis](#synopsis)
* [Requirements](#requirements)
* [Options](#options)
* [Examples](#examples)

## Synopsis

Create or update, delete a private lan.

## Requirements

* python >= 2.6
* requests (if python 2.6, requests must be 2.5.3.)

## Options

| parameter            | required | default    | type | choices               | comments                                              |
|----------------------|----------|------------|------|-----------------------|-------------------------------------------------------|
| access_key           | yes      |            | str  |                       | NIFTY Cloud API access key                            |
| secret_access_key    | yes      |            | str  |                       | NIFTY Cloud API secret access key                     |
| endpoint             | yes      |            | str  |                       | API endpoint of target region                         |
| cidr_block           | yes      |            | str  |                       | CIDR of private lan                                   |
| private_lan_name     | no       |            | str  |                       | Target private lan name. Required private_lan_name or network_id. |
| network_id           | no       |            | str  |                       | Network unique ID. Required private_lan_name or network_id.       |
| accounting_type      | no       |            | str  |                       | Accounting type. (1: monthly, 2: pay per use)         |
| description          | no       |            | str  |                       | Description of target private lan                     |
| availability_zone    | no       |            | str  |                       | Availability zone                                     |
| state                | no       | "present"  | str  | "present" or "absent" | Goal status                                           |

## Examples

```yaml
- name: Install (Requests) python package
  local_action:
    module: pip
    name: requests

- name: Create private lan
  local_action:
    module: niftycloud_private_lan
    access_key: "YOUR ACCESS KEY"
    secret_access_key: "YOUR SECRET ACCESS KEY"
    endpoint: "west-1.cp.cloud.nifty.com"
    private_lan_name: "sample"
    cidr_block: "192.169.0.0/16"
    accounting_type: "1"
    description: "sample lan"
    availability_zone: "west-11"
    state: "present"
```
