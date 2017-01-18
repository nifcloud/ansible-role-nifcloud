# niftycloud_volume - Attach the volume to an instance in NIFTY Cloud

* [Synopsis](#synopsis)
* [Requirements](#requirements)
* [Options](#options)
* [Examples](#examples)

## Synopsis

Attach the volume to an instance of NIFTY Cloud.

## Requirements

* python >= 2.6
* requests (if python 2.6, requests must be 2.5.3.)

## Options

| parameter           | required | default    | type | choices               | comments                                              |
|---------------------|----------|------------|------|-----------------------|-------------------------------------------------------|
| access_key          | yes      |            | str  |                       | NIFTY Cloud API access key                            |
| secret_access_key   | yes      |            | str  |                       | NIFTY Cloud API secret access key                     |
| endpoint            | yes      |            | str  |                       | API endpoint of target region                         |
| size                | yes      |            | str  |                       | Volume size                                           |
| volume_id           | no       |            | str  |                       | Volume name                                           |
| disk_type           | no       |            | str  |                       | Volume type                                           |
| instance_id         | yes      |            | str  |                       | Instacen ID                                           |
| accounting_type     | no       |            | str  |                       | Accounting type. (1: monthly, 2: pay per use)         |
| state               | yes      |            | str  | "present" or "absent" | Goal status ("absent" is not implemented)             |

## Examples

```yaml
- name: Install (Requests) python package
  local_action:
    module: pip
    name: requests

- name: Attach volume to instance
  local_action:
    module: niftycloud_volume
    access_key: "YOUR ACCESS KEY"
    secret_access_key: "YOUR SECRET ACCESS KEY"
    endpoint: "west-1.cp.cloud.nifty.com"
    instance_id: "web001"
    volume_id: "webdisk001"
    size: "100"
    disk_type: "3"
    accounting_type: "2"
    state: "present"
```
