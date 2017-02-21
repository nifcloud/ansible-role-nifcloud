# niftycloud - create, start or stop an instance in NIFTY Cloud

* [Synopsis](#synopsis)
* [Requirements](#requirements)
* [Options](#options)
* [Examples](#examples)

## Synopsis

Create, start or stop an instance of NIFTY Cloud.

## Requirements

* python >= 2.6
* requests (if python 2.6, requests must be 2.5.3.)

## Options

| parameter                      | required | default    | type | choices                             | comments                                         |
|------------------------------- |----------|------------|------|-------------------------------------|--------------------------------------------------|
| access_key                     | yes      |            | str  |                                     | NIFTY Cloud API access key                       |
| secret_access_key              | yes      |            | str  |                                     | NIFTY Cloud API secret access key                |
| endpoint                       | yes      |            | str  |                                     | API endpoint of target region                    |
| instance_id                    | yes      |            | str  |                                     | Instacen ID                                      |
| state                          | yes      |            | str  | "running", "stopped" or "restarted" | Goal status                                      |
| image_id                       | no       |            | str  |                                     | Image ID (Number of image) (required for create) |
| key_name                       | no       |            | str  |                                     | SSH key name (required for create)               |
| security_group                 | no       |            | str  |                                     | Member of security group (= Firewall)            |
| instance_type                  | no       |            | str  |                                     | Instance type                                    |
| availability_zone              | no       |            | str  |                                     | Availability zone                                |
| accounting_type                | no       |            | str  | "1" or "2"                          | Accounting type. (1: monthly, 2: pay per use)    |
| ip_type                        | no       |            | str  | "static", "elastic" or "none"       | IP Address type.                                 |
| public_ip                      | no       |            | str  |                                     | Elastic public IP address. (required if ip_type = elastic) |
| startup_script                 | no       |            | str  |                                     | Startup script template file path                |
| startup_script_vars            | no       | {} (blank) | dict |                                     | Variables for startup script template            |
| network_interface              | no       |            | list |                                     | NetworkInterface                                 |
| network_interface.network_id   | no       |            | str  |                                     | NetworkId                                        |
| network_interface.network_name | no       |            | str  |                                     | NetworkName                                      |
| network_interface.ipAddress    | no       |            | str  |                                     | IpAddress                                        |

## Examples

```yaml
- name: Install (Requests) python package
  local_action:
    module: pip
    name: requests

- name: Start server
  local_action:
    module: niftycloud
    access_key: "YOUR ACCESS KEY"
    secret_access_key: "YOUR SECRET ACCESS KEY"
    endpoint: "west-1.cp.cloud.nifty.com"
    instance_id: "web001"
    state: "running"
    image_id: "26"
    key_name: "dummykey"
    security_group: "webfw"
    instance_type: "mini"
    availability_zone: "west-11"
    accounting_type: "2"
    ip_type: "static"
    startup_script: "roles/infrastructure/template/startup_script"
    startup_script_vars:
      dummy_var: "DUMMY"
    network_interface:
      - network_id: net-COMMON_GLOBAL
        ipAddress: "0.0.0.0"
```
