# Ansible modules for NIFTY Cloud

* [niftycloud](documents/niftycloud.md)
* [niftycloud_fw](documents/niftycloud_fw.md)
* [niftycloud_lb](documents/niftycloud_lb.md)
* [niftycloud_volume](documents/niftycloud_volume.md)

## Test

* install necessary modules
```
# pip install unittest coverage nose
```

* execute tests
```
# nosetests --no-byte-compile --with-coverage > /dev/null 2>&1 && coverage report --include=./niftycloud*.py
```

* make anotated copies
```
# nosetests --no-byte-compile --with-coverage > /dev/null 2>&1 && coverage annotate --include=./niftycloud*.py
# cat *,cover
```

### About the signature constant value in the test

It is a signature calculated by different methods.

* calculate signature by shell-script
```
# METHOD="GET"
# ENDPOINT="west-1.cp.cloud.nifty.com"
# API_PATH="/api/"
# ACCESS_KEY_ID="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
# SECRET_ACCESS_KEY="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
# PARAMS=("Action=DescribeInstances" "AccessKeyId=$ACCESS_KEY_ID" "SignatureMethod=HmacSHA256" "SignatureVersion=2" "InstanceId=test001" "Description=$(echo '/' | nkf -WwMQ | tr = %)")

# SIGNATURE=$(. ./tests/files/calculate_signature_sample.sh; calculate_signature "$METHOD" "$ENDPOINT" "$API_PATH" "$SECRET_ACCESS_KEY" "${PARAMS[@]}")
# echo $SIGNATURE
dHOoGcBgO14Roaioryic9IdFPg7G+lihZ8Wyoa25ok4=

# QUERY=$(echo "${PARAMS[@]}" "Signature=$(echo $SIGNATURE | nkf -WwMQ | tr = %)" | tr ' ' '&')
# curl -X GET "https://${ENDPOINT}${API_PATH}?${QUERY}"
```

* results (2017/03/28)
```
Name                   Stmts   Miss  Cover
------------------------------------------
niftycloud.py            171     31    82%
niftycloud_fw.py         319      5    98%
niftycloud_lb.py         125     21    83%
niftycloud_volume.py     105     25    76%
------------------------------------------
TOTAL                    720     82    89%
```
