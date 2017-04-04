#!/bin/sh

#
# ### How to Use ###
#
# $ METHOD="GET"
# $ ENDPOINT="west-1.cp.cloud.nifty.com"
# $ API_PATH="/api/"
# $ ACCESS_KEY_ID="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
# $ SECRET_ACCESS_KEY="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
# $ PARAMS=("Action=DescribeInstances" "AccessKeyId=$ACCESS_KEY_ID" "SignatureMethod=HmacSHA256" "SignatureVersion=2" "InstanceId=test001" "Description=$(echo '/' | nkf -WwMQ | tr = %)")
#
# $ SIGNATURE=$(. ./tests/files/calculate_signature_sample.sh; calculate_signature "$METHOD" "$ENDPOINT" "$API_PATH" "$SECRET_ACCESS_KEY" "${PARAMS[@]}")
# $ echo $SIGNATURE
# dHOoGcBgO14Roaioryic9IdFPg7G+lihZ8Wyoa25ok4=
#
# $ QUERY=$(echo "${PARAMS[@]}" "Signature=$(echo $SIGNATURE | nkf -WwMQ | tr = %)" | tr ' ' '&')
# $ curl -X GET "https://${ENDPOINT}${API_PATH}?${QUERY}"
#

function calculate_signature () {
  METHOD="$1" ; shift
  ENDPOINT="$1" ; shift
  API_PATH="$1" ; shift
  SECRET_ACCESS_KEY="$1" ; shift
  PARAMS=("$@")
  
  SORTED_PARAMS=($(IFS=$'\n'; echo "${PARAMS[*]}" | sort))
  PAYLOAD="$(IFS=$'&'; echo "${SORTED_PARAMS[*]}")"
  SIGNATURE=$(echo -ne "$METHOD\n$ENDPOINT\n$API_PATH\n$PAYLOAD" | openssl dgst -sha256 -binary -hmac "$SECRET_ACCESS_KEY" | base64)
  
  echo "$SIGNATURE"
}
