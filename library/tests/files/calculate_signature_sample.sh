#!/bin/sh

function calculate_signature () {
  METHOD="$1" ; shift
  ENDPOINT="$1" ; shift
  API_PATH="$1" ; shift
  SECRET_ACCESS_KEY="$1" ; shift
  PARAMS=("$@")
  
  SORTED_PARAMS=($(IFS=$'\n'; echo "${PARAMS[*]}" | /bin/sort))
  PAYLOAD="$(IFS=$'&'; echo "${SORTED_PARAMS[*]}")"
  SIGNATURE=$(echo -ne "$METHOD\n$ENDPOINT\n$API_PATH\n$PAYLOAD" | openssl dgst -sha256 -binary -hmac "$SECRET_ACCESS_KEY" | base64)
  
  echo "$SIGNATURE"
}
