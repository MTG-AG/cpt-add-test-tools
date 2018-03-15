#!/bin/bash
if [ "$#" -ne 1 ]; then
  echo "must provide the strongswan directory as parameter"
  exit 1
fi
patch $1/src/libstrongswan/plugins/x509/x509_cert.c strsw_5.5.3._test_tool.patch
