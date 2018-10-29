#!/bin/bash
if [ "$#" -ne 1 ] && [ "$#" -ne 2 ] ; then
    echo "usage $0 <cpt-dir> [test nr]"
    exit 1
fi

now=`date +%F__%H.%M.%S`
outfile=openssl_ocsp_test_$now
shopt -s globstar
cnt=0
for i in $1/output/CERT_PATH_OCSP_*; do # Whitespace-safe and recursive
  cnt=$((cnt+1))
  if [ "$#" -eq 2 ]; then
    if [ "$2" -ne "$cnt" ]; then
      continue
    fi
  fi
  ee_file=$i/CERT_PATH_OCSP_??_EE.TC.pem.crt
  subca_file=$i/CERT_PATH_OCSP_??_SUB_CA.CA.pem.crt
  test_name=$(basename "$i")
  ocsp_uri=`openssl x509 -in $ee_file -noout -ocsp_uri`
  echo $test_name: 
  echo $test_name: >> $outfile
  test_case_file=$1/testcases/mod_ocsp/${test_name}.xml
  tmp=`sed -re 's/<Text>([A-Z]+)<\/Text>/\1/;t;d' $test_case_file` 
  # remove whitespaces:
  exp_res="$(echo -e "${tmp}" | tr -d '[:space:]')"
  status=`openssl ocsp -issuer $subca_file -cert $ee_file -url $ocsp_uri -CAfile $subca_file | sed -re 's|[a-zA-Z0-9/_-.]+: ([a-z]+)|\1|;t;d'`
  resp_ver_ok_str=`openssl ocsp -issuer $subca_file -cert $ee_file -url $ocsp_uri -CAfile $subca_file 2>&1 | sed -re 's|(Response verify OK)|\1|;t;d'`
  echo "  status = "$status >> $outfile
  echo "  response verify = "$resp_ver_ok_str >> $outfile
  resp_ver_ok=${#resp_ver_ok_str}
  echo "  resp_ver_ok="$resp_ver_ok
  echo "  expected result = "$exp_res >> $outfile
  if  [ "$resp_ver_ok" -eq 0 ] || [ "$status" != "good" ]; then
    echo "  actual result = INVALID" >> $outfile
    if [ "$exp_res" = "VALID" ]; then
      echo "  result: FAIL" >> $outfile
    else
      echo "  result: PASS" >> $outfile
    fi
  else
    echo "  actual result = VALID" >> $outfile
    echo "expected result = '"$exp_res"'"
    echo "outfile         = '"$outfile"'"
    if [ "$exp_res" = "INVALID" ]; then
      echo "  result: FAIL" >> $outfile
    else
      echo "  result: PASS" >> $outfile
    fi
  fi
done
