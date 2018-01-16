#!/bin/env bash

# openssl req -out smtp.csr -new -newkey rsa:4096 -nodes -keyout smtp.key

mv smtp.pem smtp.pem-`date +%Y-%m-%d-%h:%m:%S.%N`

CN=`hostname`

openssl req -x509 -sha256 -nodes -days 365 -newkey rsa:4096 -keyout smtp.key -out smtp.pem \
 -subj "/C=US/ST=CA/L=Los Angeles/CN=$CN"

tlsa --port 25 --certificate smtp.crt $CN
