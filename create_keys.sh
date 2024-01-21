#!/bin/bash
# generate public and private key pairs

# private key
openssl ecparam -name secp521r1 -genkey -noout -out keys/private-key.pem
# public key
openssl ec -in keys/private-key.pem -pubout -out keys/public-key.pem