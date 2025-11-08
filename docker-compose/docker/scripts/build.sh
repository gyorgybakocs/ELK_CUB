#!/bin/bash
set -e

source scripts/generate_certs.sh
source scripts/verify.sh

KEYSTORE_PASSWORD=$1
ELASTIC_PASSWORD=$2
ELASTIC_INTERNAL=$3
ELASTICSEARCH_HOST=$4
CERT_DIR='certs'

printf "====== Clearing existing Certificates ======\n\n"

find "$CERT_DIR/common" "$CERT_DIR/elasticsearch" "$CERT_DIR/logstash" "$CERT_DIR/kibana" -type f ! -name '.gitkeep' -delete


printf "====== Folders are ready for Certificates generation ======\n\n"


printf "====== Download Let's Encrypt Certificates ======\n"
download_lets_encrypt_certs

printf "====== Generating Elasticsearch Certificates ======\n"

printf "\n====== Generating Certificates ======\n\n"
generate_cacert
generate_cert elasticsearch "$CERT_DIR/elasticsearch"
generate_cert logstash "$CERT_DIR/logstash"
generate_cert kibana "$CERT_DIR/kibana"
generate_truststore

# docker BUG -> when copy 600 permission file into the docker instance the size will be ZERO!!!
chmod 777 -R $CERT_DIR

printf "\n====== Checking generated Certificates in docker/certificates/dev directory ======\n\n"
ls -lR "$CERT_DIR"
printf "\n====== Certificates generation completed successfully ======\n"

printf "\n====== Veryfy Certifications ======\n\n"
verify_all
printf "\n====== Certifications verified successfully ======\n"
