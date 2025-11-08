#!/bin/bash
source verify.sh
source generate_keystore.sh

ES_CONFIG_DIR="/usr/share/elasticsearch/config/certs"
LOG_FILE="/usr/share/elasticsearch/logs/elasticsearch.log"

{
    printf "\n====== Checking Certificates in %s directory ======\n\n" $ES_CONFIG_DIR
    ls -lR "$ES_CONFIG_DIR"

    printf "\n====== Elasticsearch Certificates copied successfully ======\n"

    printf "\n====== Generating Elasticsearch Keystore. ======\n\n"
    generate_keystore

    printf "\n====== Verify Elasticsearch Keystore ======\n\n"
    verify_keystore

    printf "\n====== Elasticsearch Keystore verified successfully ======\n\n"
} 2>&1 | tee -a $LOG_FILE
