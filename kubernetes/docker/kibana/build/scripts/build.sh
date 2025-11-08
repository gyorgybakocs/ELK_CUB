#!/bin/bash

LS_CONFIG_DIR="/usr/share/kibana/config/certs"
LOG_FILE="/usr/share/kibana/logs/kibana.log"

{
    printf "\n====== Checking Certificates in %s directory ======\n\n" $LS_CONFIG_DIR
    ls -lR "$LS_CONFIG_DIR"

    printf "\n====== Kibana Certificates copied successfully ======\n"
} 2>&1 | tee -a $LOG_FILE
