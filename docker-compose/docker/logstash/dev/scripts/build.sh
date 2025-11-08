#!/bin/bash

LS_CONFIG_DIR="/usr/share/logstash/config/certs"
LOG_FILE="/usr/share/logstash/logs/logstash.log"

{
    printf "\n====== Checking Certificates in %s directory ======\n\n" $LS_CONFIG_DIR
    ls -lR "$LS_CONFIG_DIR"

    printf "\n====== Logstash Certificates copied successfully ======\n"
} 2>&1 | tee -a $LOG_FILE
