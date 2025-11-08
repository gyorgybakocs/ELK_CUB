#!/bin/bash
set -e  # Exit immediately if a command exits with a non-zero status.

generate_keystore() {
  printf "Removing existing Keystore...\n"
  rm -f elasticsearch.keystore
  printf "Creating new Elasticsearch Keystore...\n"
  /usr/share/elasticsearch/bin/elasticsearch-keystore create
  echo "$ELASTIC_PASSWORD" | /usr/share/elasticsearch/bin/elasticsearch-keystore add -x 'bootstrap.password'
  chmod 0644 /usr/share/elasticsearch/config/elasticsearch.keystore
  chown elasticsearch:elasticsearch /usr/share/elasticsearch/config/elasticsearch.keystore
}
