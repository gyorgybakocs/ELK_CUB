#!/bin/bash
source verify.sh

ELASTIC_PASSWORD=$1
LOGSTASH_PASSWORD=$2
KIBANA_SYSTEM_PASSWORD=$3
KIBANA_PASSWORD=$4
LOG_FILE="/usr/share/elasticsearch/logs/elasticsearch.log"

/usr/share/elasticsearch/bin/elasticsearch -d

{
  # Function to check Elasticsearch health
  check_es_health() {
      for i in {1..60}; do
          printf "Checking Elasticsearch health (attempt %d/60)...\n" "$i"
          response=$(curl -s -k -u "elastic:$ELASTIC_PASSWORD" "https://localhost:9200/_cluster/health")
          printf "Health check response:\n%s\n" "$response"

          if echo "$response" | grep -q '"status":"green"'; then
              printf "Elasticsearch is healthy and ready!\n"
              return 0
          elif echo "$response" | grep -q '"status":"yellow"'; then
              printf "Elasticsearch is in yellow status. Proceeding...\n"
              return 0
          fi
          sleep 5
      done
      return 1
  }

  # Check Elasticsearch health
  if ! check_es_health; then
      printf "ERROR: Elasticsearch failed to become healthy.\n"
      exit 1
  fi

  printf "\n====== Creating logstash_writer role... ======\n\n"
  curl -X POST -k -u elastic:"$ELASTIC_PASSWORD" "https://localhost:9200/_security/role/logstash_writer" -H "Content-Type: application/json" -d'
  {
    "cluster": ["manage_index_templates", "monitor", "manage_ilm", "cluster:admin/xpack/monitoring/bulk"],
    "indices": [
      {
        "names": [ "logstash-*", "bgds_k8s_*" ],
        "privileges": ["write", "create_index", "auto_configure"]
      }
    ]
  }'
  printf "\n====== logstash_writer role created ======\n\n"

  printf "\n====== Creating Logstash user... ======\n\n"
  curl -X POST -k -u elastic:"$ELASTIC_PASSWORD" "https://localhost:9200/_security/user/logstash" -H "Content-Type: application/json" -d"
  {
    \"password\" : \"$LOGSTASH_PASSWORD\",
    \"roles\" : [ \"logstash_writer\" ],
    \"full_name\" : \"Logstash User\"
  }"
  printf "\n====== Logstash user created ======\n\n"

  printf "\n====== Updating kibana_system user password... ======\n\n"
  curl -X POST -k -u elastic:"$ELASTIC_PASSWORD" "https://localhost:9200/_security/user/kibana_system/_password" -H "Content-Type: application/json" -d"
  {
    \"password\" : \"$KIBANA_SYSTEM_PASSWORD\"
  }"
  printf "\n====== Kibana system user password updated ======\n\n"

  printf "\n====== Creating kibana_user_role... ======\n\n"
  curl -X POST -k -u elastic:"$ELASTIC_PASSWORD" "https://localhost:9200/_security/role/kibana_user_role" -H "Content-Type: application/json" -d'
  {
    "cluster": ["monitor", "manage_index_templates", "read_ilm", "all"],
    "indices": [
      {
        "names": ["k8s_*", "k8s_default", ".kibana*"],
        "privileges": ["read", "view_index_metadata", "monitor", "manage", "all"]
      }
    ]
  }'
  printf "\n====== kibana_user_role created ======\n\n"

  printf "\n====== Creating kibana_user... ======\n\n"
  curl -X POST -k -u elastic:"$ELASTIC_PASSWORD" "https://localhost:9200/_security/user/kibana_user" -H "Content-Type: application/json" -d"
  {
    \"password\" : \"$KIBANA_PASSWORD\",
    \"roles\" : [ \"kibana_admin\", \"kibana_user_role\" ],
    \"full_name\" : \"Kibana User\"
  }"
  printf "\n====== Kibana user created ======\n\n"

  printf "\n====== Verifying users... ======\n\n"
  verify_entity "user" "logstash"
  verify_entity "user" "kibana_system"
  verify_entity "user" "kibana_user"

  printf "\n====== Verifying roles... ======\n\n"
  verify_entity "role" "logstash_writer"
  verify_entity "role" "kibana_user_role"

  printf "\n====== Listing all roles... ======\n\n"
  curl -s -X GET -k -u elastic:"$ELASTIC_PASSWORD" "https://localhost:9200/_security/role"

  printf "\n\n====== Verification completed ======\n\n"

  printf "\n================== Elasticsearch initialization completed ==================\n"

} 2>&1 | tee -a $LOG_FILE
