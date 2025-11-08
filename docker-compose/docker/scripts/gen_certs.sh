#!/bin/bash
set -e

echo "KEYSTORE_PASSWORD=${KEYSTORE_PASSWORD}"
echo "ELASTIC_PASSWORD=${ELASTIC_PASSWORD}"
echo "ELASTIC_INTERNAL=${ELASTIC_INTERNAL}"
echo "ELASTICSEARCH_HOST=${ELASTICSEARCH_HOST}"

CONTAINER_NAME="cert-gen-container"
CERT_DIR_ON_HOST="docker/certificates/dev"
CERT_DIR_IN_CONTAINER="/certs"

SCRIPTS_DIR_ON_HOST="docker/scripts"
SCRIPTS_DIR_IN_CONTAINER="/scripts"

if [ "$(docker ps -aq -f name=$CONTAINER_NAME)" ]; then
    echo "==== Removing existing container: $CONTAINER_NAME ===="
    docker rm -f $CONTAINER_NAME
fi

echo "==== Starting temporary Docker container for certificate generation ===="
docker run --rm -d --name $CONTAINER_NAME \
    -v "$(pwd)/$CERT_DIR_ON_HOST:$CERT_DIR_IN_CONTAINER" \
    -v "$(pwd)/$SCRIPTS_DIR_ON_HOST:$SCRIPTS_DIR_IN_CONTAINER" \
    alpine:latest sleep infinity

echo "==== Installing dependencies inside the container ===="
docker exec -it $CONTAINER_NAME sh -c "apk add --no-cache bash openssl openjdk17 curl sudo"

echo "==== Running certificate generation script inside the container ===="
docker exec -it -e KEYSTORE_PASSWORD="${KEYSTORE_PASSWORD}" \
    $CONTAINER_NAME /bin/bash -c "sudo /scripts/build.sh ${KEYSTORE_PASSWORD} ${ELASTIC_PASSWORD} ${ELASTIC_INTERNAL} ${ELASTICSEARCH_HOST}"

echo "==== Stopping and removing the temporary container ===="
docker stop $CONTAINER_NAME
