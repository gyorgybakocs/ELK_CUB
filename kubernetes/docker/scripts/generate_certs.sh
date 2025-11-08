#!/bin/bash
set -e

download_lets_encrypt_certs() {
    printf "Downloading Let's Encrypt certificates...\n"
    mkdir -p "$CERT_DIR/temp"
    curl -s -o "$CERT_DIR/temp/isrg-root-x1.pem" https://letsencrypt.org/certs/isrg-root-x1.pem
    curl -s -o "$CERT_DIR/temp/lets-encrypt-e5.pem" https://letsencrypt.org/certs/e5.pem
    printf "Let's Encrypt certificates downloaded.\n"
}

generate_cert() {
    local component=$1
    local output_dir=$2
    printf "Generating certificate for %s...\n" "$component"
    openssl req -newkey rsa:2048 -nodes -subj "/CN=$component" -keyout "$output_dir/$component.key" -out "$output_dir/$component.csr"

    if [ "$component" = "elasticsearch" ]; then
        cat > "$output_dir/$component.cnf" << EOF
[req]
req_extensions = v3_req
[v3_req]
subjectAltName = @alt_names
[alt_names]
IP.1 = $ELASTIC_INTERNAL
DNS.1 = $ELASTICSEARCH_HOST
DNS.1 = elasticsearch
DNS.2 = localhost
EOF
        openssl x509 -req -in "$output_dir/$component.csr" -CA "$CERT_DIR/common/ca.crt" -CAkey "$CERT_DIR/common/ca.key" -CAcreateserial -out "$output_dir/$component.crt" -days 365 -sha256 -extfile "$output_dir/$component.cnf" -extensions v3_req -passin pass:"$KEYSTORE_PASSWORD"
    else
        openssl x509 -req -in "$output_dir/$component.csr" -CA "$CERT_DIR/common/ca.crt" -CAkey "$CERT_DIR/common/ca.key" -CAcreateserial -out "$output_dir/$component.crt" -days 365 -sha256 -passin pass:"$KEYSTORE_PASSWORD"
    fi
    openssl pkcs12 -export -in "$output_dir/$component.crt" -inkey "$output_dir/$component.key" -out "$output_dir/$component.p12" -name "$component" -CAfile "$CERT_DIR/common/ca.crt" -caname root -passout pass:"$KEYSTORE_PASSWORD"
    rm "$output_dir/$component.csr"
    cp "$CERT_DIR/common/ca.crt" "$output_dir/"
}

generate_cacert() {
    printf "Generating root CA... %s \n" "$KEYSTORE_PASSWORD"
    openssl genrsa -aes256 -passout pass:"$KEYSTORE_PASSWORD" -out "$CERT_DIR/common/ca.key" 2048
    openssl req -x509 -new -key "$CERT_DIR/common/ca.key" -sha256 -days 1024 -out "$CERT_DIR/common/ca.crt" -subj "/CN=Elastic-Stack-CA" -passin pass:"$KEYSTORE_PASSWORD"

    cat "$CERT_DIR/temp/lets-encrypt-e5.pem" >> "$CERT_DIR/common/ca.crt"
    cat "$CERT_DIR/temp/isrg-root-x1.pem" >> "$CERT_DIR/common/ca.crt"
    printf "Let's Encrypt certificates added to CA bundle.\n"
}

generate_truststore() {
    printf "Creating truststore...\n"
    keytool -import -file "$CERT_DIR/common/ca.crt" -alias CA -keystore "$CERT_DIR/elasticsearch/elasticsearch-truststore.p12" -storetype PKCS12 -storepass "$KEYSTORE_PASSWORD" -noprompt
}
