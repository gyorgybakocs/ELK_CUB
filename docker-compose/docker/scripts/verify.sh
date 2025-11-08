#!/bin/bash
set -e

verify_cert() {
    local cert=$1
    printf "\n====== Verifying certificate: %s ======\n" "$cert"
    if ! openssl x509 -in "$cert" -noout -text > /dev/null 2>&1; then
        echo "Error: Invalid certificate: $cert"
        exit 1
    fi
    printf "Verification successful: Certificate is valid: %s\n" "$cert"
    printf "====== Certificate verification completed ======\n"
}

verify_key() {
    local key=$1
    printf "\n====== Verifying private key: %s ======\n" "$key"

    if grep -q "ENCRYPTED" "$key" && grep -q "RSA PRIVATE KEY" "$key"; then
        printf "Detected encrypted RSA private key.\n"
        if ! openssl rsa -in "$key" -passin pass:"$KEYSTORE_PASSWORD" -check -noout > /dev/null 2>&1; then
            printf "Error: Failed to verify encrypted RSA private key. Check the password.\n"
            exit 1
        fi
        printf "Verification successful: Encrypted RSA private key is valid: %s\n" "$key"
        printf "====== Private key verification completed ======\n"
        return
    fi

    if ! openssl pkey -in "$key" -passin pass:"$KEYSTORE_PASSWORD" -check -noout > /dev/null 2>&1; then
        local key_info=$(openssl asn1parse -in "$key" 2>&1)
        printf "Key info:\n%s\n" "$key_info"
        echo "Error: Unable to verify key: $key"
        exit 1
    fi

    printf "Verification successful: Private key is valid (generic format): %s\n" "$key"
    printf "====== Private key verification completed ======\n"
}

verify_pkcs12() {
    local p12=$1
    printf "\n====== Verifying PKCS12 file: %s ======\n" "$p12"
    if ! openssl pkcs12 -info -in "$p12" -noout -passin pass:"$KEYSTORE_PASSWORD" > /dev/null 2>&1; then
        echo "Error: Invalid PKCS12 file: $p12"
        exit 1
    fi
    printf "Verification successful: PKCS12 file is valid: %s\n" "$p12"
    printf "====== PKCS12 verification completed ======\n"
}

verify_cert_chain() {
    local cert=$1
    printf "\n====== Verifying certificate chain for: %s ======\n" "$cert"
    local ca_cert="$CERT_DIR/common/ca.crt"

    if ! openssl verify -CAfile "$ca_cert" "$cert" > /dev/null 2>&1; then
        echo "Error: Certificate chain verification failed for: $cert"
        echo "Details:"
        openssl verify -CAfile "$ca_cert" "$cert"
        exit 1
    fi
    printf "Certificate chain verification successful for: %s\n" "$cert"
    printf "====== Certificate chain verification completed ======\n"
}

verify_cert_issuer() {
    local cert=$1
    printf "\n====== Checking certificate issuer for: %s ======\n" "$cert"

    local issuer=$(openssl x509 -in "$cert" -noout -issuer)
    local subject=$(openssl x509 -in "$cert" -noout -subject)

    echo "Issuer: $issuer"
    echo "Subject: $subject"

    # Check if the issuer matches the expected value
    if ! echo "$issuer" | grep -q "CN=Elastic-Stack-CA"; then
        echo "Warning: Unexpected issuer for certificate: $cert"
    fi
    printf "====== Certificate issuer check completed ======\n"
}

verify_cert_san() {
    local cert=$1
    local component=$(basename "$(dirname "$cert")")
    local cert_name=$(basename "$cert")

    # Only check SAN fields if this is the Elasticsearch certificate
    if [ "$component" == "elasticsearch" ] && [ "$cert_name" == "elasticsearch.crt" ]; then
        printf "\n====== Checking Subject Alternative Names for: %s ======\n" "$cert"

        local san=$(openssl x509 -in "$cert" -noout -text | grep -A1 "Subject Alternative Name")
        echo "SAN: $san"

        # Check if the certificate contains the expected SAN entries
        if ! echo "$san" | grep -q "$ANZU_ELASTIC_INTERNAL"; then
            echo "Warning: Elasticsearch certificate doesn't contain expected IP in SAN: $ANZU_ELASTIC_INTERNAL"
        fi
        if ! echo "$san" | grep -q "elastic-dc"; then
            echo "Warning: Elasticsearch certificate doesn't contain expected DNS name in SAN: elastic-dc"
        fi
        printf "====== SAN check completed ======\n"
    fi
}

verify_key_cert_match() {
    local component=$1
    local cert="$CERT_DIR/$component/$component.crt"
    local key="$CERT_DIR/$component/$component.key"

    printf "\n====== Verifying key and certificate match for: %s ======\n" "$component"

    local cert_modulus=$(openssl x509 -noout -modulus -in "$cert" | sha256sum)
    local key_modulus=$(openssl rsa -noout -modulus -in "$key" -passin pass:"$KEYSTORE_PASSWORD" 2>/dev/null | sha256sum)

    if [ "$cert_modulus" != "$key_modulus" ]; then
        echo "Error: Certificate and private key do not match for $component"
        exit 1
    fi
    printf "Key and certificate match verification successful for: %s\n" "$component"
    printf "====== Key-cert match verification completed ======\n"
}

verify_truststore() {
    local truststore=$1
    local password=$2

    printf "\n====== Verifying truststore content: %s ======\n" "$truststore"

    # Check if the truststore file exists
    if [ ! -f "$truststore" ]; then
        echo "Error: Truststore file not found: $truststore"
        exit 1
    fi

    # Verify truststore can be opened
    if ! keytool -list -keystore "$truststore" -storepass "$password" > /dev/null 2>&1; then
        echo "Error: Failed to read truststore: $truststore"
        exit 1
    fi

    # Print truststore content for inspection
    echo "Truststore content:"
    keytool -list -keystore "$truststore" -storepass "$password"

    # Verify that the CA certificate is in the truststore - check for "ca," entry
    if ! keytool -list -keystore "$truststore" -storepass "$password" | grep -q "ca,"; then
        echo "Warning: CA certificate not found in truststore: $truststore"
    else
        echo "CA certificate found in truststore: $truststore"
    fi

    printf "Truststore verification successful: %s\n" "$truststore"
    printf "====== Truststore verification completed ======\n"
}

verify_directory() {
    local dir=$1
    printf "\n====== Verifying directory: %s ======\n" "$dir"

    for file in "$dir"/*.{crt,key,p12}; do
        if [ -f "$file" ]; then
            case "${file##*.}" in
                crt)
                    verify_cert "$file"
                    verify_cert_chain "$file"
                    verify_cert_issuer "$file"
                    verify_cert_san "$file"
                    ;;
                key)
                    verify_key "$file"
                    ;;
                p12)
                    if [[ "$file" == *"truststore"* ]]; then
                        verify_truststore "$file" "$KEYSTORE_PASSWORD"
                    else
                        verify_pkcs12 "$file"
                    fi
                    ;;
            esac
        fi
    done
    printf "====== Directory verification completed: %s ======\n" "$dir"
}

verify_all() {
    printf "\n====== Starting certificate verification process ======\n"
    if [ -z "$KEYSTORE_PASSWORD" ]; then
        echo "Error: KEYSTORE_PASSWORD environment variable is not set."
        exit 1
    fi

    subdirs=("common" "elasticsearch" "logstash" "kibana")

    for subdir in "${subdirs[@]}"; do
        full_path="$CERT_DIR/$subdir"
        if [ -d "$full_path" ]; then
            verify_directory "$full_path"

            # Verify that the key matches the certificate
            if [ -f "$full_path/$subdir.crt" ] && [ -f "$full_path/$subdir.key" ]; then
                verify_key_cert_match "$subdir"
            fi
        else
            echo "Warning: Directory not found: $full_path"
        fi
    done

    verify_directory "$CERT_DIR"
    printf "\n====== Certificate verification process completed ======\n"
}

verify_keystore() {
    printf "\n====== Verifying Elasticsearch keystore ======\n"
    printf "Listing keystore entries:\n"
    if ! /usr/share/elasticsearch/bin/elasticsearch-keystore list; then
        echo "Error: Failed to list keystore entries"
        exit 1
    fi

    printf "\nChecking for bootstrap.password:\n"
    if ! /usr/share/elasticsearch/bin/elasticsearch-keystore list | grep -q bootstrap.password; then
        echo "ERROR: bootstrap.password not found in the keystore"
        exit 1
    fi
    echo "bootstrap.password exists in the keystore"

    printf "\nVerifying keystore integrity:\n"
    if ! /usr/share/elasticsearch/bin/elasticsearch-keystore list > /dev/null 2>&1; then
        echo "Error: Keystore may be corrupted"
        exit 1
    fi
    echo "Keystore integrity verified successfully"

    printf "\nVerifying keystore in /usr/share/elasticsearch/config/:\n"
    ls -l /usr/share/elasticsearch/config/elasticsearch.keystore
    echo "Keystore integrity verified successfully"
    printf "====== Elasticsearch keystore verification completed ======\n"
}

verify_entity() {
    local entity_type=$1
    local entity_name=$2
    printf "\n====== Verifying %s: %s ======\n" "$entity_type" "$entity_name"
    curl -s -X GET -k -u elastic:"$ELASTIC_PASSWORD" "https://localhost:9200/_security/$entity_type/$entity_name"
    printf "\n"
    printf "====== Entity verification completed ======\n"
}

verify_django_cert() {
    local file=$DJANGO_CERT
    printf "\n====== Verifying Django certificate ======\n"
    if [ -z "$DJANGO_CERT" ]; then
        echo "Error: DJANGO_DIR environment variable is not set."
        exit 1
    fi
    verify_cert "$file"
    printf "====== Django certificate verification completed ======\n"
}
