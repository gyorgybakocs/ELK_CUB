ARG ELK_VERSION=8.0.0
FROM registry.default.svc.cluster.local:5000/elk/elastic-elk:${ELK_VERSION}
ARG ELK_VERSION
ARG ELASTIC_PASSWORD
ARG LOGSTASH_PASSWORD
ARG KIBANA_SYSTEM_PASSWORD
ARG KIBANA_PASSWORD
ARG ELASTIC_CLUSTER_NAME
ARG ELASTIC_NODE_NAME
ARG ELASTIC_P12
ARG ELASTIC_TRUST_P12
ARG KEYSTORE_PASSWORD

# Switch to root to perform operations that require elevated permissions
USER root

# Create a logfile with correct permissions
RUN mkdir -p /usr/share/elasticsearch/logs && \
    touch /usr/share/elasticsearch/logs/elasticsearch.log && \
    chown elasticsearch:elasticsearch /usr/share/elasticsearch/logs/elasticsearch.log && \
    chmod 644 /usr/share/elasticsearch/logs/elasticsearch.log

# Create necessary directories
RUN mkdir -p /usr/share/elasticsearch/config/certs && \
    chown -R elasticsearch:elasticsearch /usr/share/elasticsearch/config/certs

# Copy bash files
COPY docker/elasticsearch/build/scripts/build.sh \
     docker/elasticsearch/build/scripts/es_build.sh \
     docker/elasticsearch/build/scripts/generate_keystore.sh \
     docker/scripts/verify.sh \
     /usr/local/bin/
# Set correct ownership and permissions
ARG SCRIPTS="build.sh es_build.sh generate_keystore.sh verify.sh"
RUN for script in $SCRIPTS; do \
        chmod +x /usr/local/bin/$script; \
    done

# Copy certificates
COPY docker/certificates/elasticsearch/* /usr/share/elasticsearch/config/certs/
# Set correct ownership and permissions
RUN chown -R elasticsearch:elasticsearch /usr/share/elasticsearch/config/certs && \
    chmod 700 /usr/share/elasticsearch/config/certs && \
    chmod 644 /usr/share/elasticsearch/config/certs/*.crt && \
    chmod 600 /usr/share/elasticsearch/config/certs/*.key /usr/share/elasticsearch/config/certs/*.p12

# Copy configuration files
COPY --chown=elasticsearch:elasticsearch docker/elasticsearch/build/config/elasticsearch.yml /usr/share/elasticsearch/config/elasticsearch.yml
# Set correct ownership and permissions
RUN chmod 644 /usr/share/elasticsearch/config/*.yml

# Run the generation script
RUN /usr/local/bin/build.sh

# Switch back to the elasticsearch user
USER elasticsearch

