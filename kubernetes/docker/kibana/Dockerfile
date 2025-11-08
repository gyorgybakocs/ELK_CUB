ARG ELK_VERSION=8.0.0
FROM registry.default.svc.cluster.local:5000/elk/kibana-elk:${ELK_VERSION}
ARG ELK_VERSION

# Switch to root to perform operations that require elevated permissions
USER root

# Create a logfile with correct permissions
RUN mkdir -p /usr/share/kibana/logs && \
    touch /usr/share/kibana/logs/kibana.log && \
    chown kibana:kibana /usr/share/kibana/logs/kibana.log && \
    chmod 644 /usr/share/kibana/logs/kibana.log

# Create necessary directories
RUN mkdir -p /usr/share/kibana/config/certs && \
    chown -R kibana:kibana /usr/share/kibana/config/certs

# Copy bash files
COPY docker/kibana/build/scripts/build.sh /usr/local/bin/
# Set correct ownership and permissions
RUN chmod +x /usr/local/bin/build.sh

# Copy certificates
COPY docker/certificates/kibana/* /usr/share/kibana/config/certs/
# Set correct ownership and permissions
RUN chown -R kibana:kibana /usr/share/kibana/config/certs && \
    chmod 700 /usr/share/kibana/config/certs && \
    chmod 644 /usr/share/kibana/config/certs/*.crt && \
    chmod 600 /usr/share/kibana/config/certs/*.key /usr/share/kibana/config/certs/*.p12

# Copy configuration files
COPY docker/kibana/build/config/kibana.yml /usr/share/kibana/config/kibana.yml
RUN chown -R kibana:kibana /usr/share/kibana/config && \
    chmod 644 /usr/share/kibana/config/*.yml

# Run the generation script
RUN /usr/local/bin/build.sh

# Switch back to the kibana user
USER kibana
