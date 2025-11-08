ARG ELK_VERSION=8.0.0
FROM elk/kibana-elk:${ELK_VERSION}
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
COPY kibana/dev/scripts/build.sh /usr/local/bin/
# Set correct ownership and permissions
RUN chmod +x /usr/local/bin/build.sh

# Copy certificates
COPY certificates/dev/kibana/* /usr/share/kibana/config/certs/
# Set correct ownership and permissions
RUN chown -R kibana:kibana /usr/share/kibana/config/certs && \
    chmod 700 /usr/share/kibana/config/certs && \
    chmod 644 /usr/share/kibana/config/certs/*.crt && \
    chmod 600 /usr/share/kibana/config/certs/*.key /usr/share/kibana/config/certs/*.p12

# Copy configuration files
COPY kibana/dev/config/kibana.yml /usr/share/kibana/config/kibana.yml
RUN chown -R kibana:kibana /usr/share/kibana/config && \
    chmod 644 /usr/share/kibana/config/*.yml

## Set environment variables
#ENV KIBANA_CACERT=/usr/share/kibana/config/certs/ca.crt
#ENV KIBANA_P12=/usr/share/kibana/config/certs/kibana.p12

# Run the generation script
RUN /usr/local/bin/build.sh

# Switch back to the kibana user
USER kibana
