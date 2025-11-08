ARG ELK_VERSION=8.0.0
FROM elk/logstash-elk:${ELK_VERSION}
ARG ELK_VERSION

# Switch to root to perform operations that require elevated permissions
USER root

# Create a logfile with correct permissions
RUN mkdir -p /usr/share/logstash/logs && \
    touch /usr/share/logstash/logs/logstash.log && \
    chown logstash:logstash /usr/share/logstash/logs/logstash.log && \
    chmod 644 /usr/share/logstash/logs/logstash.log

# Create necessary directories
RUN mkdir -p /usr/share/logstash/config/certs /etc/logstash/conf.d && \
    chown -R logstash:logstash /usr/share/logstash/config/certs /etc/logstash/conf.d

# Copy bash files
COPY logstash/dev/scripts/build.sh /usr/local/bin/
# Set correct ownership and permissions
RUN chmod +x /usr/local/bin/build.sh

# Copy certificates
COPY certificates/dev/logstash/* /usr/share/logstash/config/certs/
# Set correct ownership and permissions
RUN chown -R logstash:logstash /usr/share/logstash/config/certs && \
    chmod 700 /usr/share/logstash/config/certs && \
    chmod 644 /usr/share/logstash/config/certs/*.crt && \
    chmod 600 /usr/share/logstash/config/certs/*.key /usr/share/logstash/config/certs/*.p12

# Copy configuration files
COPY logstash/dev/config/* /usr/share/logstash/config/
COPY logstash/dev/config/conf/* /etc/logstash/conf.d/
# Set correct ownership and permissions
RUN chown -R logstash:logstash /usr/share/logstash/config /etc/logstash/conf.d && \
    chmod 644 /usr/share/logstash/config/*.yml \
              /usr/share/logstash/config/*.json \
              /etc/logstash/conf.d/*

# Run the generation script
RUN /usr/local/bin/build.sh

# Switch back to the logstash user
USER logstash
