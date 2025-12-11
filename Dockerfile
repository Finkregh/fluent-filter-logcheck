# fluent-plugin-logcheck/Dockerfile

FROM fluent/fluentd:edge-debian
USER root

# Environment variable for additional gem installation
# ADDITIONAL_GEM_NAMES: comma-separated list of gem names to install normally
ARG ADDITIONAL_GEM_NAMES=""
ENV ADDITIONAL_GEM_NAMES=${ADDITIONAL_GEM_NAMES}

# provides logcheck rules in e.g. /etc/logcheck/ignore.d.server
RUN apt-get update && apt-get install -y logcheck-database && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copy the plugin source code
COPY ./ /tmp/fluent-plugin-logcheck
WORKDIR /tmp

# Build and install the fluent-plugin-logcheck
RUN mkdir -p /etc/fluent/conf.d /etc/fluent/logcheck \
    && cd ./fluent-plugin-logcheck \
    && gem build fluent-plugin-logcheck.gemspec \
    && fluent-gem install fluent-plugin-logcheck-*.gem \
    && cd .. \
    && rm -rf ./fluent-plugin-logcheck \
    && chown -R fluent:fluent /etc/fluent \
    && fluent-gem search --local fluent.\* \
    && fluentd -vv -c /dev/null --dry-run

# Copy custom entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

WORKDIR /

USER fluent

# Use custom entrypoint that handles additional gems
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
