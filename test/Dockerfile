# fluentd/Dockerfile

FROM fluent/fluentd:edge-debian
USER root

COPY ./ /tmp/fluent-plugin-logcheck
WORKDIR /tmp
RUN ls -la /tmp/fluent-plugin-logcheck
RUN mkdir -p /etc/fluent/conf.d \
    && mkdir -p /etc/fluent/logcheck \
    && cp -a ./fluent-plugin-logcheck/test/container-files/* /etc/fluent/logcheck/ \
    && gem build ./fluent-plugin-logcheck/fluent-plugin-logcheck.gemspec \
    && fluent-gem install fluent-plugin-logcheck-*.gem \
    && rm -rf ./fluent-plugin-logcheck \
    && chown -R fluent:fluent /etc/fluent \
    && fluent-gem search --local fluent.\* \
    && fluentd -vv --dry-run -c /dev/null

WORKDIR /

USER fluent
