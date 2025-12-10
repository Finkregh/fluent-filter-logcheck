# fluentd/Dockerfile

FROM fluent/fluentd:edge-debian
USER root

COPY ./ /tmp/fluent-plugin-logcheck
WORKDIR /tmp
# RUN ls -la /tmp/fluent-plugin-logcheck
RUN mkdir -p /etc/fluent/conf.d /etc/fluent/logcheck \
    && cp -a ./fluent-plugin-logcheck/test/container-files/* /etc/fluent/logcheck/ \
    && cd ./fluent-plugin-logcheck \
    && gem build fluent-plugin-logcheck.gemspec \
    && fluent-gem install fluent-plugin-logcheck-*.gem \
    && cd .. \
    && rm -rf ./fluent-plugin-logcheck \
    && chown -R fluent:fluent /etc/fluent \
    && fluent-gem search --local fluent.\* \
    && fluentd -vv --dry-run -c /etc/fluent/logcheck/fluentd-test.conf
    # && ls -la /usr/local/bundle/gems/fluent-plugin-logcheck-0.1.0/

WORKDIR /

USER fluent
