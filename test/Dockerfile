# fluentd/Dockerfile

FROM fluent/fluentd:edge-debian
USER root

COPY ./* /tmp/fluent-plugin-logcheck
RUN ["gem", "build", "/tmp/fluent-plugin-logcheck/fluent-plugin-logcheck.gemspec"]
RUN ["gem", "install", "/tmp/fluent-plugin-logcheck/fluent-plugin-logcheck-*.gem", "--no-document"]

COPY ./test/container-files/* /etc/fluent/logcheck/

USER fluent
