FROM alpine:latest

MAINTAINER Psiphon Inc. <info@psiphon.ca>
LABEL Description="Alpine Linux based Psiphon Tunnel-Core Server" Vendor="Psiphon Inc." Version="1.0"

RUN apk add --update \
      bash \
      ca-certificates \
    && rm -rf /var/cache/apk/*

RUN mkdir -p /opt/psiphon

ADD ["psiphond", "psiphond.config", "/opt/psiphon/"]

EXPOSE 22
EXPOSE 53
EXPOSE 443
EXPOSE 80

WORKDIR /opt/psiphon

ENTRYPOINT ["./psiphond", "--config", "psiphond.config", "run"]
