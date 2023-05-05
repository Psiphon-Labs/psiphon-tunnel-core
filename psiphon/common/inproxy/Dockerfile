# docker build --no-cache=true -t psiphon-inproxy-test .
#
# docker run \
#   --platform=linux/amd64 \
#   --user "$(id -u):$(id -g)" \ [maybe omit this line]
#   --rm \
#   -v $(go env GOCACHE):/.cache/go-build \
#   -v $(go env GOMODCACHE):/go/pkg/mod \
#   -v $PWD:/go/src/inproxy \
#   psiphon-inproxy-test \
#   /bin/bash -c 'PION_LOG_TRACE=all go test -v -timeout 30s -run TestInProxy'

FROM --platform=linux/amd64 ubuntu:18.04

# Install system-level dependencies.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    pkg-config \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Install Go.
ENV GOVERSION=go1.19.2 GOROOT=/usr/local/go GOPATH=/go PATH=$PATH:/usr/local/go/bin:/go/bin CGO_ENABLED=1

RUN curl -L https://storage.googleapis.com/golang/$GOVERSION.linux-amd64.tar.gz -o /tmp/go.tar.gz \
   && tar -C /usr/local -xzf /tmp/go.tar.gz \
   && rm /tmp/go.tar.gz \
   && echo $GOVERSION > $GOROOT/VERSION

WORKDIR /go/src/inproxy
