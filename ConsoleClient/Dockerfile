# Dockerfile to build an image with the local version of psiphon-tunnel-core.
#
# See README.md for usage instructions.

FROM ubuntu:15.04

ENV GOVERSION=go1.5

# Install system-level dependencies.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get -y install build-essential curl git mercurial upx gcc-mingw-w64-i686 gcc-mingw-w64-x86-64 gcc-multilib

# Install Go.
ENV GOROOT=/usr/local/go GOPATH=/go
ENV PATH=$PATH:$GOROOT/bin:$GOPATH/bin

RUN curl -L https://storage.googleapis.com/golang/$GOVERSION.linux-amd64.tar.gz -o /tmp/go.tar.gz && \
  tar -C /usr/local -xzf /tmp/go.tar.gz && \
  rm /tmp/go.tar.gz && \
  echo $GOVERSION > $GOROOT/VERSION

ENV CGO_ENABLED=1

RUN go get github.com/mitchellh/gox && go get github.com/pwaller/goupx

WORKDIR $GOPATH/src
