# Dockerfile to build an image with the local version of psiphon-tunnel-core.
#
# See README.md for usage instructions.

FROM debian:testing

ENV GOVERSION=go1.4

# Install system-level dependencies.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
  apt-get -y install build-essential python-software-properties bzip2 unzip curl \
    git subversion mercurial bzr \
    upx gcc-mingw-w64-i686 gcc-mingw-w64-x86-64 gcc-multilib

# Install Go.
ENV GOROOT=/go \
  GOPATH=/
ENV PATH=$PATH:$GOROOT/bin
RUN echo "INSTALLING GO" && \
  curl -L https://github.com/golang/go/archive/$GOVERSION.zip -o /tmp/go.zip && \
  unzip /tmp/go.zip && \
  rm /tmp/go.zip && \
  mv /go-$GOVERSION $GOROOT && \
  echo $GOVERSION > $GOROOT/VERSION && \
  cd $GOROOT/src && \
  ./all.bash

ENV CGO_ENABLED=1
RUN go get github.com/mitchellh/gox && \
  go get github.com/inconshreveable/gonative && \
  mkdir -p /usr/local/gonative && \
  cd /usr/local/gonative && \
  gonative build
ENV PATH=/usr/local/gonative/go/bin:$PATH

WORKDIR $GOPATH/src
