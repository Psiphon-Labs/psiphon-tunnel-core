# Dockerfile to build an image with the local version of psiphon-tunnel-core.
#
# See README.md for usage instructions.

FROM ubuntu:15.04

ENV GOVERSION=go1.5.3

# Install system-level dependencies.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get -y install build-essential curl git mercurial upx gcc-mingw-w64-i686 gcc-mingw-w64-x86-64 mingw-w64 gcc-multilib pkg-config

# Install Go.
ENV GOROOT=/usr/local/go GOPATH=/go
ENV PATH=$PATH:$GOROOT/bin:$GOPATH/bin

RUN curl -L https://storage.googleapis.com/golang/$GOVERSION.linux-amd64.tar.gz -o /tmp/go.tar.gz && \
  tar -C /usr/local -xzf /tmp/go.tar.gz && \
  rm /tmp/go.tar.gz && \
  echo $GOVERSION > $GOROOT/VERSION

ENV CGO_ENABLED=1

# Get go dependencies
RUN go get github.com/mitchellh/gox && go get github.com/pwaller/goupx

# Build static OpenSSL libray
ENV OPENSSL_VERSION=1.0.1p
ENV PKG_CONFIG_PATH=/tmp/openssl/openssl-$OPENSSL_VERSION

RUN curl -L https://github.com/Psiphon-Labs/psiphon-tunnel-core/raw/master/openssl/openssl-$OPENSSL_VERSION.tar.gz -o /tmp/openssl.tar.gz && \
      mkdir -p /tmp/openssl && tar -C /tmp/openssl -xzf /tmp/openssl.tar.gz && rm /tmp/openssl.tar.gz
RUN cd $PKG_CONFIG_PATH && ./Configure --cross-compile-prefix=i686-w64-mingw32- mingw no-shared no-ssl2 no-ssl3 no-comp no-hw no-md2 no-md4 no-rc2 no-rc5 no-krb5 no-ripemd160 no-idea no-gost no-camellia no-seed no-3des no-heartbeats && make depend && make

WORKDIR $GOPATH/src
