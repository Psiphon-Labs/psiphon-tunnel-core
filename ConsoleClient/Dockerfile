# Dockerfile to build an image with the local version of psiphon-tunnel-core.
#
# See README.md for usage instructions.

FROM ubuntu:latest

# Install system-level dependencies.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    gcc-mingw-w64-i686 \
    gcc-mingw-w64-x86-64 \
    gcc-multilib \
    git \
    mingw-w64 \
    mercurial \
    pkg-config \
    upx \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Install Go.
ENV GOVERSION=go1.6 GOROOT=/usr/local/go GOPATH=/go PATH=$PATH:/usr/local/go/bin:/go/bin CGO_ENABLED=1

RUN curl -L https://storage.googleapis.com/golang/$GOVERSION.linux-amd64.tar.gz -o /tmp/go.tar.gz \
   && tar -C /usr/local -xzf /tmp/go.tar.gz \
   && rm /tmp/go.tar.gz \
   && echo $GOVERSION > $GOROOT/VERSION

# Get external Go dependencies.
RUN go get github.com/mitchellh/gox \
    && go get github.com/pwaller/goupx

# Setup OpenSSL libray.
ENV OPENSSL_VERSION=1.0.1p
ENV PKG_CONFIG_PATH_32=/tmp/openssl/32/openssl-$OPENSSL_VERSION PKG_CONFIG_PATH_64=/tmp/openssl/64/openssl-$OPENSSL_VERSION

RUN mkdir -p /tmp/openssl/32 \
 && mkdir -p /tmp/openssl/64 \
 && curl -L https://github.com/Psiphon-Labs/psiphon-tunnel-core/raw/master/openssl/openssl-$OPENSSL_VERSION.tar.gz -o /tmp/openssl.tar.gz \
 && tar -C /tmp/openssl/32 -xzf /tmp/openssl.tar.gz \
 && tar -C /tmp/openssl/64 -xzf /tmp/openssl.tar.gz \
 && rm /tmp/openssl.tar.gz

RUN cd $PKG_CONFIG_PATH_32 \
  && ./Configure --cross-compile-prefix=i686-w64-mingw32- mingw \
    no-shared \
    no-ssl2 \
    no-ssl3 \
    no-comp \
    no-hw \
    no-md2 \
    no-md4 \
    no-rc2 \
    no-rc5 \
    no-krb5 \
    no-ripemd160 \
    no-idea \
    no-gost \
    no-camellia \
    no-seed \
    no-3des \
    no-heartbeats \
  && make depend \
  && make \
  && cd $PKG_CONFIG_PATH_64 \
  && ./Configure --cross-compile-prefix=x86_64-w64-mingw32- mingw64 \
    no-shared \
    no-ssl2 \
    no-ssl3 \
    no-comp \
    no-hw \
    no-md2 \
    no-md4 \
    no-rc2 \
    no-rc5 \
    no-krb5 \
    no-ripemd160 \
    no-idea \
    no-gost \
    no-camellia \
    no-seed \
    no-3des \
    no-heartbeats \
  && make depend \
  && make

WORKDIR $GOPATH/src
