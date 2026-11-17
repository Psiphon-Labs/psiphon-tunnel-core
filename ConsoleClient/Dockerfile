# Dockerfile to build an image with the local version of psiphon-tunnel-core.
#
# See README.md for usage instructions.

FROM --platform=linux/amd64 ubuntu:18.04@sha256:152dc042452c496007f07ca9127571cb9c29697f42acbfad72324b2bb2e43c98

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
ENV GOVERSION=go1.26.10 GOROOT=/usr/local/go GOPATH=/go PATH=$PATH:/usr/local/go/bin:/go/bin CGO_ENABLED=1
ENV GOSHA256=ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5

RUN curl -fL https://go.dev/dl/$GOVERSION.linux-amd64.tar.gz -o /tmp/go.tar.gz \
   && echo "$GOSHA256  /tmp/go.tar.gz" | sha256sum -c - \
   && tar -C /usr/local -xzf /tmp/go.tar.gz \
   && rm /tmp/go.tar.gz \
   && echo $GOVERSION > $GOROOT/VERSION

WORKDIR $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/ConsoleClient
