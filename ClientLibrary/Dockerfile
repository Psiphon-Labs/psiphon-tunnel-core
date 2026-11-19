# Dockerfile to build the Psiphon Client Library for multiple platforms.
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
    python \
    unzip \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Install Go.
# NOTE: Go 1.10+ is required to build c-shared for windows (https://github.com/golang/go/commit/bb0bfd002ada7e3eb9198d4287b32c2fed6e8da6)
ENV GOVERSION=go1.26.10 GOROOT=/usr/local/go GOPATH=/go PATH=$PATH:/usr/local/go/bin:/go/bin CGO_ENABLED=1
ENV GOSHA256=ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5

RUN curl -fL https://go.dev/dl/$GOVERSION.linux-amd64.tar.gz -o /tmp/go.tar.gz \
   && echo "$GOSHA256  /tmp/go.tar.gz" | sha256sum -c - \
   && tar -C /usr/local -xzf /tmp/go.tar.gz \
   && rm /tmp/go.tar.gz \
   && echo $GOVERSION > $GOROOT/VERSION

# Setup Android Environment.
ENV ANDROID_NDK_VERSION=r22b
ENV ANDROID_NDK_SHA256=ac3a0421e76f71dd330d0cd55f9d99b9ac864c4c034fc67e0d671d022d4e806b
ENV ANDROID_NDK_TOOLCHAIN_ROOT=/android-ndk-toolchain

# Setup Android NDK
RUN cd /tmp \
  && curl -fL https://dl.google.com/android/repository/android-ndk-${ANDROID_NDK_VERSION}-linux-x86_64.zip -o /tmp/android-ndk.zip \
  && echo "$ANDROID_NDK_SHA256  /tmp/android-ndk.zip" | sha256sum -c - \
  && unzip /tmp/android-ndk.zip -d / \
  && mkdir -p /android-ndk-toolchain \
  && /android-ndk-${ANDROID_NDK_VERSION}/build/tools/make_standalone_toolchain.py --arch arm --install-dir /android-ndk-toolchain/arm \
  && /android-ndk-${ANDROID_NDK_VERSION}/build/tools/make_standalone_toolchain.py --arch arm64 --install-dir /android-ndk-toolchain/arm64

WORKDIR $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/ClientLibrary
