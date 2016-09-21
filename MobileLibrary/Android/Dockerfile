# Dockerfile to build an image with the local version of psiphon-tunnel-core.
#
# See README.md for usage instructions.

FROM ubuntu:16.04

# Install system-level dependencies.
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    openjdk-8-jdk \
    pkg-config \
    zip \
    unzip \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*

# Install Go.
ENV GOVERSION=go1.7.1 GOROOT=/usr/local/go GOPATH=/go PATH=$PATH:/usr/local/go/bin:/go/bin CGO_ENABLED=1

RUN curl -L https://storage.googleapis.com/golang/$GOVERSION.linux-amd64.tar.gz -o /tmp/go.tar.gz \
  && tar -C /usr/local -xzf /tmp/go.tar.gz \
  && rm /tmp/go.tar.gz \
  && echo $GOVERSION > $GOROOT/VERSION

# Setup Android Environment.
ENV ANDROID_NDK_ROOT=/android-ndk ANDROID_HOME=/android-sdk-linux

# Setup Android NDK
RUN cd /tmp \
  && curl -L http://dl.google.com/android/ndk/android-ndk-r10e-linux-x86_64.bin -o /tmp/android-ndk.bin \
  && chmod a+x /tmp/android-ndk.bin \
  && /tmp/android-ndk.bin \
  && rm /tmp/android-ndk.bin \
  && ln -s $(find /tmp -type d -name 'android-ndk-*') /android-ndk

# Setup Android SDK.
RUN curl -L http://dl.google.com/android/android-sdk_r24.4.1-linux.tgz -o /tmp/android-sdk.tgz \
  && tar -C / -xzf /tmp/android-sdk.tgz \
  && rm /tmp/android-sdk.tgz \
  && (while true; do echo 'y'; sleep 2; done) | $ANDROID_HOME/tools/android update sdk --no-ui --filter platform,platform-tool,tool

# Setup OpenSSL libray.
ENV OPENSSL_VERSION=1.0.2h
ENV PKG_CONFIG_PATH=/tmp/openssl/openssl-$OPENSSL_VERSION
ENV CGO_CFLAGS="-I $PKG_CONFIG_PATH/include" CGO_LDFLAGS="-L $PKG_CONFIG_PATH -lssl -lcrypto"

RUN mkdir -p /tmp/openssl \
  && curl -L https://github.com/Psiphon-Labs/psiphon-tunnel-core/raw/master/openssl/openssl-$OPENSSL_VERSION.tar.gz -o /tmp/openssl.tar.gz \
  && tar -C /tmp/openssl -xzf /tmp/openssl.tar.gz \
  && rm /tmp/openssl.tar.gz \
  && curl -L https://github.com/Psiphon-Labs/psiphon-tunnel-core/raw/master/openssl/setenv-android.sh -o /tmp/setenv-android.sh \
  && /bin/bash -c "\
    source /tmp/setenv-android.sh \
    && cd /tmp/openssl/openssl-$OPENSSL_VERSION \
    && perl -pi -e 's/install: all install_docs install_sw/install: install_docs install_sw/g' Makefile.org \
    && ./config \
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
      --openssldir=./ssl \
    && perl -pi -e 's/-O3/-Os -mfloat-abi=softfp/g' Makefile \
    && make depend \
    && make all"

# Install Pinned Gomobile
#  - Ordered last to allow use of previously cached layers when changing revisions
ENV GOMOBILE_PINNED_REV=320ec40f6328971c405979b804e20d5f3c86770c
RUN mkdir -p $GOPATH/pkg/gomobile/dl \
  && cd $GOPATH/pkg/gomobile/dl \
  && curl -O https://dl.google.com/go/mobile/gomobile-ndk-r10e-linux-x86_64.tar.gz \
  && curl -O https://dl.google.com/go/mobile/gomobile-openal-soft-1.16.0.1.tar.gz \
  && mkdir -p $GOPATH/src/golang.org/x \
  && cd $GOPATH/src/golang.org/x \
  && git clone https://github.com/golang/mobile \
  && cd mobile \
  && git checkout -b pinned $GOMOBILE_PINNED_REV \
  && echo "master: $(git rev-parse master)\npinned: $(git rev-parse pinned)" | tee $GOROOT/MOBILE \
  && go install golang.org/x/mobile/cmd/gomobile \
  && gomobile init -v

WORKDIR $GOPATH/src
