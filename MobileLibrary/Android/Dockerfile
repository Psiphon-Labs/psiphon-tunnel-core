# Dockerfile to build an image with the local version of psiphon-tunnel-core.
#
# See README.md for usage instructions.

FROM ubuntu:18.04

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
ENV GOVERSION=go1.17.9 GOROOT=/usr/local/go GOPATH=/go PATH=$PATH:/usr/local/go/bin:/go/bin CGO_ENABLED=1

RUN curl -L https://storage.googleapis.com/golang/$GOVERSION.linux-amd64.tar.gz -o /tmp/go.tar.gz \
  && tar -C /usr/local -xzf /tmp/go.tar.gz \
  && rm /tmp/go.tar.gz \
  && echo $GOVERSION > $GOROOT/VERSION

# Setup Android Environment.
ENV ANDROID_NDK_ROOT=/android-ndk ANDROID_NDK_HOME=/android-ndk ANDROID_HOME=/android-sdk-linux

# Setup Android NDK.
RUN cd /tmp \
  && curl -L https://dl.google.com/android/repository/android-ndk-r23b-linux.zip -o /tmp/android-ndk-r23b-linux.zip \
  && cd /tmp \
  && unzip android-ndk-r23b-linux.zip \
  && mv /tmp/android-ndk-r23b /android-ndk

# Setup Android SDK.
RUN curl -L https://dl.google.com/android/android-sdk_r24.4.1-linux.tgz -o /tmp/android-sdk.tgz \
  && tar -C / -xzf /tmp/android-sdk.tgz \
  && rm /tmp/android-sdk.tgz \
  && (while true; do echo 'y'; sleep 2; done) | $ANDROID_HOME/tools/android update sdk --no-ui --filter platform,platform-tool,tool

# Install Pinned Gomobile.
# The sed operation patches gomobile, editing a command that assumes modules
ENV GOMOBILE_PINNED_REV=ce6a79cf6a13dd77095a6f8dbee5f39848fa7da1
RUN mkdir -p $GOPATH/pkg/gomobile/dl \
  && cd $GOPATH/pkg/gomobile/dl \
  && mkdir -p $GOPATH/src/golang.org/x \
  && cd $GOPATH/src/golang.org/x \
  && git clone https://github.com/golang/mobile \
  && cd mobile \
  && git checkout -b pinned $GOMOBILE_PINNED_REV \
  && mv ./cmd/gomobile/init.go ./cmd/gomobile/init.go.orig \
  && sed -e 's/golang.org\/x\/mobile\/cmd\/gobind@latest/golang.org\/x\/mobile\/cmd\/gobind/g' ./cmd/gomobile/init.go.orig > ./cmd/gomobile/init.go \
  && echo "master: $(git rev-parse master)\npinned: $(git rev-parse master)" | tee $GOROOT/MOBILE \
  && export GO111MODULE=off \
  && go get golang.org/x/mod/modfile \
  && go get golang.org/x/tools/go/packages\
  && go install golang.org/x/mobile/cmd/gomobile \
  && gomobile init -v

WORKDIR $GOPATH/src
