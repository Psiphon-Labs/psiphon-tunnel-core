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
ENV GOVERSION=go1.17.8 GOROOT=/usr/local/go GOPATH=/go PATH=$PATH:/usr/local/go/bin:/go/bin CGO_ENABLED=1

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

# Install Pinned Gomobile
#  - Ordered last to allow use of previously cached layers when changing revisions
ENV GOMOBILE_PINNED_REV=c4d780faeb85123ee32b88e84fd022739ed8c124
RUN mkdir -p $GOPATH/pkg/gomobile/dl \
  && cd $GOPATH/pkg/gomobile/dl \
  && curl -O https://dl.google.com/go/mobile/gomobile-ndk-r10e-linux-x86_64.tar.gz \
  && curl -O https://dl.google.com/go/mobile/gomobile-openal-soft-1.16.0.1.tar.gz \
  && mkdir -p $GOPATH/src/golang.org/x \
  && cd $GOPATH/src/golang.org/x \
  && git clone https://github.com/golang/mobile \
  && cd mobile \
  && git checkout -b pinned $GOMOBILE_PINNED_REV \
  && git format-patch --stdout -1 e6f31964531b3d6b76d334ba0d313b64c9687146 | git apply \
  && mv ./cmd/gomobile/build.go ./cmd/gomobile/build.go.orig \
  && sed -e 's/"-tags="+strconv.Quote(strings.Join(ctx.BuildTags, ",")),/"-tags",strings.Join(ctx.BuildTags, " "),/g' ./cmd/gomobile/build.go.orig > ./cmd/gomobile/build.go \
  && mv ./cmd/gomobile/build.go ./cmd/gomobile/build.go.orig \
  && sed -e 's/"strconv"//g' ./cmd/gomobile/build.go.orig > ./cmd/gomobile/build.go \
  && echo "master: $(git rev-parse master)\npinned: $(git rev-parse pinned)" | tee $GOROOT/MOBILE \
  && GO111MODULE=off go install golang.org/x/mobile/cmd/gomobile \
  && gomobile init -v

WORKDIR $GOPATH/src
