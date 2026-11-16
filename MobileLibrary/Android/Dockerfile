# Dockerfile to build an image with the local version of psiphon-tunnel-core.
#
# See README.md for usage instructions.

FROM --platform=linux/amd64 ubuntu:18.04@sha256:152dc042452c496007f07ca9127571cb9c29697f42acbfad72324b2bb2e43c98

# Install system-level dependencies.
ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p /usr/share/man/man1 # fixes https://stackoverflow.com/a/69844974

RUN apt-get update -y && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    git \
    ca-certificates-java \
    openjdk-8-jdk \
    pkg-config \
    zip \
    unzip \
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

# Setup Android environment and install build tools.
ENV ANDROID_PLATFORM_VERSION=30 ANDROID_NDK_VERSION=23.1.7779620
ENV ANDROID_SDK_ROOT=/android-sdk-root-linux
ENV ANDROID_HOME=$ANDROID_SDK_ROOT
ENV ANDROID_NDK_HOME=$ANDROID_SDK_ROOT/ndk/$ANDROID_NDK_VERSION
ENV ANDROID_COMMAND_LINE_TOOLS_SHA256=d71f75333d79c9c6ef5c39d3456c6c58c613de30e6a751ea0dbd433e8f8b9cbf
RUN curl -fL https://dl.google.com/android/repository/commandlinetools-linux-8092744_latest.zip -o /tmp/commandlinetools-linux.zip \
  && echo "$ANDROID_COMMAND_LINE_TOOLS_SHA256  /tmp/commandlinetools-linux.zip" | sha256sum -c - \
  && mkdir -p $ANDROID_SDK_ROOT \
  && cd $ANDROID_SDK_ROOT \
  && mkdir cmdline-tools \
  && cd cmdline-tools \
  && unzip /tmp/commandlinetools-linux.zip \
  && mv cmdline-tools latest \
  && yes | $ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager --licenses \
  && $ANDROID_SDK_ROOT/cmdline-tools/latest/bin/sdkmanager --install "platforms;android-${ANDROID_PLATFORM_VERSION}" "ndk;${ANDROID_NDK_VERSION}"

# Install Gomobile from source at MobileLibrary/go-mobile
# The sed operation patches gomobile, editing a command that assumes modules
RUN mkdir -p $GOPATH/src/golang.org/x
COPY go-mobile $GOPATH/src/golang.org/x/mobile
RUN cd $GOPATH/src/golang.org/x/mobile \
  && mv ./cmd/gomobile/init.go ./cmd/gomobile/init.go.orig \
  && sed -e 's/golang.org\/x\/mobile\/cmd\/gobind@latest/golang.org\/x\/mobile\/cmd\/gobind/g' ./cmd/gomobile/init.go.orig > ./cmd/gomobile/init.go \
  && export GO111MODULE=off \
  && go install golang.org/x/mobile/cmd/gomobile \
  && gomobile init -v

WORKDIR $GOPATH/src
