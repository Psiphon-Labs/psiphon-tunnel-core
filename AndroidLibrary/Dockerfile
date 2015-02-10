# Dockerfile to build an image with the local version of psiphon-tunnel-core.
#
# See README.md for usage instructions.

FROM ubuntu:12.04

ENV GOVERSION=go1.4.1

# Install system-level dependencies.
ENV DEBIAN_FRONTEND=noninteractive
RUN echo "debconf shared/accepted-oracle-license-v1-1 select true" | debconf-set-selections && \
  echo "debconf shared/accepted-oracle-license-v1-1 seen true" | debconf-set-selections && \
  apt-get update && \
  apt-get -y install build-essential python-software-properties bzip2 unzip curl \
    git subversion mercurial bzr \
    libncurses5:i386 libstdc++6:i386 zlib1g:i386 && \
  add-apt-repository ppa:webupd8team/java && \
  apt-get update && \
  apt-get -y install oracle-java7-installer

# Install Ant.
RUN echo "INSTALLING ANT" && \
  curl -L https://archive.apache.org/dist/ant/binaries/apache-ant-1.9.4-bin.tar.gz | tar xz -C /usr/local
ENV ANT_HOME=/usr/local/apache-ant-1.9.4

# Install Android SDK.
ENV ANDROID_HOME=/usr/local/android-sdk-linux
RUN echo "INSTALLING ANDROID SDK" && \
  curl -L https://dl.google.com/android/android-sdk_r24.0.1-linux.tgz | tar xz -C /usr/local && \
  echo y | $ANDROID_HOME/tools/android update sdk --no-ui --all --filter build-tools-21.1.2 && \
  echo y | $ANDROID_HOME/tools/android update sdk --no-ui --all --filter platform-tools && \
  echo y | $ANDROID_HOME/tools/android update sdk --no-ui --all --filter android-21
  
# Install Android NDK.
ENV NDK_ROOT=/usr/local/android-ndk-r10d
RUN echo "INSTALLING ANDROID NDK" && \
  wget https://dl.google.com/android/ndk/android-ndk-r10d-linux-x86_64.bin && \
  chmod a+x android-ndk-r10d-linux-x86_64.bin && ./android-ndk-r10d-linux-x86_64.bin && \
  mv android-ndk-r10d /usr/local && \
  $NDK_ROOT/build/tools/make-standalone-toolchain.sh --platform=android-9 --arch=arm --install-dir=$NDK_ROOT --system=linux-x86_64

# Install Gradle
# : android-gradle compatibility
#   http://tools.android.com/tech-docs/new-build-system/version-compatibility
RUN echo "INSTALLING GRADLE" && \
  curl -L https://services.gradle.org/distributions/gradle-2.2.1-all.zip -o /tmp/gradle-2.2.1-all.zip && \
  unzip /tmp/gradle-2.2.1-all.zip -d /usr/local && rm /tmp/gradle-2.2.1-all.zip
ENV GRADLE_HOME=/usr/local/gradle-2.2.1

# Update PATH for the above.
ENV PATH=$PATH:$ANDROID_HOME/tools:$ANDROID_HOME/platform-tools:$NDK_ROOT:$ANT_HOME/bin:$GRADLE_HOME/bin

# Install Go.
ENV GOROOT=/go \
  GOPATH=/
ENV PATH=$PATH:$GOROOT/bin
RUN echo "INSTALLING GO" && \
  curl -L https://github.com/golang/go/archive/$GOVERSION.zip -o /tmp/go.zip && \
  unzip /tmp/go.zip && \
  rm /tmp/go.zip && \
  mv /go-$GOVERSION $GOROOT && \
  echo devel > $GOROOT/VERSION && \
  cd $GOROOT/src && \
  ./all.bash && \
  CC_FOR_TARGET=$NDK_ROOT/bin/arm-linux-androideabi-gcc GOOS=android GOARCH=arm GOARM=7 ./make.bash

WORKDIR $GOPATH/src
