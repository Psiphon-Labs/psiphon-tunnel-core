#!/usr/bin/env bash

set -e -u -x

if [ ! -f make.bash ]; then
  echo "make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/Android"
  exit 1
fi

# $1, if specified, is go build tags
if [ -z ${1+x} ]; then BUILD_TAGS=""; else BUILD_TAGS="$1"; fi

# At this time, psiphon-tunnel-core doesn't support modules
export GO111MODULE=off

export GOCACHE=/tmp

BUILDINFOFILE="psiphon-tunnel-core_buildinfo.txt"
BUILDDATE=$(date --iso-8601=seconds)
BUILDREPO="https://github.com/Psiphon-Labs/psiphon-tunnel-core.git"
BUILDREV=$(git rev-parse --short HEAD)
GOVERSION=$(go version | perl -ne '/go version (.*?) / && print $1')

# -checklinkname=0 is a required workaround for an in-proxy dependency:
# https://github.com/wlynxg/anet/tree/5501d401a269290292909e6cc75f105571f97cfa?tab=readme-ov-file#how-to-build-with-go-1230-or-later
#
# TODO: conditional on !PSIPHON_DISABLE_INPROXY build tag?

# 16KB page size alignment for Android compatibility
export CGO_LDFLAGS="${CGO_LDFLAGS:-} -Wl,-z,max-page-size=16384,-z,common-page-size=16384"

LDFLAGS="\
-checklinkname=0 \
-s \
-w \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildDate=$BUILDDATE \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildRepo=$BUILDREPO \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildRev=$BUILDREV \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.goVersion=$GOVERSION \
-extldflags=-Wl,-z,max-page-size=16384,-z,common-page-size=16384 \
"

echo -e "${BUILDDATE}\n${BUILDREPO}\n${BUILDREV}\n" > $BUILDINFOFILE

echo "Variables for ldflags:"
echo " Build date: ${BUILDDATE}"
echo " Build repo: ${BUILDREPO}"
echo " Build revision: ${BUILDREV}"
echo " Go version: ${GOVERSION}"
echo ""

gomobile bind -v -x -target=android/arm,android/arm64,android/386,android/amd64 -tags="${BUILD_TAGS}" -ldflags="$LDFLAGS" github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi
if [ $? != 0 ]; then
  echo "..'gomobile bind' failed, exiting"
  exit $?
fi

mkdir -p build-tmp/psi
unzip -o psi.aar -d build-tmp/psi
yes | cp -f PsiphonTunnel/AndroidManifest.xml build-tmp/psi/AndroidManifest.xml
mkdir -p build-tmp/psi/res/xml
yes | cp -f PsiphonTunnel/ca_psiphon_psiphontunnel_backup_rules.xml build-tmp/psi/res/xml/ca_psiphon_psiphontunnel_backup_rules.xml

javac -d build-tmp -bootclasspath $ANDROID_HOME/platforms/android-$ANDROID_PLATFORM_VERSION/android.jar -source 1.8 -target 1.8 -classpath build-tmp/psi/classes.jar PsiphonTunnel/PsiphonTunnel.java
if [ $? != 0 ]; then
  echo "..'javac' compiling PsiphonTunnel failed, exiting"
  exit $?
fi

cd build-tmp

jar uf psi/classes.jar ca/psiphon/*.class
if [ $? != 0 ]; then
  echo "..'jar' failed to add classes, exiting"
  exit $?
fi

cd -
cd build-tmp/psi
echo -e "-keep class psi.** { *; }\n-keep class ca.psiphon.** { *; }\n"  >> proguard.txt
rm -f ../../ca.psiphon.aar
zip -r ../../ca.psiphon.aar ./
cd -
rm -rf build-tmp
echo "Done"
