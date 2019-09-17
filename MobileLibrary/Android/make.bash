#!/usr/bin/env bash

set -e -u -x

if [ ! -f make.bash ]; then
  echo "make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/Android"
  exit 1
fi

# $1, if specified, is go build tags
if [ -z ${1+x} ]; then BUILD_TAGS=""; else BUILD_TAGS="$1"; fi

# Don't use '-u' to force updates because the docker builds always pull
# the latest versions. Outside of Docker, be aware that these dependencies
# will not be overridden w/ new versions if they already exist in $GOPATH

GOOS=android go get -d -v -tags "${BUILD_TAGS}" github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi
if [ $? != 0 ]; then
  echo "..'go get -d -v github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon' failed, exiting"
  exit $?
fi

BUILDINFOFILE="psiphon-tunnel-core_buildinfo.txt"
BUILDDATE=$(date --iso-8601=seconds)
BUILDREPO=$(git config --get remote.origin.url)
BUILDREV=$(git rev-parse --short HEAD)
GOVERSION=$(go version | perl -ne '/go version (.*?) / && print $1')
GOMOBILEVERSION=$(gomobile version | perl -ne '/gomobile version (.*?) / && print $1')

# - starts the string with a `{`
# - uses the `go list` command and passes it a template string (using the Go template syntax) saying I want all the dependencies of the package in the current directory, printing 1/line via printf
# - pipes to `xargs` to run a command on each line output from the first command
#  - uses `go list` with a template string to print the "Import Path" (from just below `$GOPATH/src`) if the package is not part of the standard library
# - pipes to `xargs` again, specifiying `pkg` as the placeholder name for each item being operated on (which is the list of non standard library import paths from the previous step)
#  - `xargs` runs a bash script (via `-c`) which changes to each import path in sequence, then echoes out `"<import path>":"<subshell output of getting the short git revision>",`
# - this leaves a trailing `,` at the end, and no close to the JSON object, so simply `sed` replace the comma before the end of the line with `}` and you now have valid JSON
DEPENDENCIES=$(cd ../psi && echo -n "{" && GOOS=android go list -tags "${BUILD_TAGS}" -f '{{range $dep := .Deps}}{{printf "%s\n" $dep}}{{end}}' | GOOS=android xargs go list -tags "${BUILD_TAGS}" -f '{{if not .Standard}}{{.ImportPath}}{{end}}' | xargs -I pkg bash -c 'cd $GOPATH/src/pkg && echo -n "\"pkg\":\"$(git rev-parse --short HEAD)\","' | sed 's/,$/}/')

LDFLAGS="\
-s \
-w \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildDate=$BUILDDATE \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildRepo=$BUILDREPO \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.buildRev=$BUILDREV \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.goVersion=$GOVERSION \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.gomobileVersion=$GOMOBILEVERSION \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/buildinfo.dependencies=$DEPENDENCIES \
"

echo -e "${BUILDDATE}\n${BUILDREPO}\n${BUILDREV}\n" > $BUILDINFOFILE

echo "Variables for ldflags:"
echo " Build date: ${BUILDDATE}"
echo " Build repo: ${BUILDREPO}"
echo " Build revision: ${BUILDREV}"
echo " Go version: ${GOVERSION}"
echo " Gomobile version: ${GOMOBILEVERSION}"
echo " Dependencies: ${DEPENDENCIES}"
echo ""

# Note: android/386 is x86 and android/amd64 is x86_64
gomobile bind -v -x -target=android/arm,android/arm64,android/386,android/amd64 -tags="${BUILD_TAGS}" -ldflags="$LDFLAGS" github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi
if [ $? != 0 ]; then
  echo "..'gomobile bind' failed, exiting"
  exit $?
fi

mkdir -p build-tmp/psi
unzip -o psi.aar -d build-tmp/psi
yes | cp -f PsiphonTunnel/AndroidManifest.xml build-tmp/psi/AndroidManifest.xml
yes | cp -f PsiphonTunnel/libs/armeabi-v7a/libtun2socks.so build-tmp/psi/jni/armeabi-v7a/libtun2socks.so
yes | cp -f PsiphonTunnel/libs/arm64-v8a/libtun2socks.so build-tmp/psi/jni/arm64-v8a/libtun2socks.so
yes | cp -f PsiphonTunnel/libs/x86/libtun2socks.so build-tmp/psi/jni/x86/libtun2socks.so
yes | cp -f PsiphonTunnel/libs/x86_64/libtun2socks.so build-tmp/psi/jni/x86_64/libtun2socks.so

javac -d build-tmp -bootclasspath $ANDROID_HOME/platforms/android-23/android.jar -source 1.8 -target 1.8 -classpath build-tmp/psi/classes.jar PsiphonTunnel/PsiphonTunnel.java
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
echo -e "-keep class psi.** { *; }\n"  >> proguard.txt
zip -r ../../ca.psiphon.aar ./
cd -
rm -rf build-tmp
echo "Done"
