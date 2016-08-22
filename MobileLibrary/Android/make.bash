#!/usr/bin/env bash

set -e

if [ ! -f make.bash ]; then
  echo "make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/Android"
  exit 1
fi

# Don't use '-u' to force updates because the docker builds always pull
# the latest versions. Outside of Docker, be aware that these dependencies
# will not be overridden w/ new versions if they already exist in $GOPATH

GOOS=arm go get -d -v github.com/Psiphon-Inc/openssl
if [ $? != 0 ]; then
  echo "..'go get -d -v github.com/psiphon-inc/openssl' failed, exiting"
  exit $?
fi
GOOS=arm go get -d -v github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon
if [ $? != 0 ]; then
  echo "..'go get -d -v github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon' failed, exiting"
  exit $?
fi

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
DEPENDENCIES=$(cd ../psi && echo -n "{" && go list -f '{{range $dep := .Deps}}{{printf "%s\n" $dep}}{{end}}' | xargs go list -f '{{if not .Standard}}{{.ImportPath}}{{end}}' | xargs -I pkg bash -c 'cd $GOPATH/src/pkg && echo -n "\"pkg\":\"$(git rev-parse --short HEAD)\","' | sed 's/,$/}/')

LDFLAGS="\
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.buildDate=$BUILDDATE \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.buildRepo=$BUILDREPO \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.buildRev=$BUILDREV \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.goVersion=$GOVERSION \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.gomobileVersion=$GOMOBILEVERSION \
-X github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common.dependencies=$DEPENDENCIES \
"

echo "Variables for ldflags:"
echo " Build date: ${BUILDDATE}"
echo " Build repo: ${BUILDREPO}"
echo " Build revision: ${BUILDREV}"
echo " Go version: ${GOVERSION}"
echo " Gomobile version: ${GOMOBILEVERSION}"
echo " Dependencies: ${DEPENDENCIES}"
echo ""

gomobile bind -v -target=android/arm -ldflags="$LDFLAGS" github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi
if [ $? != 0 ]; then
  echo "..'gomobile bind' failed, exiting"
  exit $?
fi

mkdir -p build-tmp/psi
unzip -o psi.aar -d build-tmp/psi
yes | cp -f PsiphonTunnel/AndroidManifest.xml build-tmp/psi/AndroidManifest.xml
yes | cp -f PsiphonTunnel/libs/libtun2socks.so build-tmp/psi/jni/armeabi-v7a/libtun2socks.so

javac -d build-tmp -bootclasspath $ANDROID_HOME/platforms/android-23/android.jar -source 1.7 -target 1.7 -classpath build-tmp/psi/classes.jar:$ANDROID_HOME/platforms/android-23/optional/org.apache.http.legacy.jar PsiphonTunnel/PsiphonTunnel.java 
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
zip -r ../../ca.psiphon.aar ./
cd -
rm -rf build-tmp
echo "Done"
