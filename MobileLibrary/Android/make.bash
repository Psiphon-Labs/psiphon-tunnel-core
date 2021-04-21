#!/usr/bin/env bash

set -e -u -x

if [ ! -f make.bash ]; then
  echo "make.bash must be run from $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/Android"
  exit 1
fi

# $1, if specified, is go build tags
if [ -z ${1+x} ]; then BUILD_TAGS=""; else BUILD_TAGS="$1"; fi

# At this time, gomobile doesn't support modules
export GO111MODULE=off

BUILDINFOFILE="psiphon-tunnel-core_buildinfo.txt"
BUILDDATE=$(date --iso-8601=seconds)
BUILDREPO=$(git config --get remote.origin.url)
BUILDREV=$(git rev-parse --short HEAD)
GOVERSION=$(go version | perl -ne '/go version (.*?) / && print $1')
GOMOBILEVERSION=$(gomobile version | perl -ne '/gomobile version (.*?) / && print $1')

# DEPENDENCIES
#
# - this script produces a JSON object listing all Go package dependencies,
#   excluding packages under github.com/Psiphon-Labs/psiphon-tunnel-core/
#   (thus also excluding vendored packages) which will all have the same rev
#   as BUILDREV
#
# - starts the string with a `{` and ends with a `}`
#
# - uses the `go list` command and passes it a template string (using the Go
#   template syntax) saying I want all the dependencies of the package in the
#   current directory, printing 1/line via printf
#
# - pipes to `xargs` to run a command on each line output from the first
#   command and uses `go list` with a template string to print the "Import
#   Path" (from just below `$GOPATH/src`) if the package is not part of the
#   standard library
#
# - pipes to `xargs` again, specifiying `pkg` as the placeholder name for each
#   item being operated on (which is the list of non standard library import
#   paths from the previous step); `xargs` runs a bash script (via `-c`) which
#   changes to each import path in sequence, then echoes out, after the
#   exclusion check, `"<import path>":"<subshell output of getting the short
#   git revision>",`
#
# - for non-empty dependency lists, the last command leaves a trailing `,\n` at
#   the end, so use `sed` and `tr` to remove the suffix.
#
DEPENDENCIES=$(cd ../psi && echo -n "{" && GOOS=android go list -tags "${BUILD_TAGS}" -f '{{range $dep := .Deps}}{{printf "%s\n" $dep}}{{end}}' | GOOS=android xargs go list -tags "${BUILD_TAGS}" -f '{{if not .Standard}}{{.ImportPath}}{{end}}' | xargs -I pkg bash -c 'cd $GOPATH/src/$0 && if echo -n "$0" | grep -vEq "^github.com/Psiphon-Labs/psiphon-tunnel-core/" ; then echo -n "\"$0\":\"$(git rev-parse --short HEAD)\"," ; fi' pkg | sed 's/,$//' | tr -d '\n' && echo -n "}")

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

# Note: android/386 is x86, which is used on both x86 and x86_64 Android
# devices. We are excluding the android/amd64, x86_64, ABI as it causes a
# crash in Android x86_64 emulators: "seccomp prevented call to disallowed
# x86_64 system call 22". x86/linux syscall 22 is pipe.
#
# In Android seccomp config, pipe is permitted only for 32-bit platforms:
# https://android.googlesource.com/platform/bionic/+/2b499046f10487802bfbaaf4429160595d08b22c/libc/SECCOMP_WHITELIST_APP.TXT#7.
#
# The Go syscall.Pipe on linux(android)/amd64 is the disallowed pipe:
# https://github.com/golang/go/blob/release-branch.go1.14/src/syscall/syscall_linux_amd64.go#L115-L126
#
# A potential future fix is to use the allowed pipe2,
# https://android.googlesource.com/platform/bionic/+/2b499046f10487802bfbaaf4429160595d08b22c/libc/SYSCALLS.TXT#129,
# which is what linux(android)/arm64 uses, for example:
# https://github.com/golang/go/blob/release-branch.go1.14/src/syscall/syscall_linux_arm64.go#L150-L159.

gomobile bind -v -x -target=android/arm,android/arm64,android/386 -tags="${BUILD_TAGS}" -ldflags="$LDFLAGS" github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/psi
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
mkdir -p build-tmp/psi/res/xml
yes | cp -f PsiphonTunnel/ca_psiphon_psiphontunnel_backup_rules.xml build-tmp/psi/res/xml/ca_psiphon_psiphontunnel_backup_rules.xml

javac -d build-tmp -bootclasspath $ANDROID_HOME/platforms/android-26/android.jar -source 1.8 -target 1.8 -classpath build-tmp/psi/classes.jar PsiphonTunnel/PsiphonTunnel.java
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
rm -f ../../ca.psiphon.aar
zip -r ../../ca.psiphon.aar ./
cd -
rm -rf build-tmp
echo "Done"
