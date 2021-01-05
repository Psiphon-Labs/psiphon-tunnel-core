#!/bin/bash


REPO_DIR=$GOPATH/src/github.com/refraction-networking/gotapdance/

#sed -i.bak "s/buildInfo = \"\"/buildInfo = \"$TRAVIS_BRANCH-$TRAVIS_COMMIT\"/" tapdance/logger.go
git clone https://github.com/Psiphon-Labs/psiphon-tunnel-core.git $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core
cd $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core && git checkout -b build-refraction-networking


go get github.com/kardianos/govendor
cd $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core && $GOPATH/bin/govendor remove github.com/refraction-networking/gotapdance/...

sed -i.bak 's/refraction_networking_tapdance.Logger().Out = ioutil.Discard//' $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tapdance/tapdance.go


# Conjure APK
echo "Conjure APK before_Script"

cd $GOPATH/src/github.com/refraction-networking/gotapdance

docker pull refraction/psiandroid:latest

mkdir -p $GOPATH/src/bitbucket.org/psiphon
hg clone https://bitbucket.org/psiphon/psiphon-circumvention-system $GOPATH/src/bitbucket.org/psiphon/psiphon-circumvention-system

cd $GOPATH/src/bitbucket.org/psiphon/psiphon-circumvention-system #&& hg checkout

# Use modified EmbeddedValues.java for TapDance
cd $GOPATH/src/github.com/refraction-networking/gotapdance
/usr/local/ssl/bin/openssl enc -nosalt -aes-256-cbc -md sha512 -pbkdf2 -iter 1000 -pass pass:$aes_cbc_passwd  -d -in build/EmbeddedValues.java.enc -out $GOPATH/src/bitbucket.org/psiphon/psiphon-circumvention-system/Android/app/src/main/java/com/psiphon3/psiphonlibrary/EmbeddedValues.java

echo "patching..."
# Patched tunneling protocol for TapDance
patch $GOPATH/src/bitbucket.org/psiphon/psiphon-circumvention-system/Android/app/src/main/java/com/psiphon3/psiphonlibrary/TunnelManager.java build/TunnelManager.java.patch

# Patch the Psiphon app's gradle build for java 1.8 compatibility [TODO]{priority:later} remove this when psiphon merges it themselves
patch $GOPATH/src/bitbucket.org/psiphon/psiphon-circumvention-system/Android/app/build.gradle build/PsiphonCoreGradle.patch

# Add dialer options to enable Conjure
patch $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tapdance/tapdance.go build/conjure.golang.patch

echo "digesting..."
# Digest this branch's ClientConf into Psiphon's embedded_config
./test_scripts/psiphon_digest_cc.sh ./assets/ClientConf $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/psiphon/common/tapdance/embedded_config.go

echo "Conjure APK script"
cd $REPO_DIR

# Build Psiphon Android Library ca.psiphon.aar
#docker run -v $DOCKER_DIR:$GOPATH/go/src/github.com/refraction-networking/gotapdance -v $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core:$GOPATH/go/src/github.com/Psiphon-Labs/psiphon-tunnel-core refraction/psiandroid /bin/bash -c 'cd $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/Android && ./make.bash "TAPDANCE"'
docker run -v $REPO_DIR:/go/src/github.com/refraction-networking/gotapdance -v $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core:/go/src/github.com/Psiphon-Labs/psiphon-tunnel-core refraction/psiandroid /bin/bash -c 'cd /go/src/github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/Android && ./make.bash "TAPDANCE"'

echo "moving .aar"
cd $GOPATH/src/github.com/refraction-networking/gotapdance
mv $GOPATH/src/github.com/Psiphon-Labs/psiphon-tunnel-core/MobileLibrary/Android/ca.psiphon.aar build/

# Build Psiphon Android App PsiphonAndroid-debug.apk
cp -f build/ca.psiphon.aar $GOPATH/src/bitbucket.org/psiphon/psiphon-circumvention-system/Android/app/libs/

cd $GOPATH/src/github.com/refraction-networking/gotapdance
echo "docker run gradlew assembleDebug.."
#docker run -v $DOCKER_DIR:/go/src/github.com/refraction-networking/gotapdance -v $GOPATH/src/bitbucket.org/psiphon/psiphon-circumvention-system/Android:/go/src/bitbucket.org/psiphon/psiphon-circumvention-system/Android refraction/psiandroid /bin/bash -c 'yes | /android-sdk-linux/tools/bin/sdkmanager --update && cd /go/src/bitbucket.org/psiphon/psiphon-circumvention-system/Android && ./gradlew assembleDebug'
docker run -v $REPO_DIR:/go/src/github.com/refraction-networking/gotapdance -v $GOPATH/src/bitbucket.org/psiphon/psiphon-circumvention-system/Android:/go/src/bitbucket.org/psiphon/psiphon-circumvention-system/Android refraction/psiandroid /bin/bash -c 'yes | /android-sdk-linux/tools/bin/sdkmanager --update && cd /go/src/bitbucket.org/psiphon/psiphon-circumvention-system/Android && ./gradlew assembleDebug'

cp $GOPATH/src/bitbucket.org/psiphon/psiphon-circumvention-system/Android/app/build/outputs/apk/debug/PsiphonAndroid-debug.apk build/PsiphonAndroid-CJ-debug.apk

pwd
echo "build/PsiphonAndroid-CJ-debug.apk"
