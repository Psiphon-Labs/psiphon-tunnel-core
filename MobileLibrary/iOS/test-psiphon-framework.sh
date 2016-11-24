#!/usr/bin/env bash

set -e

BASE_DIR=$(cd "$(dirname "$0")" ; pwd -P)
cd ${BASE_DIR}

# The location of the final framework build
BUILD_DIR="${BASE_DIR}/build"

#
# Run tests
# 

cd ${BASE_DIR}

# Run the framework projects tests
xcodebuild test -project "PsiphonTunnel/PsiphonTunnel.xcodeproj" -scheme "PsiphonTunnel" -destination 'platform=iOS Simulator,name=iPhone 7'
rc=$?; if [[ $rc != 0 ]]; then
  echo "FAILURE: PsiphonTunnel tests"
  exit $rc
fi

# Run the sample app project tests
rm -rf "SampleApps/TunneledWebRequest/TunneledWebRequest/PsiphonTunnel.framework" 
cp -R "${BUILD_DIR}/PsiphonTunnel.framework" "SampleApps/TunneledWebRequest/TunneledWebRequest"
xcodebuild test -project "SampleApps/TunneledWebRequest/TunneledWebRequest.xcodeproj" -scheme "TunneledWebRequest" -destination 'platform=iOS Simulator,name=iPhone 7'
rc=$?; if [[ $rc != 0 ]]; then
  echo "FAILURE: TunneledWebRequest tests"
  exit $rc
fi

echo "TESTS DONE"
