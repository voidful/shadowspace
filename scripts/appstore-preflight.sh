#!/bin/sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ruby scripts/generate-appstore-xcodeproj.rb

plutil -lint AppStore/ShadowSpace-Info.plist
plutil -lint AppStore/ShadowTunnel/Info.plist
plutil -lint AppStore/PrivacyInfo.xcprivacy
plutil -lint AppStore/entitlements/ShadowSpace.appstore.entitlements
plutil -lint AppStore/entitlements/ShadowTunnel.entitlements

DERIVED_DATA="$ROOT/build/AppStoreDerivedData"
rm -rf "$DERIVED_DATA"

xcodebuild \
  -project AppStore/ShadowSpace.xcodeproj \
  -scheme ShadowSpace \
  -configuration Release \
  -destination 'platform=macOS' \
  -derivedDataPath "$DERIVED_DATA" \
  -jobs 1 \
  CODE_SIGNING_ALLOWED=NO \
  COMPILER_INDEX_STORE_ENABLE=NO \
  SDK_STAT_CACHE_ENABLE=NO \
  build

APP_PRODUCT="$DERIVED_DATA/Build/Products/Release/ShadowSpace.app"
if [ ! -d "$APP_PRODUCT/Contents/PlugIns/ShadowTunnel.appex" ]; then
  echo "ERROR: App Store build is missing ShadowTunnel.appex" >&2
  exit 1
fi

if find "$APP_PRODUCT" -name 'sing-box' -print -quit | grep -q .; then
  echo "ERROR: App Store build contains sing-box" >&2
  exit 1
fi

echo "App Store preflight passed."
