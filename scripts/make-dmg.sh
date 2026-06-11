#!/bin/bash
# 把 ShadowSpace.app 打包成可拖曳安裝的壓縮 DMG（內含 /Applications 捷徑）。
# 帶 SIGN_IDENTITY 時會一併簽署 DMG。
set -eo pipefail
cd "$(dirname "$0")/.."

APP="${1:-build/ShadowSpace.app}"
IDENTITY="${SIGN_IDENTITY:--}"

if [ ! -d "$APP" ]; then
  echo "❌ 找不到 $APP，請先執行 make app"
  exit 1
fi

VERSION=$(/usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" \
  "$APP/Contents/Info.plist" 2>/dev/null || echo "0.0.0")
VOL="ShadowSpace"
DMG="build/ShadowSpace-${VERSION}.dmg"
STAGE="build/dmg-stage"

echo "→ 準備 DMG 內容…"
rm -rf "$STAGE" "$DMG"
mkdir -p "$STAGE"
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"

echo "→ 建立壓縮映像檔…"
hdiutil create -volname "$VOL" -srcfolder "$STAGE" \
  -ov -format UDZO -fs HFS+ "$DMG" >/dev/null
rm -rf "$STAGE"

if [ "$IDENTITY" != "-" ]; then
  echo "→ 簽署 DMG…"
  codesign --force --timestamp --sign "$IDENTITY" "$DMG"
fi

hdiutil verify "$DMG" >/dev/null && echo "→ DMG 完整性驗證通過"
echo "✅ DMG：$DMG  （$(du -h "$DMG" | cut -f1)）"
