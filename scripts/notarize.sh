#!/bin/bash
# 將 .app 或 .dmg 送 Apple 公證並 staple 票證。
# 需先以 notarytool 儲存憑證 profile（一次性，見 PACKAGING.md）：
#   xcrun notarytool store-credentials ShadowSpaceNotary \
#       --apple-id you@example.com --team-id TEAMID --password <app-專用密碼>
set -eo pipefail
cd "$(dirname "$0")/.."

TARGET="${1:?用法: notarize.sh <path-to-.app-or-.dmg>}"
PROFILE="${NOTARY_PROFILE:-ShadowSpaceNotary}"

if [ ! -e "$TARGET" ]; then
  echo "❌ 找不到 $TARGET"
  exit 1
fi

submit() {
  echo "→ 上傳公證（可能需數分鐘，會等待結果）…"
  xcrun notarytool submit "$1" --keychain-profile "$PROFILE" --wait
}

case "$TARGET" in
  *.app)
    ZIP="build/$(basename "$TARGET" .app)-notarize.zip"
    echo "→ 壓縮 App 以供上傳…"
    /usr/bin/ditto -c -k --keepParent "$TARGET" "$ZIP"
    submit "$ZIP"
    echo "→ staple 票證到 App…"
    xcrun stapler staple "$TARGET"
    rm -f "$ZIP"
    ;;
  *.dmg)
    submit "$TARGET"
    echo "→ staple 票證到 DMG…"
    xcrun stapler staple "$TARGET"
    ;;
  *)
    echo "❌ 只接受 .app 或 .dmg"
    exit 1
    ;;
esac

xcrun stapler validate "$TARGET"
echo "✅ 公證完成並已 staple：$TARGET"
