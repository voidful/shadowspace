#!/bin/bash
# 由一張正方形 PNG（建議 1024x1024 以上）產生 macOS App 圖示 Resources/AppIcon.icns。
#   ./scripts/make-icon.sh path/to/icon.png
# 之後 make app 會自動把 AppIcon.icns 複製進 .app（Info.plist 已設 CFBundleIconFile）。
set -euo pipefail
cd "$(dirname "$0")/.."

SRC="${1:-Resources/AppIcon.png}"
OUT="Resources/AppIcon.icns"

if [ ! -f "$SRC" ]; then
  echo "❌ 找不到來源圖：$SRC"
  echo "   用法：./scripts/make-icon.sh path/to/icon.png"
  exit 1
fi

W=$(sips -g pixelWidth  "$SRC" | awk '/pixelWidth/{print $2}')
H=$(sips -g pixelHeight "$SRC" | awk '/pixelHeight/{print $2}')
if [ "$W" != "$H" ]; then
  echo "⚠️  來源不是正方形（${W}x${H}），icon 可能會被拉伸；建議用 1024x1024。"
fi

TMP="$(mktemp -d)"
ICONSET="$TMP/AppIcon.iconset"
mkdir -p "$ICONSET"
gen() { sips -z "$1" "$1" "$SRC" --out "$ICONSET/$2" >/dev/null; }

gen 16   icon_16x16.png
gen 32   icon_16x16@2x.png
gen 32   icon_32x32.png
gen 64   icon_32x32@2x.png
gen 128  icon_128x128.png
gen 256  icon_128x128@2x.png
gen 256  icon_256x256.png
gen 512  icon_256x256@2x.png
gen 512  icon_512x512.png
gen 1024 icon_512x512@2x.png

iconutil -c icns "$ICONSET" -o "$OUT"
rm -rf "$TMP"
echo "✅ 已產生 $OUT"
