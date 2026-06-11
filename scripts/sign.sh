#!/bin/bash
# 以 Hardened Runtime「由內而外」簽署 ShadowSpace.app。
# 預設 ad-hoc（SIGN_IDENTITY=-），僅供本機測試；發佈請帶入 Developer ID Application。
#
#   SIGN_IDENTITY="Developer ID Application: 你的名字 (TEAMID)" ./scripts/sign.sh
set -euo pipefail
cd "$(dirname "$0")/.."

APP="${1:-build/ShadowSpace.app}"
IDENTITY="${SIGN_IDENTITY:--}"
APP_ENT="Resources/ShadowSpace.entitlements"
CORE_ENT="Resources/singbox.entitlements"

if [ ! -d "$APP" ]; then
  echo "❌ 找不到 $APP，請先執行 make app"
  exit 1
fi

COMMON=(--force --options runtime)
TS=(--timestamp)
if [ "$IDENTITY" = "-" ]; then
  echo "⚠️  使用 ad-hoc 簽章：僅供本機測試，無法公證、無法給別台 Mac 執行。"
  echo "    發佈請用：SIGN_IDENTITY=\"Developer ID Application: ... (TEAMID)\" make sign"
  TS=()   # ad-hoc 不能加時間戳
fi

# 1) 先簽內嵌的執行檔（sing-box）—— 必須在簽 App 本體之前
if [ -d "$APP/Contents/Resources/bin" ]; then
  while IFS= read -r bin; do
    echo "→ 簽署核心：${bin#"$APP/"}"
    codesign "${COMMON[@]}" ${TS[@]+"${TS[@]}"} \
      --identifier "com.voidful.shadowspace.singbox" \
      --entitlements "$CORE_ENT" --sign "$IDENTITY" "$bin"
  done < <(find "$APP/Contents/Resources/bin" -type f)
fi

# 2) 最後簽 App 本體（刻意不用 --deep，Apple 已不建議）
echo "→ 簽署 App：$APP"
codesign "${COMMON[@]}" ${TS[@]+"${TS[@]}"} \
  --entitlements "$APP_ENT" --sign "$IDENTITY" "$APP"

echo "→ 驗證簽章結構…"
codesign --verify --strict --verbose=2 "$APP"

if [ "$IDENTITY" != "-" ]; then
  echo "→ Gatekeeper 評估（公證前顯示 rejected 屬正常，公證 staple 後才會 accepted）："
  spctl -a -vvv --type execute "$APP" 2>&1 || true
fi
echo "✅ 簽署完成（identity: $IDENTITY）"
