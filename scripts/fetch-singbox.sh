#!/bin/bash
# 下載官方 sing-box 二進位檔到 vendor/，供 make app 打包進 .app。
# App 本身也能在第一次連線時自動下載引擎，這個腳本只是 CLI 同好的捷徑。
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p vendor

case "$(uname -m)" in
  arm64)  ARCH="arm64" ;;
  x86_64) ARCH="amd64" ;;
  *) echo "不支援的架構: $(uname -m)"; exit 1 ;;
esac

VERSION="${SINGBOX_VERSION:-}"
if [ -z "$VERSION" ]; then
  echo "==> 查詢 sing-box 最新版本…"
  # 先完整收下 API 回應再解析，避免 curl | grep -m1 早退觸發 SIGPIPE（curl error 56）
  API_JSON=$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest)
  VERSION=$(printf '%s\n' "$API_JSON" | sed -n 's/.*"tag_name":[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p')
fi
if [ -z "$VERSION" ]; then
  echo "無法取得版本資訊。可手動指定：SINGBOX_VERSION=1.12.0 $0"
  echo "或改用 Homebrew：brew install sing-box"
  exit 1
fi

NAME="sing-box-${VERSION}-darwin-${ARCH}"
URL="https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/${NAME}.tar.gz"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "==> 下載 ${URL}"
curl -fL --progress-bar -o "$TMP/sb.tar.gz" "$URL"
tar -xzf "$TMP/sb.tar.gz" -C "$TMP"
mv "$TMP/$NAME/sing-box" vendor/sing-box
chmod +x vendor/sing-box
xattr -c vendor/sing-box 2>/dev/null || true

echo "==> 完成：$(./vendor/sing-box version | head -n1)"
