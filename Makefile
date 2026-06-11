APP_NAME := ShadowSpace
BUILD_DIR := build
APP_BUNDLE := $(BUILD_DIR)/$(APP_NAME).app
RELEASE_BIN := .build/release/$(APP_NAME)

# 簽章身分：預設 ad-hoc（本機測試）。發佈時覆寫為 Developer ID Application。
#   make release SIGN_IDENTITY="Developer ID Application: 你的名字 (TEAMID)"
SIGN_IDENTITY ?= -
NOTARY_PROFILE ?= ShadowSpaceNotary
VERSION = $(shell /usr/libexec/PlistBuddy -c "Print CFBundleShortVersionString" Resources/Info.plist)

.PHONY: all setup build app sign run dev test engine dmg notarize release clean

all: app

## 一鍵完成：下載引擎 + 編譯 + 打包
setup: engine app
	@echo ""
	@echo "✅ 完成！執行 make run 啟動 ShadowSpace"

## 下載 sing-box 核心到 vendor/（App 內也可自動下載，但發佈版建議內嵌）
engine:
	./scripts/fetch-singbox.sh

build:
	swift build -c release

## 組裝 .app 並簽署（預設 ad-hoc；簽章邏輯在 scripts/sign.sh）
app: build
	rm -rf $(APP_BUNDLE)
	mkdir -p $(APP_BUNDLE)/Contents/MacOS $(APP_BUNDLE)/Contents/Resources
	cp $(RELEASE_BIN) $(APP_BUNDLE)/Contents/MacOS/$(APP_NAME)
	cp Resources/Info.plist $(APP_BUNDLE)/Contents/Info.plist
	@if [ -f Resources/AppIcon.icns ]; then \
		cp Resources/AppIcon.icns $(APP_BUNDLE)/Contents/Resources/AppIcon.icns; \
		echo "已套用 App 圖示"; \
	fi
	@if [ -f vendor/sing-box ]; then \
		mkdir -p $(APP_BUNDLE)/Contents/Resources/bin; \
		cp vendor/sing-box $(APP_BUNDLE)/Contents/Resources/bin/sing-box; \
		echo "已內嵌 sing-box 引擎"; \
	else \
		echo "（未內嵌引擎：App 會在首次連線自動下載。發佈版請先 make engine）"; \
	fi
	@SIGN_IDENTITY='$(SIGN_IDENTITY)' ./scripts/sign.sh $(APP_BUNDLE)

## 重新簽署既有 bundle（改了憑證時用）
sign:
	@SIGN_IDENTITY='$(SIGN_IDENTITY)' ./scripts/sign.sh $(APP_BUNDLE)

run: app
	open $(APP_BUNDLE)

## 開發模式（不打包，部分功能如登入啟動不可用）
dev:
	swift run

test:
	swift test

## 打包 DMG（帶 SIGN_IDENTITY 時一併簽署）
dmg:
	@SIGN_IDENTITY='$(SIGN_IDENTITY)' ./scripts/make-dmg.sh $(APP_BUNDLE)

## 公證 .app（需先存好 notarytool 憑證 profile）
notarize:
	./scripts/notarize.sh $(APP_BUNDLE)

## 完整發佈：簽章 → 公證 App → DMG → 公證 DMG（需 Developer ID 憑證）
release:
	@if [ '$(SIGN_IDENTITY)' = '-' ]; then \
		echo "❌ 請指定 Developer ID 憑證："; \
		echo '   make release SIGN_IDENTITY="Developer ID Application: 你的名字 (TEAMID)"'; \
		exit 1; \
	fi
	@if [ ! -f vendor/sing-box ]; then \
		echo "❌ 發佈版需內嵌引擎，請先執行：make engine"; \
		exit 1; \
	fi
	$(MAKE) app SIGN_IDENTITY='$(SIGN_IDENTITY)'
	NOTARY_PROFILE='$(NOTARY_PROFILE)' ./scripts/notarize.sh $(APP_BUNDLE)
	$(MAKE) dmg SIGN_IDENTITY='$(SIGN_IDENTITY)'
	NOTARY_PROFILE='$(NOTARY_PROFILE)' ./scripts/notarize.sh $(BUILD_DIR)/$(APP_NAME)-$(VERSION).dmg
	@echo ""
	@echo "🎉 發佈完成：$(BUILD_DIR)/$(APP_NAME)-$(VERSION).dmg"

clean:
	rm -rf .build $(BUILD_DIR)
