# ================== 基础设置 ==================
.ONESHELL:
SHELL := /bin/bash
SHELLFLAGS := -eu -o pipefail -c

APP        ?= mlkmbp
PKG        ?= .
MAIN_DIR   ?= $(PKG)             # main.go 同目录；若未指定 CONFIG_* 就用 MAIN_DIR/config
BUILD_DIR  ?= build
LDFLAGS    ?= -s -w -X 'mlkmbp/mbp/api.BuildVersion=beta1'
GOFLAGS    ?= -trimpath -buildvcs=false

ZIG        ?= zig
NPM        ?= npm
SDKROOT    ?= $(shell xcrun --sdk macosx --show-sdk-path 2>/dev/null || true)

GOHOSTOS   := $(shell go env GOHOSTOS)
GOHOSTARCH := $(shell go env GOHOSTARCH)

PLATFORMS_ALL = \
	linux/amd64 \
	linux/arm64 \
	windows/amd64 \
	windows/arm64 \
	darwin/amd64 \
	darwin/arm64

.DEFAULT_GOAL := native
$(shell mkdir -p $(BUILD_DIR))

# ================== 前端 / 配置 输入参数 ==================
REQUIRE_HTML   ?= 1                 # 1=所有包必须含 html/；0=允许没有

# 三选一：确定 html 源
FRONTEND_SRC   ?=                   # 现成 dist 目录（优先）
FRONTEND_BUILD ?= 0                 # 1=需要时构建一次（npm run build）
FRONTEND_ROOT  ?= frontend          # 含 package.json 的目录
FRONTEND_OUT   ?= $(FRONTEND_ROOT)/dist

# 配置来源（其一；否则自动 MAIN_DIR/config 或仓库根 config/）
CONFIG_FILE    ?=
CONFIG_DIR     ?=

# 可选：打包后自动把 config.yaml 里的 static_root 设为 ./html
PATCH_CONFIG_STATIC_ROOT ?= 0

# 打包后是否保留 build/ 下的可执行文件（默认 0=删除；1=保留）
KEEP_BIN_AFTER_TAR ?= 0

# ================== 打包矩阵 ==================
PACKAGE_PLATFORMS ?= \
	linux/amd64 \
	linux/arm64 \
	windows/amd64 \
	windows/arm64 \
	darwin/amd64 \
	darwin/arm64

VERSION  ?= $(shell git describe --tags --always 2>/dev/null || echo latest)

# strip 快捷
_app      := $(strip $(APP))
_pkg      := $(strip $(PKG))
_main     := $(strip $(MAIN_DIR))
_build    := $(strip $(BUILD_DIR))
_ldflags  := $(strip $(LDFLAGS))
_goflags  := $(strip $(GOFLAGS))
_zig      := $(strip $(ZIG))
_npm      := $(strip $(NPM))
_fe_src   := $(strip $(FRONTEND_SRC))
_fe_build := $(strip $(FRONTEND_BUILD))
_fe_root  := $(strip $(FRONTEND_ROOT))
_fe_out   := $(strip $(FRONTEND_OUT))
_req_html := $(strip $(REQUIRE_HTML))
_cfg_file := $(strip $(CONFIG_FILE))
_cfg_dir  := $(strip $(CONFIG_DIR))
_ver      := $(strip $(VERSION))
_patch_sr := $(strip $(PATCH_CONFIG_STATIC_ROOT))
_keep_bin := $(strip $(KEEP_BIN_AFTER_TAR))

PKG_ROOT  = $(_build)/pkgroot
CHECKSUM  = $(shell if command -v sha256sum >/dev/null 2>&1; then echo sha256sum; else echo "shasum -a 256"; fi)

# ================== 工具检查 ==================
.PHONY: check-tools
check-tools:
	@echo "== PRECHECK ====================="
	@command -v go  >/dev/null 2>&1 || { echo "ERROR: go not found";  exit 10; }
	@command -v "$(_zig)" >/dev/null 2>&1 || { echo "ERROR: zig not found"; exit 11; }
	@command -v tar >/dev/null 2>&1 || { echo "ERROR: tar not found"; exit 12; }
	@echo "OK  go / zig / tar"
	@if [ -z "$(_fe_src)" ] && [ "$(_fe_build)" = "1" ]; then \
	  command -v "$(_npm)" >/dev/null 2>&1 || { \
	    echo "ERROR: npm not found but FRONTEND_BUILD=1"; \
	    echo "       方案A：安装 npm；方案B：传 FRONTEND_SRC=/path/to/dist"; \
	    exit 13; }; \
	  echo "OK  npm (FRONTEND_BUILD=1)"; \
	fi
	@echo "================================"

# ================== 后端构建 ==================
all: $(PLATFORMS_ALL)
native: $(GOHOSTOS)/$(GOHOSTARCH)
linux:   linux/amd64 linux/arm64
windows: windows/amd64 windows/arm64
darwin:  darwin/amd64 darwin/arm64

$(PLATFORMS_ALL):
	@os=$(word 1,$(subst /, ,$@)); arch=$(word 2,$(subst /, ,$@)); \
	out="$(_build)/$(_app)_$${os}_$${arch}"; [ "$$os" = "windows" ] && out="$$out.exe"; \
	echo "── BUILD [$(_app)] $$os/$$arch → $$out"; \
	if [ "$$os" = "darwin" ] && [ -z "$(SDKROOT)" ] && [ "$(GOHOSTOS)" != "darwin" ]; then \
	  echo "SKIP darwin/$$arch (no macOS SDKROOT on host $(GOHOSTOS))"; exit 0; \
	fi; \
	case "$$os/$$arch" in \
	  linux/amd64)   CC_CMD="$(_zig) cc -target x86_64-linux-gnu" ;; \
	  linux/arm64)   CC_CMD="$(_zig) cc -target aarch64-linux-gnu" ;; \
	  windows/amd64) CC_CMD="$(_zig) cc -target x86_64-windows-gnu" ;; \
	  windows/arm64) CC_CMD="$(_zig) cc -target aarch64-windows-gnu" ;; \
	  darwin/amd64)  CC_CMD="$(_zig) cc -target x86_64-macos" ;; \
	  darwin/arm64)  CC_CMD="$(_zig) cc -target aarch64-macos" ;; \
	esac; \
	if [ "$$os" = "darwin" ]; then \
	  export CGO_CFLAGS="$$CGO_CFLAGS -isysroot $(SDKROOT)"; \
	  export CGO_LDFLAGS="$$CGO_LDFLAGS -isysroot $(SDKROOT)"; \
	fi; \
	GOOS="$$os" GOARCH="$$arch" CGO_ENABLED=1 CC="$$CC_CMD" \
	  go build $(_goflags) -ldflags="$(_ldflags)" -o "$$out" $(_pkg); \
	[ -s "$$out" ] || { echo "ERROR: build failed: $$out"; exit 2; }; \
	echo "OK  BUILD $$os/$$arch"

# ================== 顶层打包（一次计算 HTML；同进程循环打包） ==================
.PHONY: package
package: check-tools
	@echo "== PREPARE FRONTEND ============"
	@mkdir -p "$(_build)"
	# 计算 HTML（日志直接打印在控制台）
	@HTML=""
	@if [ -n "$(_fe_src)" ] && [ -d "$(_fe_src)" ]; then \
	  HTML="$(_fe_src)"; \
	elif [ -d "html" ] && [ -f "html/index.html" ]; then \
	  HTML="html"; \
	elif [ "$(_fe_build)" = "1" ]; then \
	  echo "-- build at: $(_fe_root)"; \
	  test -f "$(_fe_root)/package.json"; \
	  cd "$(_fe_root)"; \
	  if [ -f package-lock.json ]; then "$(_npm)" ci; else "$(_npm)" install; fi; \
	  "$(_npm)" run build; \
	  cd - >/dev/null; \
	  HTML="$(_fe_out)"; \
	fi; \
	# 兜底 dist/dist
	if [ -n "$$HTML" ] && [ -d "$$HTML/dist" ]; then HTML="$$HTML/dist"; fi; \
	# 校验入口 & 必须性
	if [ -n "$$HTML" ] && [ ! -f "$$HTML/index.html" ]; then echo "ERROR: $$HTML 缺少 index.html"; exit 14; fi; \
	if [ -z "$$HTML" ] && [ "$(_req_html)" = "1" ]; then echo "ERROR: 未发现 html 产物。请传 FRONTEND_SRC=/path/to/dist 或设 FRONTEND_BUILD=1"; exit 15; fi; \
	if [ -n "$$HTML" ]; then echo "OK  FRONTEND: $$HTML"; else echo "OK  FRONTEND: (disabled)"; fi; \
	echo "================================"
	# 打包函数（同一 Shell，避免递归 make）
	@do_pack() { \
	  os="$$1"; arch="$$2"; \
	  if [ "$$os" = "darwin" ] && [ -z "$(SDKROOT)" ] && [ "$(GOHOSTOS)" != "darwin" ]; then \
	    echo "SKIP darwin/$$arch (no macOS SDKROOT on host $(GOHOSTOS))"; return 0; \
	  fi; \
	  # 后端二进制
	  if [ "$$os" = "windows" ]; then BIN_IN="$(_build)/$(_app)_$${os}_$${arch}.exe"; else BIN_IN="$(_build)/$(_app)_$${os}_$${arch}"; fi; \
	  [ -s "$$BIN_IN" ] || $(MAKE) $$os/$$arch >/dev/null; \
	  # 配置源判定
	  CONFIG_FILE_RES=""; CONFIG_DIR_RES=""; \
	  if   [ -n "$(_cfg_file)" ] && [ -f "$(_cfg_file)" ]; then CONFIG_FILE_RES="$(_cfg_file)"; \
	  elif [ -n "$(_cfg_dir)" ] && [ -d "$(_cfg_dir)" ]; then CONFIG_DIR_RES="$(_cfg_dir)"; \
	  elif [ -d "$(_main)/config" ]; then CONFIG_DIR_RES="$(_main)/config"; \
	  elif [ -f "config/config.yaml" ]; then CONFIG_FILE_RES="config/config.yaml"; \
	  elif [ -d "config" ]; then CONFIG_DIR_RES="config"; fi; \
	  # 只在 Windows / macOS 打包时拷贝 config
	  COPY_CONFIG=0; case "$$os" in windows|darwin) COPY_CONFIG=1 ;; esac; \
	  # 日志
	  echo "── PACK [$(_app)] $$os/$$arch v$(_ver)"; \
	  echo "BIN    : $$BIN_IN"; \
	  if [ -n "$$HTML" ]; then echo "HTML   : $$HTML → html/"; else echo "HTML   : (none)"; fi; \
	  if [ "$$COPY_CONFIG" = "1" ]; then \
	    if [ -n "$$CONFIG_FILE_RES" ]; then echo "CONFIG : file $$CONFIG_FILE_RES → config/config.yaml"; fi; \
	    if [ -n "$$CONFIG_DIR_RES"  ]; then echo "CONFIG : dir  $$CONFIG_DIR_RES  → config/"; fi; \
	    [ -z "$$CONFIG_FILE_RES$$CONFIG_DIR_RES" ] && echo "CONFIG : (none)" || true; \
	  else \
	    echo "CONFIG : (skipped on $$os)"; \
	  fi; \
	  # 组装
	  rm -rf "$(PKG_ROOT)/$(_app)"; \
	  mkdir -p "$(PKG_ROOT)/$(_app)/bin" "$(PKG_ROOT)/$(_app)/meta"; \
	  if [ "$$os" = "windows" ]; then \
	    install -m 0755 "$$BIN_IN" "$(PKG_ROOT)/$(_app)/bin/$(_app).exe"; \
	  else \
	    install -m 0755 "$$BIN_IN" "$(PKG_ROOT)/$(_app)/bin/$(_app)"; \
	  fi; \
	  # html（按需强制）
	  if [ "$(_req_html)" = "1" ] && [ -z "$$HTML" ]; then echo "ERROR: REQUIRE_HTML=1 但未准备 html"; return 21; fi; \
	  if [ -n "$$HTML" ]; then mkdir -p "$(PKG_ROOT)/$(_app)/html"; cp -a "$$HTML/." "$(PKG_ROOT)/$(_app)/html/"; fi; \
	  # config（仅 Windows / macOS 复制；复制后可选打补丁）
	  if [ "$$COPY_CONFIG" = "1" ] && { [ -n "$$CONFIG_FILE_RES" ] || [ -n "$$CONFIG_DIR_RES" ]; }; then \
	    mkdir -p "$(PKG_ROOT)/$(_app)/config"; \
	    if [ -n "$$CONFIG_FILE_RES" ]; then cp -a "$$CONFIG_FILE_RES" "$(PKG_ROOT)/$(_app)/config/config.yaml"; \
	    else cp -a "$$CONFIG_DIR_RES/." "$(PKG_ROOT)/$(_app)/config/"; fi; \
	    if [ "$(_patch_sr)" = "1" ] && [ -f "$(PKG_ROOT)/$(_app)/config/config.yaml" ]; then \
	      # BSD/GNU sed 兼容：用 -i.bak 再删备份 \
	      sed -E -i.bak 's#^([[:space:]]*static_root:).*#\1 "./html"#' "$(PKG_ROOT)/$(_app)/config/config.yaml" || true; \
	      rm -f "$(PKG_ROOT)/$(_app)/config/config.yaml.bak" || true; \
	      if ! grep -Eq '^[[:space:]]*static_root:' "$(PKG_ROOT)/$(_app)/config/config.yaml"; then \
	        printf '\nstatic_root: "./html"\n' >> "$(PKG_ROOT)/$(_app)/config/config.yaml" || true; \
	      fi; \
	    fi; \
	  fi; \
	  # meta + 打包
	  echo "$(_ver)" > "$(PKG_ROOT)/$(_app)/meta/VERSION"; \
	  ( cd "$(PKG_ROOT)" && find "$(_app)" -type f ! -path "$(_app)/meta/checksums.txt" -print0 | xargs -0 $(CHECKSUM) ) > "$(PKG_ROOT)/$(_app)/meta/checksums.txt"; \
	  mkdir -p "$(_build)"; \
	  OS_CAP=$$(echo "$$os" | awk '{printf toupper(substr($$0,1,1)) tolower(substr($$0,2))}'); \
	  TARBALL="$(_build)/$(_app)_$${OS_CAP}_$${arch}_$(_ver).tar.gz"; \
	  tar -C "$(PKG_ROOT)" -czf "$$TARBALL" "$(_app)"; \
	  SIZE=$$(du -h "$$TARBALL" | awk '{print $$1}'); \
	  echo "OK  TARBALL: $$TARBALL (size: $$SIZE)"; \
	  if [ -d "$(PKG_ROOT)/$(_app)/html" ]; then echo "      html/: included"; else echo "      html/: (none)"; fi; \
	  if [ -d "$(PKG_ROOT)/$(_app)/config" ]; then echo "      config/: included"; else echo "      config/: (none)"; fi; \
	  # 打包后删除 build/ 下对应可执行文件（所有平台；KEEP_BIN_AFTER_TAR=1 可跳过）
	  if [ "$(_keep_bin)" = "0" ]; then rm -f "$$BIN_IN"; fi; \
	  echo "────────────"; \
	}; \
	for p in $(PACKAGE_PLATFORMS); do os=$${p%/*}; arch=$${p#*/}; do_pack "$$os" "$$arch"; done

# ================== 单平台便捷目标（只改矩阵后复用 package） ==================
package-linux-amd64   : ; @PACKAGE_PLATFORMS="linux/amd64"   $(MAKE) -s package VERSION="$(_ver)" FRONTEND_SRC="$(FRONTEND_SRC)" FRONTEND_BUILD="$(FRONTEND_BUILD)" FRONTEND_ROOT="$(FRONTEND_ROOT)" FRONTEND_OUT="$(FRONTEND_OUT)"
package-linux-arm64   : ; @PACKAGE_PLATFORMS="linux/arm64"   $(MAKE) -s package VERSION="$(_ver)" FRONTEND_SRC="$(FRONTEND_SRC)" FRONTEND_BUILD="$(FRONTEND_BUILD)" FRONTEND_ROOT="$(FRONTEND_ROOT)" FRONTEND_OUT="$(FRONTEND_OUT)"
package-windows-amd64 : ; @PACKAGE_PLATFORMS="windows/amd64" $(MAKE) -s package VERSION="$(_ver)" FRONTEND_SRC="$(FRONTEND_SRC)" FRONTEND_BUILD="$(FRONTEND_BUILD)" FRONTEND_ROOT="$(FRONTEND_ROOT)" FRONTEND_OUT="$(FRONTEND_OUT)"
package-windows-arm64 : ; @PACKAGE_PLATFORMS="windows/arm64" $(MAKE) -s package VERSION="$(_ver)" FRONTEND_SRC="$(FRONTEND_SRC)" FRONTEND_BUILD="$(FRONTEND_BUILD)" FRONTEND_ROOT="$(FRONTEND_ROOT)" FRONTEND_OUT="$(FRONTEND_OUT)"
package-darwin-amd64  : ; @PACKAGE_PLATFORMS="darwin/amd64"  $(MAKE) -s package VERSION="$(_ver)" FRONTEND_SRC="$(FRONTEND_SRC)" FRONTEND_BUILD="$(FRONTEND_BUILD)" FRONTEND_ROOT="$(FRONTEND_ROOT)" FRONTEND_OUT="$(FRONTEND_OUT)"
package-darwin-arm64  : ; @PACKAGE_PLATFORMS="darwin/arm64"  $(MAKE) -s package VERSION="$(_ver)" FRONTEND_SRC="$(FRONTEND_SRC)" FRONTEND_BUILD="$(FRONTEND_BUILD)" FRONTEND_ROOT="$(FRONTEND_ROOT)" FRONTEND_OUT="$(FRONTEND_OUT)"

# ================== 清理 ==================
.PHONY: clean
clean:
	@rm -rf "$(_build)"
