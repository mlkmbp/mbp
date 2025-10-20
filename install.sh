#!/usr/bin/env bash
set -euo pipefail

# ================== 基本配置 ==================
APP_NAME="${APP_NAME:-mlkmbp}"
PKG_VERSION="${PKG_VERSION:-latest}"        # 安装包版本或直链
LETSENCRYPT_STAGING="${LETSENCRYPT_STAGING:-0}"  # 1=走 LE 测试环境

ARCH_RAW="$(uname -m | tr '[:upper:]' '[:lower:]')"
OS_TYPE="$(uname -s | tr '[:upper:]' '[:lower:]')"

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_FILE="${CONFIG_FILE:-/etc/${APP_NAME}/config.yaml}"
LOG_DIR_DEFAULT="/var/log/${APP_NAME}"
LOG_DIR="${LOG_DIR:-$LOG_DIR_DEFAULT}"; LOG_DIR="${LOG_DIR%\}}"
DB_DIR="${DB_DIR:-/var/lib/${APP_NAME}}"
FRONTEND_DIR="${FRONTEND_DIR:-/var/html/${APP_NAME}}"
CERT_DIR="${CERT_DIR:-/etc/${APP_NAME}/tls}"   # 保留变量，实际用 acme 默认路径
BACKUP_DIR="${BACKUP_DIR:-/var/backups/${APP_NAME}}"

# ================== 彩色输出 ==================
GREEN='\033[32m'; RED='\033[31m'; YELLOW='\033[33m'; BLUE='\033[34m'; RESET='\033[0m'
ok()   { printf "%b\n" "${GREEN}$*${RESET}"; }
warn() { printf "%b\n" "${YELLOW}$*${RESET}"; }
err()  { printf "%b\n" "${RED}$*${RESET}"; }

# ================== 提权/依赖/Systemd ==================
as_root() {
  if [ "$(id -u)" -eq 0 ]; then "$@"
  elif command -v sudo >/dev/null 2>&1; then sudo "$@"
  elif command -v su   >/dev/null 2>&1; then local cmd; cmd="$(printf '%q ' "$@")"; su -c "$cmd"
  else err "需要 root 权限执行：$*"; exit 1; fi
}
ensure_systemd(){ command -v systemctl >/dev/null 2>&1 || { err "需要 systemd 环境（未找到 systemctl）。"; exit 1; }; }
systemctl_req(){ ensure_systemd; as_root systemctl "$@"; }

install_dependency() {
  local dep="$1"
  warn "正在安装缺失的依赖：$dep"
  if command -v apt-get >/dev/null 2>&1; then
    as_root apt-get update -y
    as_root apt-get install -y "$dep"
  elif command -v yum >/dev/null 2>&1; then
    as_root yum install -y "$dep"
  elif command -v dnf >/dev/null 2>&1; then
    as_root dnf install -y "$dep"
  elif command -v apk >/dev/null 2>&1; then
    as_root apk add --no-cache "$dep"
  else
    err "不支持的包管理器，无法自动安装 $dep"; exit 1
  fi
  command -v "$dep" >/dev/null 2>&1 || { err "$dep 安装失败"; exit 1; }
}
need_cmd(){ command -v "$1" >/dev/null 2>&1 || install_dependency "$1"; }

ensure_downloader(){
  if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then return 0; fi
  install_dependency curl || install_dependency wget
}

preflight_deps(){
  ensure_systemd
  need_cmd tar
  need_cmd socat
  command -v gzip >/dev/null 2>&1 || true
  command -v openssl >/dev/null 2>&1 || command -v base64 >/dev/null 2>&1 || need_cmd openssl || true
  command -v ss >/dev/null 2>&1 || command -v netstat >/dev/null 2>&1 || true
  ensure_downloader
}
preflight_deps

# ================== 工具/校验函数 ==================
normalize_arch(){
  case "$ARCH_RAW" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    armv7l|armv7) echo "armv7" ;;
    *) echo "$ARCH_RAW" ;;
  esac
}
ARCH="$(normalize_arch)"
is_url(){ [[ "$1" =~ ^https?:// ]]; }
to_lower(){ printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]'; }

# 控制字符检测 + 统一输入（支持隐藏、清空、重输）
has_ctrl_bs(){ [[ "$1" == *$'\x08'* || "$1" == *$'\x7f'* || "$1" == *'^H'* ]]; }
prompt_clean(){ # $1=提示 $2=hidden?1:0 -> echo 值；输入 "-" 代表清空；含控制字符将重输
  local p="$1" hid="${2:-0}" x=""
  while true; do
    if [ "$hid" = "1" ]; then
      read -rsp "$p" x || true
      # 关键修复：隐藏输入后强制换行到 stderr（read -p 也是写 stderr）
      printf '\n' >&2
    else
      read -rp "$p" x || true
    fi
    [ "$x" = "-" ] && { echo ""; return 0; }
    has_ctrl_bs "$x" && { warn "检测到退格/控制字符，已丢弃，请重新输入（清空请输入 '-'）"; continue; }
    echo "$x"; return 0
  done
}

# 校验
is_valid_domain(){ local d="$1"; [[ "$d" =~ ^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$ ]]; }
is_valid_email(){ local e="$1"; [[ "$e" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; }
is_valid_url_http(){ local u="$1"; [[ "$u" =~ ^https?://[A-Za-z0-9._-]+(:[0-9]{1,5})?(/.*)?$ ]]; }
is_valid_port(){ local p="${1:-}"; [[ "$p" =~ ^[0-9]{1,5}$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ]; }
is_ipv4(){
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r a b c d <<<"$ip"
  for o in "$a" "$b" "$c" "$d"; do [ "$o" -ge 0 ] 2>/dev/null && [ "$o" -le 255 ] 2>/dev/null || return 1; done
}
is_fqdn(){ local h="$1"; [[ "$h" =~ ^([A-Za-z0-9-]+\.)+[A-Za-z0-9-]+$ ]]; }
is_valid_ssh_user(){ local u="$1"; [[ "$u" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]]; }
# ssh_base_url 仅允许 host[:port]
is_valid_ssh_base(){
  local x="$1" host port
  host="${x%%:*}"; [ "$host" = "$x" ] && port="" || port="${x##*:}"
  [ -n "$port" ] && ! is_valid_port "$port" && return 1
  [[ "$host" == *%s* ]] && return 1
  is_ipv4 "$host" || is_fqdn "$host"
}

service_exists(){ systemctl_req list-unit-files | grep -q "^${APP_NAME}\.service"; }
service_is_active(){ systemctl_req is-active --quiet "${APP_NAME}"; }
restart_if_active(){ if service_is_active; then ok "配置已更新，重启服务生效"; systemctl_req restart "${APP_NAME}" || true; fi; }
timestamp(){ date +%Y%m%d-%H%M%S; }

# ================== 下载/解压/定位包 ==================
build_pkg_url(){ local v="$1"; if is_url "$v"; then echo "$v"; else echo "https://github.com/mlkmbp/mbp/releases/download/latest/${APP_NAME}_Linux_${ARCH}_${v}.tar.gz"; fi; }
download_file(){
  local url="$1" out="$2"
  printf "%b\n" "${BLUE}下载：${url}${RESET}"
  if command -v curl >/dev/null 2>&1; then curl -fL --connect-timeout 15 --retry 3 --retry-delay 1 "$url" -o "$out"
  else wget -t 3 -T 20 -O "$out" "$url"; fi
}
extract_pkg(){ local tarball="$1" target="$2"; ok "解压 ${tarball} 到 ${target}"; mkdir -p "$target"; tar --no-same-owner --no-same-permissions -xzf "$tarball" -C "$target"; }
locate_pkg_root(){
  local base="$1"
  if [ -d "$base/$APP_NAME/bin" ] && [ -d "$base/$APP_NAME/html" ]; then echo "$base/$APP_NAME"; return 0; fi
  local f; f="$(find "$base" -maxdepth 4 -type f \( -name "$APP_NAME" -o -name "$APP_NAME.exe" \) 2>/dev/null | head -n1 || true)"
  if [ -n "$f" ]; then local r; r="$(dirname "$(dirname "$f")")"; [ -d "$r/html" ] && { echo "$r"; return 0; }; fi
  echo ""
}

# ================== 域名/时区工具 ==================
get_current_tz(){
  if command -v timedatectl >/dev/null 2>&1; then timedatectl show -p Timezone --value 2>/dev/null || true
  elif [ -L /etc/localtime ]; then readlink /etc/localtime | sed 's#^.*/zoneinfo/##' || true
  elif [ -f /etc/timezone ]; then cat /etc/timezone || true
  fi
}
set_timezone(){
  local tz="$1"
  if command -v timedatectl >/dev/null 2>&1; then as_root timedatectl set-timezone "$tz"
  else
    if [ -f "/usr/share/zoneinfo/$tz" ]; then
      as_root ln -sf "/usr/share/zoneinfo/$tz" /etc/localtime
      echo "$tz" | as_root tee /etc/timezone >/dev/null || true
    else err "找不到时区文件：/usr/share/zoneinfo/$tz"; return 1; fi
  fi
  ok "时区已设置为：$tz"
}
check_timezone_on_install(){
  local cur; cur="$(get_current_tz || true)"; local target="Asia/Shanghai"
  if [ "$cur" != "$target" ]; then
    warn "检测到系统时区为：${cur:-未知}，不是北京时间(${target})"
    read -rp "是否将系统时区修改为 北京时间(${target})? (y/n): " ans || true
    case "${ans,,}" in y|yes) set_timezone "$target" ;; *) echo "保持当前时区：${cur:-未知}" ;; esac
  else ok "系统时区已是 北京时间(${target})"; fi
}
show_time_and_tz(){ local cur; cur="$(get_current_tz || true)"; ok "当前时区：${cur:-未知}"; date; }
interactive_set_tz(){ read -rp "请输入目标时区（例如 Asia/Shanghai）： " tz || true; [ -z "${tz:-}" ] && { echo "取消修改"; return 0; }; set_timezone "$tz"; show_time_and_tz; }

# ================== 安装状态 ==================
already_installed(){ [ -x "${INSTALL_DIR}/${APP_NAME}" ] && return 0 || service_exists; }

# ================== YAML 写入 ==================
remove_top_block(){
  local key="$1"
  [ -f "$CONFIG_FILE" ] || return 0
  local tmp; tmp="$(mktemp)"
  awk -v KEY="$key" '
    BEGIN{skip=0}
    $0 ~ "^[[:space:]]*"KEY":[[:space:]]*$" {skip=1; next}
    skip && /^[^[:space:]]/ {skip=0}
    !skip {print}
  ' "$CONFIG_FILE" > "$tmp" || true
  as_root install -m 0644 "$tmp" "$CONFIG_FILE"
  rm -f "$tmp"
}
yaml_q(){ local s="${1:-}"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; printf '"%s"' "$s"; }

append_logging_block(){
  local level="${1:-info}"
  [ -z "${level}" ] && { ok "取消覆盖 logging"; return 0; }
  echo "" | as_root tee -a "$CONFIG_FILE" >/dev/null
  as_root tee -a "$CONFIG_FILE" >/dev/null <<EOF
logging:
  level: $(yaml_q "$level")
EOF
}

# ---- PVE：含 SSH* 字段（不支持 %s 模板；ssh_private_key_pem 单行） ----
append_pve_block(){
  local base_url="${1:-}" token_id="${2:-}" secret="${3:-}"
  local ssh_base_url="${4:-}" ssh_user="${5:-}" ssh_password="${6:-}"
  local ssh_pem="${7:-}" ssh_passphrase="${8:-}"

  if [ -z "$base_url$token_id$secret$ssh_base_url$ssh_user$ssh_password$ssh_pem$ssh_passphrase" ]; then
    ok "取消覆盖 pve（未修改）"; return 0
  fi

  echo "" | as_root tee -a "$CONFIG_FILE" >/dev/null
  as_root tee -a "$CONFIG_FILE" >/dev/null <<EOF
pve:
  base_url: $(yaml_q "$base_url")
  token_id: $(yaml_q "$token_id")
  secret:   $(yaml_q "$secret")
  ssh_base_url: $(yaml_q "$ssh_base_url")
  ssh_user: $(yaml_q "$ssh_user")
  ssh_password: $(yaml_q "$ssh_password")
  ssh_private_key_pem: $(yaml_q "$ssh_pem")
  ssh_key_passphrase: $(yaml_q "$ssh_passphrase")
EOF
}

append_influx_block(){
  local base_url="${1:-}" token="${2:-}"
  if [ -z "$base_url$token" ]; then ok "取消覆盖 influxdb2（未修改）"; return 0; fi
  echo "" | as_root tee -a "$CONFIG_FILE" >/dev/null
  as_root tee -a "$CONFIG_FILE" >/dev不起
EOF
}
append_tls_block_to_yaml(){
  local cert="$1" key="$2" sni="$3"
  [ -f "$CONFIG_FILE" ] || { as_root install -d -m 0755 "$(dirname "$CONFIG_FILE")"; as_root touch "$CONFIG_FILE"; as_root chmod 0644 "$CONFIG_FILE"; }
  echo "" | as_root tee -a "$CONFIG_FILE" >/dev/null
  as_root tee -a "$CONFIG_FILE" >/dev/null <<EOF
tls:
  cert: "${cert}"
  key:  "${key}"
  sniGuard: "${sni}"
EOF
  ok "已写入/覆盖 tls 段：cert=${cert##*/} key=${key##*/}"
}

# ================== 配置文件初始生成 ==================
gen_jwt_secret(){
  if command -v openssl >/dev/null 2>&1; then openssl rand -base64 32 | tr '/+' '_-' | tr -d '\n'; return 0; fi
  if command -v base64  >/dev/null 2>&1; then head -c 32 /dev/urandom | base64 | tr '/+' '_-' | tr -d '\n'; return 0; fi
  if command -v xxd     >/dev/null 2>&1; then xxd -p -l 32 /dev/urandom | tr -d '\n'; return 0; fi
  od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
}
generate_config_file(){
  local jwt; jwt="$(gen_jwt_secret)"; [ -z "$jwt" ] && { err "生成 jwt_secret 失败"; exit 1; }
  : "${LOG_ENABLE:=false}"
  as_root install -d -m 0755 "$(dirname "$CONFIG_FILE")" "$DB_DIR" "$LOG_DIR"
  ok "生成配置文件：${CONFIG_FILE}"
  as_root tee "$CONFIG_FILE" >/dev/null <<EOF
# ${APP_NAME} 配置文件
db:
  forwarder:
    driver: sqlite #暂时未开放
    dsn: "file:${DB_DIR}/forwarder.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=page_size(32768)&_pragma=foreign_keys(ON)" #暂时未开放
    pool:
      max_open: 20
      max_idle: 10
      max_lifetime_sec: 600

  log:
    enable: ${LOG_ENABLE}
    driver: sqlite #暂时未开放
    dsn: "file:${DB_DIR}/log.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=page_size(32768)&_pragma=foreign_keys(ON)" #暂时未开放
    pool:
      max_open: 1
      max_idle: 1
      max_lifetime_sec: 0

admin:
  admin_ids: [1] #暂时未开放
  jwt_secret: "${jwt}" #暂时未开放
  token_ttl: 600 #暂时未开放

logging:
  level: "info"

pve:
  base_url: ""
  token_id: ""
  secret:   ""
  ssh_base_url: ""
  ssh_user: ""
  ssh_password: ""
  ssh_private_key_pem: ""
  ssh_key_passphrase: ""

influxdb2:
  base_url: ""
  token:    ""
EOF
  as_root chmod 0644 "$CONFIG_FILE"
}

# ================== acme 工具链 ==================
root_home(){ if command -v getent >/dev/null 2>&1; then getent passwd root | awk -F: '{print $6}'; else echo "/root"; fi; }

find_acme_bin(){
  local RH; RH="$(root_home)"
  local cands=("$RH/.acme.sh/acme.sh" "${HOME:-$RH}/.acme.sh/acme.sh" "/usr/local/bin/acme.sh" "/opt/acme.sh/acme.sh")
  local p; for p in "${cands[@]}"; do [ -f "$p" ] && { echo "$p"; return 0; }; done
  local f; for base in "$RH" "/usr/local" "/opt" "/home"; do
    [ -d "$base" ] || continue
    f="$(find "$base" -maxdepth 3 -type f -name acme.sh 2>/dev/null | head -n1 || true)"
    [ -n "$f" ] && { echo "$f"; return 0; }
  done
  return 1
}

ACME_BIN=""

ensure_acme_installed(){
  local email="$1"
  while ! is_valid_email "$email"; do
    email="$(prompt_clean '联系邮箱（必填，用于注册 CA；例如 user@example.com）: ' 0)"
    [ -z "${email:-}" ] && { warn "邮箱不能为空"; continue; }
    ! is_valid_email "$email" && err "邮箱格式不正确"
  done

  ACME_BIN="$(find_acme_bin || true)"
  if [ -z "$ACME_BIN" ]; then
    ok "安装 acme.sh ..."
    local RH; RH="$(root_home)"
    ensure_downloader
    if command -v curl >/dev/null 2>&1; then
      as_root env -i HOME="$RH" sh -c 'curl -fsSL https://get.acme.sh | sh -s email='"$email" 2>&1 || true
    else
      as_root env -i HOME="$RH" sh -c 'wget -O - https://get.acme.sh | sh -s email='"$email" 2>&1 || true
    fi
    for _ in $(seq 1 50); do
      ACME_BIN="$(find_acme_bin || true)"
      [ -n "$ACME_BIN" ] && break
      sleep 0.1
    done
  fi
  if [ -z "$ACME_BIN" ] || [ ! -f "$ACME_BIN" ]; then
    err "acme.sh 安装后仍未找到可执行文件：$(root_home)/.acme.sh/acme.sh"
    return 1
  fi
  ok "acme.sh 路径：$ACME_BIN"
  return 0
}

acme_run(){
  local RH; RH="$(root_home)"; [ -z "$ACME_BIN" ] && ACME_BIN="$(find_acme_bin || true)"
  as_root env -i HOME="$RH" PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    "$ACME_BIN" "$@" 2>&1
}

port80_busy(){
  if command -v ss >/dev/null 2>&1; then ss -lntp 2>/dev/null | grep -qE 'LISTEN.+:80(\s|$)'
  elif command -v netstat >/dev/null 2>&1; then netstat -lntp 2>/dev/null | awk '$6=="LISTEN" && $4 ~ /:80$/ {found=1} END{exit !found}'
  else return 1; fi
}
using_nginx(){ command -v ss >/dev/null 2>&1 || return 1; ss -lntp 2>/dev/null | grep -qE 'LISTEN.+:80 .*nginx'; }
using_apache(){ command -v ss >/dev/null 2>&1 || return 1; ss -lntp 2>/dev/null | grep -qE 'LISTEN.+:80 .*(apache2|httpd)'; }
stop_port80_services_if_needed(){
  if using_nginx;  then warn "临时停止 nginx 以释放 80 端口"; systemctl_req stop nginx  || true; ACME_STOPPED_NGINX="1"; fi
  if using_apache; then warn "临时停止 apache/httpd 以释放 80 端口"; systemctl_req stop apache2 || systemctl_req stop httpd || true; ACME_STOPPED_APACHE="1"; fi
}
restore_port80_services(){
  [ "${ACME_STOPPED_NGINX:-0}" = "1" ]  && { ok "恢复 nginx";  systemctl_req start nginx  || true; }
  [ "${ACME_STOPPED_APACHE:-0}" = "1" ] && { ok "恢复 apache/httpd"; systemctl_req start apache2 || systemctl_req start httpd || true; }
}

precheck_http01(){
  local d="$1"
  ok "HTTP-01 预检：$d"
  if port80_busy; then warn "本机 80 端口当前被占用"; else ok "本机 80 端口可用"; fi
  if command -v dig >/dev/null 2>&1; then
    local v4 v6; v4="$(dig +short A "$d"    | head -n1 || true)"; v6="$(dig +short AAAA "$d" | head -n1 || true)"
    [ -n "$v4" ] && ok "A 记录：$v4" || warn "未找到 A 记录"
    [ -n "$v6" ] && warn "检测到 AAAA 记录：$v6；若无公网 IPv6，请先移除或确保 v6 可达" || ok "无 AAAA 记录"
  fi
}

set_default_ca(){
  local server="letsencrypt"
  [ "$LETSENCRYPT_STAGING" = "1" ] && server="letsencrypt_test"
  ok "将使用 CA：$([ "$server" = "letsencrypt" ] && echo "Let's Encrypt 正式环境" || echo "Let's Encrypt 测试环境")"
  acme_run --set-default-ca --server "$server" || true
}

cert_paths(){ local d="$1"; local RH; RH="$(root_home)"; echo "${RH}/.acme.sh/${d}_ecc/fullchain.cer ${RH}/.acme.sh/${d}_ecc/${d}.key"; }
cert_valid_seconds(){
  local cert="$1"; [ -s "$cert" ] || { echo 0; return; }
  local end; end="$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null | cut -d= -f2 || true)"
  [ -n "$end" ] || { echo 0; return; }
  local end_ts; end_ts="$(date -d "$end" +%s 2>/dev/null || true)"
  local now_ts; now_ts="$(date +%s)"
  [ -n "$end_ts" ] || { echo 0; return; }
  echo $(( end_ts - now_ts ))
}

write_tls_block_and_maybe_restart(){
  local domain="$1" restart_now="$2"
  local cert key; read cert key < <(cert_paths "$domain")
  remove_top_block "tls"
  append_tls_block_to_yaml "$cert" "$key" "$domain"
  if [ "$restart_now" = "1" ] && service_exists; then
    systemctl_req restart "${APP_NAME}" || true
    ok "已重启服务：${APP_NAME}"
  fi
}

tls_issue_single(){ # $1 domain, $2 email, $3 restart_now(0/1)
  local domain="$1" email="$2" restart_now="${3:-0}"

  ensure_acme_installed "$email" || return 1
  set_default_ca

  local had_service=0
  if service_exists; then had_service=1; systemctl_req stop "${APP_NAME}" || true; fi
  if port80_busy; then
    stop_port80_services_if_needed
    if port80_busy; then
      read -rp "80 端口仍被占用，仍要继续签发？(y/n): " cont || true
      [[ "${cont,,}" =~ ^y ]] || { restore_port80_services; [ "$had_service" -eq 1 ] && systemctl_req start "${APP_NAME}" || true; return 1; }
    fi
  fi

  precheck_http01 "$domain"

  local RH; RH="$(root_home)"
  local conf="${RH}/.acme.sh/${domain}/${domain}.conf"
  local cert key; read cert key < <(cert_paths "$domain")
  local remain=0; [ -s "$cert" ] && remain="$(cert_valid_seconds "$cert")" || remain=0

  if [ "$remain" -gt 0 ]; then
    ok "检测到已有有效证书（剩余 $((remain/86400)) 天），不重新签发，仅覆盖配置"
  else
    if [ -f "$conf" ]; then
      ok "发现历史订单，执行强制续签：$domain"
      acme_run --renew -d "$domain" --force
    else
      ok "首次签发（standalone + ECC）：$domain"
      if ! acme_run --issue --standalone --listen-v6 --httpport 80 --ecc -d "$domain"; then
        warn "IPv6/80 失败，回退仅 IPv4"
        acme_run --issue --standalone --httpport 80 --ecc -d "$domain"
      fi
    fi
  fi

  write_tls_block_and_maybe_restart "$domain" "$restart_now"
  restore_port80_services
  [ "$had_service" -eq 1 ] && [ "$restart_now" != "1" ] && ok "安装阶段不重启，稍后随安装流程统一启动/重启"
  return 0
}

tls_request_single_interactive(){
  ok "==> 申请 tls 证书（HTTP-01，单域名；回车跳过）"
  while true; do
    d=""; e=""
    read -rp "请输入域名（单个；回车跳过）： " d || true
    [ -z "${d:-}" ] && { echo "跳过 tls 申请"; return 0; }
    is_valid_domain "$d" || { err "域名格式不正确"; continue; }
    while true; do
      read -rp "联系邮箱（必填，例如 user@example.com；回车取消）： " e || true
      [ -z "${e:-}" ] && { ok "已取消"; return 0; }
      is_valid_email "${e:-}" && break || err "邮箱格式不正确"
    done
    if tls_issue_single "$d" "$e" "0"; then
      return 0
    else
      warn "tls 申请失败，继续重试（回车直接跳过）"
    fi
  done
}

tls_renew_single_interactive(){
  ok "==> 续签 tls 证书（单域名，成功必覆盖配置并重启）"
  read -rp "输入要续签的域名（例如 example.com；回车取消）: " domain || true
  [ -z "${domain:-}" ] && { ok "已取消"; return 0; }
  is_valid_domain "${domain:-}" || { err "域名格式不正确"; return 1; }

  local email=""
  if ! find_acme_bin >/dev/null 2>&1; then
    while true; do
      read -rp "acme.sh 未安装，续签前先安装。请输入邮箱（必填；回车取消）: " email || true
      [ -z "${email:-}" ] && { ok "已取消"; return 0; }
      is_valid_email "${email:-}" && break || err "邮箱格式不正确"
    done
  fi
  ensure_acme_installed "${email:-nobody@example.invalid}" || return 1
  set_default_ca

  local cert key; read cert key < <(cert_paths "$domain")
  local remain=0; [ -s "$cert" ] && remain="$(cert_valid_seconds "$cert")" || remain=0

  local had_service=0
  if [ "$remain" -le 0 ]; then
    if service_exists; then had_service=1; systemctl_req stop "${APP_NAME}" || true; fi
    if port80_busy; then stop_port80_services_if_needed; fi
    ok "证书已过期/缺失，执行强制续签：$domain"
    acme_run --renew -d "$domain" --force || { err "续签失败：${domain}"; restore_port80_services; [ "$had_service" -eq 1 ] && systemctl_req start "${APP_NAME}" || true; return 1; }
    restore_port80_services
  else
    ok "证书尚未到期（剩余 $((remain/86400)) 天），不强制更新，仅覆盖配置"
  fi

  write_tls_block_and_maybe_restart "$domain" 1
}

tls_list(){
  local RH; RH="$(root_home)"
  local any=0
  for ddir in "$RH"/.acme.sh/*_ecc; do
    [ -d "$ddir" ] || continue
    any=1
    local d base cert key exp left
    base="$(basename "$ddir")"; d="${base%_ecc}"
    cert="$ddir/fullchain.cer"; key="$ddir/${d}.key"
    if [ -s "$cert" ]; then
      exp="$(openssl x509 -noout -enddate -in "$cert" 2>/dev/null | cut -d= -f2 || true)"
      left="$(cert_valid_seconds "$cert")"; left="$((left/86400))"
      printf "%b\n" "${GREEN}${d}${RESET}"
      echo "  cert : $cert"
      echo "  key  : $key"
      echo "  过期 : ${exp:-未知}（剩余 ${left} 天）"
    else
      printf "%b\n" "${YELLOW}${d}${RESET}"
      echo "  cert : $cert（不存在）"
      echo "  key  : $key"
    fi
  done
  [ "$any" -eq 1 ] || echo "未发现任何 *_ecc 证书目录"
}

# ================== 卸载/安装/服务 ==================
uninstall(){
  err "==> 卸载 ${APP_NAME}"
  systemctl_req stop "${APP_NAME}" || true
  systemctl_req disable "${APP_NAME}" || true
  as_root rm -f "/etc/systemd/system/${APP_NAME}.service" || true
  systemctl_req daemon-reload || true
  as_root rm -f "${INSTALL_DIR}/${APP_NAME}" || true
  as_root rm -rf "${CONFIG_FILE}" "${LOG_DIR}" "${DB_DIR}" "${FRONTEND_DIR}" "${CERT_DIR}" || true
  ok "卸载完成"
}

make_dirs(){ as_root install -d -m 0755 "$INSTALL_DIR" "$LOG_DIR" "$DB_DIR" "$FRONTEND_DIR" "$(dirname "$CONFIG_FILE")"; }

install_from_pkg_dir(){
  local IN="$1"
  local ROOT; ROOT="$(locate_pkg_root "$IN")"
  [ -n "$ROOT" ] || { err "无法识别安装包结构（未找到 $APP_NAME/bin/$APP_NAME 与 html/）"; exit 1; }
  make_dirs
  local BIN_LIN="${ROOT}/bin/${APP_NAME}"
  local BIN_WIN="${ROOT}/bin/${APP_NAME}.exe"
  local BIN_SRC=""
  if   [ -f "$BIN_LIN" ]; then BIN_SRC="$BIN_LIN"
  elif [ -f "$BIN_WIN" ]; then BIN_SRC="$BIN_WIN"
  else err "未找到可执行文件：${ROOT}/bin/${APP_NAME}[.exe]"; exit 1; fi
  as_root install -m 0755 "$BIN_SRC" "${INSTALL_DIR}/${APP_NAME}"
  ok "后端安装完成：${INSTALL_DIR}/${APP_NAME}"

  [ -d "${ROOT}/html" ] || { err "安装包缺少前端目录：${ROOT}/html"; exit 1; }
  as_root rm -rf "${FRONTEND_DIR:?}/"* || true
  as_root cp -a "${ROOT}/html/." "${FRONTEND_DIR}/"
  ok "前端安装完成：${FRONTEND_DIR}"
}

setup_service_linux(){
  ok "==> 创建并启用 systemd 服务"
  local UNIT="/etc/systemd/system/${APP_NAME}.service"
  as_root tee "$UNIT" >/dev/null <<EOF
[Unit]
Description=${APP_NAME} service
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${APP_NAME}
WorkingDirectory=${INSTALL_DIR}
Restart=always
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
  systemctl_req daemon-reload
  systemctl_req enable "${APP_NAME}"
  systemctl_req start "${APP_NAME}"
  ok "systemd 服务已创建并自启：${APP_NAME}"
}

enable_autostart(){ [ -f "/etc/systemd/system/${APP_NAME}.service" ] || { err "未发现 unit 文件"; return 1; }; systemctl_req enable "${APP_NAME}"; ok "已启用开机自启"; }
disable_autostart(){ [ -f "/etc/systemd/system/${APP_NAME}.service" ] || { err "未发现 unit 文件"; return 1; }; systemctl_req disable "${APP_NAME}"; ok "已取消开机自启"; }

# ================== 交互配置（覆盖+重启） ==================
configure_logging_interactive(){
  local lv
  while true; do
    lv="$(prompt_clean 'level（默认 info，debug/info/warn/error；回车取消）: ' 0)"
    [ -z "${lv:-}" ] && { ok "已取消"; return 0; }
    lv="$(to_lower "$lv")"
    case "$lv" in debug|info|warn|error) break ;; *) err "无效 level，请输入 debug/info/warn/error";; esac
  done
  remove_top_block "logging"
  append_logging_block "$lv"
  ok "已覆盖 logging.level = $lv"
  restart_if_active
}

configure_pve_interactive(){
  echo "覆盖 PVE（可回车留空；ssh_private_key_pem 仅单行；输入 '-' 清空该项）"
  local pve_url pve_tid pve_sec ssh_base ssh_user ssh_pass ssh_pem ssh_pp

  while true; do
    pve_url="$(prompt_clean 'base_url（http/https；回车跳过）: ' 0)"
    [ -z "${pve_url:-}" ] && break
    is_valid_url_http "$pve_url" && break || err "格式错误：示例 https://pve.example.com:8006"
  done
  pve_tid="$(prompt_clean 'token_id（回车跳过）: ' 0)"
  pve_sec="$(prompt_clean 'secret  （回车跳过）: ' 0)"

  while true; do
    ssh_base="$(prompt_clean 'ssh_base_url（host[:port]；例 pve01.example.com:22；回车=<node>:22）: ' 0)"
    [ -z "${ssh_base:-}" ] && break
    is_valid_ssh_base "$ssh_base" && break || err "格式错误：host[:port]；端口范围 1-65535；不支持 %s 模板"
  done

  while true; do
    ssh_user="$(prompt_clean 'ssh_user（默认 root，可留空）: ' 0)"; [ -z "${ssh_user:-}" ] && { ssh_user="root"; break; }
    is_valid_ssh_user "$ssh_user" && break || err "用户名不合法（字母/数字/._-，且不能以数字开头）"
  done

  ssh_pass="$(prompt_clean 'ssh_password（可留空；输入隐藏）: ' 1)"
  ssh_pem="$(prompt_clean 'ssh_private_key_pem（单行，可留空）: ' 0)"
  ssh_pp="$(prompt_clean 'ssh_key_passphrase（私钥解密口令，可留空；输入隐藏）: ' 1)"

  remove_top_block "pve"
  append_pve_block "${pve_url:-}" "${pve_tid:-}" "${pve_sec:-}" \
                   "${ssh_base:-}" "${ssh_user:-root}" "${ssh_pass:-}" \
                   "${ssh_pem:-}" "${ssh_pp:-}"
  ok "已覆盖 pve 配置（含 SSH 字段）"
  restart_if_active
}

configure_influx_interactive(){
  echo "覆盖 influxdb2（可回车留空；输入 '-' 清空该项）"
  local ifx_url ifx_token
  while true; do
    ifx_url="$(prompt_clean 'base_url（http/https；回车跳过）: ' 0)"
    [ -z "${ifx_url:-}" ] && break
    is_valid_url_http "$ifx_url" && break || err "格式错误：示例 http://influx.example.com:8086"
  done
  ifx_token="$(prompt_clean 'token   （回车跳过）: ' 0)"
  remove_top_block "influxdb2"
  # 这里原来贴文里误打断了，这里是正常块
  echo "" | as_root tee -a "$CONFIG_FILE" >/dev/null
  as_root tee -a "$CONFIG_FILE" >/dev/null <<EOF
influxdb2:
  base_url: $(yaml_q "${ifx_url:-}")
  token:    $(yaml_q "${ifx_token:-}")
EOF
  ok "已覆盖 influxdb2 配置"
  restart_if_active
}

# ================== 状态/日志页 ==================
status_page(){
  (
    trap 'echo; echo -e "'"${YELLOW}返回主菜单${RESET}"'"; exit 0' INT
    while true; do
      clear || true
      echo -e "${GREEN}==> 服务状态（每 1 秒刷新） [Ctrl+C 返回主菜单]${RESET}"
      systemctl_req status "${APP_NAME}" || true
      sleep 1
    done
  )
}
logs_page(){
  echo -e "${GREEN}==> 实时日志 [Ctrl+C 返回主菜单]${RESET}"
  (
    trap 'echo; echo -e "'"${YELLOW}返回主菜单${RESET}"'"; exit 0' INT
    as_root journalctl -u "${APP_NAME}" -f || true
  )
}
status(){ status_page; }
logf(){ logs_page; }
start(){ ok "==> 启动服务";   systemctl_req start "${APP_NAME}"; }
stop(){  err "==> 停止服务";  systemctl_req stop  "${APP_NAME}"; }
restart(){ ok "==> 重启服务"; systemctl_req restart "${APP_NAME}"; }

# ================== 安装主流程（单包；安装阶段不重启） ==================
install_flow(){
  if already_installed; then
    warn "检测到已安装。"
    echo "1) 卸载后安装"
    echo "0) 取消"
    read -rp "请选择 [1/0]: " act || true
    [[ "${act}" = "1" ]] || { echo "已取消"; return 0; }
    uninstall
  fi

  while true; do
    read -rp "是否启用流量日志? (y/n): " choice || true
    case "$(to_lower "${choice:-}")" in y|yes) LOG_ENABLE="true"; break ;; n|no) LOG_ENABLE="false"; break ;; *) echo "请输入 y 或 n." ;; esac
  done
  check_timezone_on_install
  generate_config_file

  echo "==> 步骤 1/4：申请 tls（HTTP-01，单域名；成功则覆盖 tls 段；安装阶段不重启）"
  tls_request_single_interactive || true

  echo "==> 步骤 2/4：配置 logging.level"
  configure_logging_interactive

  echo "==> 步骤 3/4：配置 pve"
  configure_pve_interactive

  echo "==> 步骤 4/4：配置 influxdb2"
  configure_influx_interactive

  # 下载并安装
  local PKG_TMP; PKG_TMP="$(mktemp -d)"
  local TARBALL="${PKG_TMP}/pkg.tar.gz"
  local url; url="$(build_pkg_url "$PKG_VERSION")"
  download_file "$url" "$TARBALL"
  ok "安装包下载成功"
  extract_pkg "$TARBALL" "$PKG_TMP"
  install_from_pkg_dir "$PKG_TMP"
  setup_service_linux
}

# ================== 菜单 ==================
while true; do
  printf "%b\n" "${GREEN}请选择操作:${RESET}"
  echo "0.  退出"
  echo "1.  安装（单包；含 tls/logging/pve/influxdb2 配置；安装阶段不重启）"
  echo "2.  启动"
  echo "3.  停止"
  echo "4.  重启"
  echo "5.  查看日志（Ctrl+C 返回）"
  echo "6.  卸载"
  echo "7.  启用开机自启"
  echo "8.  取消开机自启"
  echo "9.  查看服务状态（Ctrl+C 返回）"
  echo "10. 查看当前时间与时区"
  echo "11. 修改系统时区"
  echo "12.  申请 tls 证书（HTTP-01；单域名，成功后覆盖配置并重启）"
  echo "13.  续签 tls 证书（单域名，成功后覆盖配置并重启）"
  echo "14.  列出 tls 证书状态"
  echo "15. 配置 logging.level（覆盖+重启）"
  echo "16. 配置 pve（覆盖+重启）"
  echo "17. 配置 influxdb2（覆盖+重启）"
  read -rp "请输入操作编号 [0-17]: " choice || true

  case "${choice}" in
    0) exit 0 ;;
    1) install_flow ;;
    2) start ;;
    3) stop ;;
    4) restart ;;
    5) logf ;;
    6) uninstall ;;
    7) enable_autostart ;;
    8) disable_autostart ;;
    9) status ;;
    10) show_time_and_tz ;;
    11) interactive_set_tz ;;
    12)
      while true; do
        d=""; e=""
        read -rp "请输入域名（单个；回车返回菜单）： " d || true
        [ -z "${d:-}" ] && break
        is_valid_domain "$d" || { err "域名格式不正确"; continue; }
        while true; do
          read -rp "联系邮箱（必填，例如 user@example.com；回车返回菜单）： " e || true
          [ -z "${e:-}" ] && { ok "已取消"; break; }
          is_valid_email "${e:-}" && break || err "邮箱格式不正确"
        done
        [ -z "${e:-}" ] && break
        if tls_issue_single "$d" "$e" "1"; then break; else warn "签发失败，继续重试（回车返回菜单）"; fi
      done
      ;;
    13) tls_renew_single_interactive ;;
    14) tls_list ;;
    15) configure_logging_interactive ;;
    16) configure_pve_interactive ;;
    17) configure_influx_interactive ;;
    *) err "无效选项" ;;
  esac
  echo
done
