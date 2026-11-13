#!/usr/bin/env bash
# att-tunnel-hub 一键安装脚本
#
#   机器1 面板机：  ./install.sh --panel
#   机器2/3 转发机：./install.sh -a <面板地址> -s <密钥>
#                   （这条命令由面板里「添加转发机」自动生成，复制粘贴即可，全程零交互）
#   落地机：        由转发机面板里「添加落地机」生成命令，走 att-tunnel 原生流程
#
# 架构：面板机不过流量；转发机 = att-tunnel A 端 + agent（主动回连面板）；
#       落地机 = att-tunnel B 端，主动外拨连转发机，与节点 1:1。
set -Eeuo pipefail

VERSION="1.11.4"
# att-tunnel 网页面板（--web）和「添加节点可填 SSH 直装出口机」都还在 PR #2 分支上，
# main 仍是 v2.0.0。先固定到含 SSH 直装和链接二维码 / 订阅的提交；PR #2 合并后改回 main。
ATT_REPO_RAW="${ATT_REPO_RAW:-https://raw.githubusercontent.com/dabao9037/att-tunnel/ee0c9368e8a5337847846e7ebd8cb0ea4d6bb729/install.sh}"
HUB_RAW_URL="${HUB_RAW_URL:-https://raw.githubusercontent.com/dabao9037/att-tunnel-hub/main/install.sh}"
# 转发机装 att-tunnel 入口端时用的 REALITY 伪装域名。取 att-tunnel 预置列表第一个；
# 万一它不支持 TLS 1.3，att-tunnel 自己会换成预置列表里可用的那个，不会回头问人。
# 需要指定时加 -d <域名>。
DEFAULT_SNI="${ATT_HUB_SNI:-www.debian.org}"

HUB_DIR=/usr/local/lib/att-hub
HUB_ETC=/etc/att-hub
HUB_STATE=/var/lib/att-hub
AG_DIR=/usr/local/lib/att-hub-agent
AG_ETC=/etc/att-hub-agent

RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; CYN=$'\e[36m'; RST=$'\e[0m'
info(){ echo "${CYN}==>${RST} $*"; }
ok(){   echo "${GRN}[OK]${RST} $*"; }
warn(){ echo "${YEL}[!]${RST} $*"; }
die(){  echo "${RED}[X]${RST} $*" >&2; exit 1; }

trap 'die "第 $LINENO 行出错，已停止"' ERR

need_root(){ [ "$(id -u)" = 0 ] || die "请用 root 运行"; }

have(){ command -v "$1" >/dev/null 2>&1; }

# ==================== 屏蔽 SVCB(64) / HTTPS(65) DNS 记录 ====================
# 这两类记录会把 ipv4hint / ipv6hint（真实地址）和 ech（加密 SNI 配置）直接写进
# DNS 应答。在 Fake-IP 代理体系下，客户端拿到 hint 会绕过假 IP 直连，alpn=h3 又会
# 把流量推进 QUIC(UDP/443)，结果是既走不成代理，也把出口 IP 与 DNS 一起漏出去。
#
# 过滤掉这两种 RR 后，客户端按 RFC 9460/9461 自动回退到 A/AAAA + h2，业务功能不受
# 影响；代价只是失去 HTTP/3 与 ECH。
#
# 依赖 dnsmasq >= 2.86（filter-rr 在 2.86 引入）。版本不够时跳过而不是把系统 DNS
# 改坏。关闭方式：SVCB_BLOCK=0，或执行 dns-unblock 子命令。
# ==========================================================================
SVCB_BLOCK="${SVCB_BLOCK:-1}"
SVCB_ETC="${SVCB_ETC:-/etc}"
SVCB_RESOLV="${SVCB_RESOLV:-/etc/resolv.conf}"
SVCB_CONF="${SVCB_CONF:-$SVCB_ETC/svcb-dns-filter.conf}"
SVCB_UNIT="${SVCB_UNIT:-$SVCB_ETC/systemd/system/svcb-dns-filter.service}"
SVCB_BAK="${SVCB_BAK:-$SVCB_RESOLV.svcb-block.bak}"
SVCB_MODE_FILE="${SVCB_MODE_FILE:-$SVCB_ETC/svcb-dns-filter.mode}"
SVCB_RESOLVED_DROPIN="${SVCB_RESOLVED_DROPIN:-$SVCB_ETC/systemd/resolved.conf.d/90-svcb-block.conf}"
SVCB_NM_DROPIN="${SVCB_NM_DROPIN:-$SVCB_ETC/NetworkManager/conf.d/90-svcb-block.conf}"
SVCB_SHARED_CONF="${SVCB_SHARED_CONF:-$SVCB_ETC/dnsmasq.d/svcb-block.conf}"
SVCB_LISTEN="${SVCB_LISTEN:-127.0.0.1}"
SVCB_TAG="svcb-dns-filter"
SVCB_SVC="$SVCB_TAG.service"

svcb_version() {
  dnsmasq --version 2>/dev/null | sed -n '1s/.*version \([0-9][0-9.]*\).*/\1/p'
}

svcb_version_ok() {
  local v; v="$(svcb_version || true)"
  [ -n "$v" ] || return 1
  [ "$(printf '%s\n2.86\n' "$v" | sort -V 2>/dev/null | sed -n '1p')" = "2.86" ]
}

svcb_is_on() {
  [ -f "$SVCB_CONF" ] || [ -f "$SVCB_SHARED_CONF" ]
}

svcb_active() {
  systemctl is-active --quiet "$SVCB_SVC" 2>/dev/null
}

svcb_install_dnsmasq() {
  info "安装 dnsmasq（SVCB/HTTPS 过滤依赖 filter-rr）"
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dnsmasq >/dev/null 2>&1 || return 1
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q dnsmasq >/dev/null 2>&1 || return 1
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q dnsmasq >/dev/null 2>&1 || return 1
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache dnsmasq >/dev/null 2>&1 || return 1
  else
    return 1
  fi
  command -v dnsmasq >/dev/null 2>&1
}

# 沿用系统现有的上游，避免把解析路径换成别处不通的公共 DNS。
# 必须剔除所有环回地址：本脚本自己就把 resolv.conf 指向 127.0.0.1，
# 一旦把 127.0.0.1 当成上游就会自环，整台机器的 DNS 立刻死掉。
svcb_upstreams() {
  { awk '/^[[:space:]]*nameserver[[:space:]]/{print $2}' "$SVCB_RESOLV" 2>/dev/null || true
    awk '/^[[:space:]]*nameserver[[:space:]]/{print $2}' /run/systemd/resolve/resolv.conf 2>/dev/null || true
    # 第三来源：本脚本自己写下的 resolv.conf 备份。
    # 一旦 SVCB_RESOLV 已被改成 127.0.0.1，前两个来源就都是空/环回，只剩这份还留着
    # 真实上游 —— 历史版本正是漏了这一步，导致 shared 模式下 dnsmasq 上游为空。
    if [ -f "$SVCB_BAK" ]; then
      grep -vE '^(symlink:|absent$)' "$SVCB_BAK" 2>/dev/null \
        | awk '/^[[:space:]]*nameserver[[:space:]]/{print $2}' || true
    fi
  } | grep -vE '^127\.|^::1$|^0\.0\.0\.0$|^localhost$' | awk '!seen[$0]++' | sed -n '1,3p'
}

svcb_backup_resolv() {
  [ -e "$SVCB_BAK" ] && return 0
  if [ -L "$SVCB_RESOLV" ]; then
    printf 'symlink:%s\n' "$(readlink "$SVCB_RESOLV" 2>/dev/null || true)" > "$SVCB_BAK"
  elif [ -f "$SVCB_RESOLV" ]; then
    cp -a "$SVCB_RESOLV" "$SVCB_BAK"
  else
    printf 'absent\n' > "$SVCB_BAK"
  fi
}

svcb_restore_resolv() {
  [ -e "$SVCB_BAK" ] || return 0
  if grep -q '^symlink:' "$SVCB_BAK" 2>/dev/null; then
    ln -sfn "$(sed -n 's/^symlink://p' "$SVCB_BAK")" "$SVCB_RESOLV" 2>/dev/null || true
  elif grep -q '^absent$' "$SVCB_BAK" 2>/dev/null; then
    rm -f "$SVCB_RESOLV" 2>/dev/null || true
  else
    rm -f "$SVCB_RESOLV" 2>/dev/null || true
    cp -a "$SVCB_BAK" "$SVCB_RESOLV" 2>/dev/null || true
  fi
  rm -f "$SVCB_BAK" 2>/dev/null || true
}

# systemd-resolved 的 stub 占着 127.0.0.53:53，NetworkManager 会重写 resolv.conf
svcb_release_53() {
  if systemctl is-active --quiet systemd-resolved 2>/dev/null && [ ! -f "$SVCB_RESOLVED_DROPIN" ]; then
    mkdir -p "$(dirname "$SVCB_RESOLVED_DROPIN")" 2>/dev/null || true
    printf '[Resolve]\nDNSStubListener=no\n' > "$SVCB_RESOLVED_DROPIN"
    systemctl restart systemd-resolved >/dev/null 2>&1 || true
  fi
  if systemctl is-active --quiet NetworkManager 2>/dev/null && [ ! -f "$SVCB_NM_DROPIN" ]; then
    mkdir -p "$(dirname "$SVCB_NM_DROPIN")" 2>/dev/null || true
    printf '[main]\ndns=none\n' > "$SVCB_NM_DROPIN"
    systemctl reload NetworkManager >/dev/null 2>&1 || systemctl restart NetworkManager >/dev/null 2>&1 || true
  fi
  sleep 1
}

svcb_write_conf() {
  local upstreams="$1" s
  mkdir -p "$(dirname "$SVCB_CONF")" 2>/dev/null || true
  {
    printf '# %s\n' "$SVCB_TAG"
    printf '# 过滤 SVCB(64)/HTTPS(65)：阻断 Fake-IP 下的 hint 直连与 QUIC 旁路\n'
    printf 'port=53\n'
    printf 'no-resolv\n'
    while IFS= read -r s; do
      [ -n "$s" ] && printf 'server=%s\n' "$s"
    done <<< "$upstreams"
    printf 'listen-address=%s\n' "$SVCB_LISTEN"
    printf 'bind-dynamic\n'
    printf 'cache-size=2000\n'
    printf 'filter-rr=HTTPS\n'
    printf 'filter-rr=SVCB\n'
  } > "$SVCB_CONF"
  chmod 644 "$SVCB_CONF" 2>/dev/null || true
}

svcb_write_unit() {
  local bin; bin="$(command -v dnsmasq || true)"
  [ -n "$bin" ] || return 1
  mkdir -p "$(dirname "$SVCB_UNIT")" 2>/dev/null || true
  cat > "$SVCB_UNIT" <<UNIT
[Unit]
Description=SVCB/HTTPS DNS 记录过滤器 (dnsmasq)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$bin --keep-in-foreground --conf-file=$SVCB_CONF
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload >/dev/null 2>&1 || true
}

svcb_write_resolv() {
  rm -f "$SVCB_RESOLV" 2>/dev/null || true
  cat > "$SVCB_RESOLV" <<RESOLV
# $SVCB_TAG: 已过滤 SVCB/HTTPS 记录
nameserver 127.0.0.1
options timeout:2 attempts:3
RESOLV
  chmod 644 "$SVCB_RESOLV" 2>/dev/null || true
}

svcb_port_ready() {
  local _i out=""
  for _i in 1 2 3 4 5 6 7 8 9 10; do
    out="$(ss -Hlun 2>/dev/null | awk '{print $4}' | grep -E '(^|:)53$' 2>/dev/null || true)"
    [ -n "$out" ] && return 0
    sleep 1
  done
  return 1
}

svcb_verify() {
  local a h
  if ! command -v dig >/dev/null 2>&1; then
    info "本机未装 dig，跳过查询验证（仅确认服务与端口）"
    return 0
  fi
  # 先用 A 记录证明这条解析链路是通的，否则"查不到 HTTPS"毫无意义
  a="$(dig +short +time=3 +tries=1 A example.com @127.0.0.1 2>/dev/null | grep -v '^;;' | sed -n '1p' || true)"
  if [ -z "$a" ]; then
    warn "无法从 127.0.0.1 解析 A 记录，DNS 链路未就绪"
    return 1
  fi
  h="$(dig +short +time=3 +tries=1 HTTPS example.com @127.0.0.1 2>/dev/null | grep -v '^;;' || true)"
  [ -z "$h" ] && h="$(dig +short +time=3 +tries=1 SVCB example.com @127.0.0.1 2>/dev/null | grep -v '^;;' || true)"
  if [ -z "$h" ]; then
    ok "验证通过：A 记录正常，HTTPS/SVCB 返回空（已过滤）"
    return 0
  fi
  warn "验证未通过，HTTPS/SVCB 仍可解析：$(printf '%s' "$h" | tr '\n' ' ')"
  return 1
}

svcb_status() {
  local v; v="$(svcb_version || true)"
  info "DNS 过滤状态"
  printf '  dnsmasq 版本 : %s\n' "${v:-未安装}"
  printf '  模式文件     : %s\n' "$([ -f "$SVCB_MODE_FILE" ] && cat "$SVCB_MODE_FILE" || echo 未启用)"
  if svcb_active; then
    printf '  独立服务     : %s（运行中）\n' "$SVCB_SVC"
  else
    printf '  独立服务     : 未运行\n'
  fi
  printf '  共享配置     : %s\n' "$([ -f "$SVCB_SHARED_CONF" ] && echo 存在 || echo 无)"
  printf '  系统解析     : %s\n' "$(awk '/^[[:space:]]*nameserver/{print $2}' "$SVCB_RESOLV" 2>/dev/null | tr '\n' ' ')"
  printf '  上游         : %s\n' "$(svcb_upstreams | tr '\n' ' ')"
  svcb_verify || true
}

# 关闭：停服务、删配置、还原 resolv.conf 与 resolved stub
svcb_disable() {
  local mode="dedicated"
  [ -f "$SVCB_MODE_FILE" ] && mode="$(cat "$SVCB_MODE_FILE" 2>/dev/null || echo dedicated)"
  if [ "$mode" = "shared" ]; then
    rm -f "$SVCB_SHARED_CONF" 2>/dev/null || true
    systemctl reload dnsmasq >/dev/null 2>&1 || systemctl restart dnsmasq >/dev/null 2>&1 || true
  else
    systemctl disable --now "$SVCB_SVC" >/dev/null 2>&1 || true
    rm -f "$SVCB_UNIT" "$SVCB_CONF" 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  rm -f "$SVCB_RESOLVED_DROPIN" "$SVCB_NM_DROPIN" 2>/dev/null || true
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    systemctl restart systemd-resolved >/dev/null 2>&1 || true
  fi
  if systemctl is-active --quiet NetworkManager 2>/dev/null; then
    systemctl reload NetworkManager >/dev/null 2>&1 || true
  fi
  svcb_restore_resolv
  rm -f "$SVCB_MODE_FILE" 2>/dev/null || true
  ok "已关闭 SVCB/HTTPS 记录过滤，DNS 配置已还原"
}

# 修复历史版本写下的「半成品」shared 配置（缺 no-resolv + server=）。
#
# 判定依据只看 no-resolv：新版本一定会写它，旧版本一定没有。命中就整份重写成
# 带上游的形态并重启 dnsmasq —— 已坏的机器跑一次 dns-block 即可自愈，不必手工救。
# 恒返回 0，不阻断 svcb_enable 后续流程。
svcb_repair_shared() {
  [ -f "$SVCB_SHARED_CONF" ] || return 0
  grep -qE '^[[:space:]]*no-resolv' "$SVCB_SHARED_CONF" 2>/dev/null && return 0
  local ups; ups="$(svcb_upstreams || true)"
  [ -n "$ups" ] || ups="${SVCB_UPSTREAM:-1.1.1.1 8.8.8.8}"
  info "检测到旧版 shared DNS 配置缺上游（会导致整机解析失败），正在修复"
  {
    printf '# %s\n' "$SVCB_TAG"
    printf '# 上游显式钉死（修复版）：resolv.conf 已指向 127.0.0.1，不能再当上游来源\n'
    printf 'no-resolv\n'
    printf 'no-poll\n'
    while IFS= read -r _svcb_up; do
      if [ -n "$_svcb_up" ]; then printf 'server=%s\n' "$_svcb_up"; fi
    done <<< "$ups"
    printf 'filter-rr=HTTPS\n'
    printf 'filter-rr=SVCB\n'
  } > "$SVCB_SHARED_CONF"
  if systemctl restart dnsmasq >/dev/null 2>&1; then
    ok "shared DNS 配置已修复（上游：$(printf '%s' "$ups" | tr '\n' ' ')）"
  else
    warn "dnsmasq 重启失败，配置已写好，下次启用时会再试一次"
  fi
  return 0
}

# 开启：幂等；任何一步失败都回滚，不把系统 DNS 弄坏
svcb_enable() {
  if [ "$SVCB_BLOCK" != "1" ]; then
    info "SVCB_BLOCK=$SVCB_BLOCK，跳过 SVCB/HTTPS 记录过滤"
    return 0
  fi
  if [ "$(id -u)" != "0" ]; then
    warn "非 root，跳过 SVCB/HTTPS 记录过滤"
    return 0
  fi
  # 自愈：历史版本的 shared 配置只写了 filter-rr，没写 no-resolv/server=，
  # 而 svcb_write_resolv 又把 resolv.conf 指向 127.0.0.1 —— 于是 dnsmasq 上游为空、
  # 整机解析 REFUSED（2026-11-08 秘书3 事故）。每次启用前先补一次，幂等。
  svcb_repair_shared
  # 幂等：服务在跑、配置还在、或者上次已经标记过模式，都直接返回
  if svcb_active || svcb_is_on || [ -f "$SVCB_MODE_FILE" ]; then
    ok "SVCB/HTTPS 记录过滤已启用"
    return 0
  fi

  command -v dnsmasq >/dev/null 2>&1 || svcb_install_dnsmasq || {
    warn "dnsmasq 安装失败，跳过 SVCB/HTTPS 过滤（不影响其他功能）"
    return 0
  }
  if ! svcb_version_ok; then
    warn "dnsmasq $(svcb_version || echo 未知) 低于 2.86，无 filter-rr，跳过过滤"
    return 0
  fi

  local upstreams mode="dedicated"
  upstreams="$(svcb_upstreams || true)"
  [ -n "$upstreams" ] || upstreams="${SVCB_UPSTREAM:-1.1.1.1 8.8.8.8}"

  # 已有 dnsmasq 在跑：注入配置，不另建实例、不动别人的 dnsmasq
  if systemctl is-active --quiet dnsmasq 2>/dev/null; then
    mode="shared"
  fi

  svcb_backup_resolv || true
  svcb_release_53 || true

  if [ "$mode" = "shared" ]; then
    mkdir -p "$(dirname "$SVCB_SHARED_CONF")" 2>/dev/null || true
    {
      printf '# %s\n' "$SVCB_TAG"
      printf '# 上游必须显式钉死：下面 svcb_write_resolv 会把 /etc/resolv.conf 指向\n'
      printf '# 127.0.0.1，若 dnsmasq 仍按 resolv.conf 取上游就是自环，上游列表为空，\n'
      printf '# 整机域名解析一律 REFUSED（2026-11-08 秘书3「更新后没网」事故）。\n'
      printf 'no-resolv\n'
      printf 'no-poll\n'
      while IFS= read -r _svcb_up; do
        if [ -n "$_svcb_up" ]; then printf 'server=%s\n' "$_svcb_up"; fi
      done <<< "$upstreams"
      printf 'filter-rr=HTTPS\n'
      printf 'filter-rr=SVCB\n'
    } > "$SVCB_SHARED_CONF"
    if ! grep -qE '^[[:space:]]*conf-dir=/etc/dnsmasq\.d' /etc/dnsmasq.conf 2>/dev/null; then
      printf '\nconf-dir=/etc/dnsmasq.d/,*.conf\n' >> /etc/dnsmasq.conf 2>/dev/null || true
    fi
    if ! systemctl restart dnsmasq >/dev/null 2>&1; then
      warn "现有 dnsmasq 重启失败，回滚"
      rm -f "$SVCB_SHARED_CONF" 2>/dev/null || true
      svcb_restore_resolv
      return 0
    fi
  else
    # 发行版自带 unit 先让位，避免抢 53
    if systemctl is-enabled --quiet dnsmasq 2>/dev/null; then
      systemctl disable --now dnsmasq >/dev/null 2>&1 || true
    fi
    svcb_write_conf "$upstreams" || { warn "写配置失败，跳过"; svcb_restore_resolv; return 0; }
    svcb_write_unit || { warn "写 service 失败，跳过"; rm -f "$SVCB_CONF"; svcb_restore_resolv; return 0; }
    if ! systemctl enable --now "$SVCB_SVC" >/dev/null 2>&1; then
      warn "过滤服务启动失败，回滚"
      systemctl disable --now "$SVCB_SVC" >/dev/null 2>&1 || true
      rm -f "$SVCB_UNIT" "$SVCB_CONF" 2>/dev/null || true
      systemctl daemon-reload >/dev/null 2>&1 || true
      svcb_restore_resolv
      return 0
    fi
  fi

  if ! svcb_port_ready; then
    warn "53 端口未就绪，回滚 DNS 配置"
    svcb_disable >/dev/null 2>&1 || true
    return 0
  fi

  printf '%s\n' "$mode" > "$SVCB_MODE_FILE" 2>/dev/null || true
  svcb_write_resolv
  ok "已启用 SVCB/HTTPS 记录过滤（$mode 模式，上游：$(printf '%s' "$upstreams" | tr '\n' ' ')）"
  # 验证失败必须回滚，不能把机器留在一个「过滤生效但解析全死」的状态。
  # 宁可暂时没有 DNS 过滤，也不能让转发机失去解析能力（2026-11-08 教训）。
  if ! svcb_verify; then
    warn "验证未通过：解析链路不可用，回滚 DNS 配置以免整机断网"
    svcb_disable >/dev/null 2>&1 || true
    return 0
  fi
  return 0
}
# ================== 屏蔽 SVCB/HTTPS 记录 · 结束 ==================

install_deps(){
  have python3 || { info "安装 python3"; apt-get update -qq && apt-get install -y -qq python3; }
  have curl || apt-get install -y -qq curl
  python3 -c 'import sys; sys.exit(0 if sys.version_info>=(3,8) else 1)' \
    || die "需要 python3 >= 3.8"
}

free_port(){
  python3 - <<'PY'
import socket
s=socket.socket(); s.bind(('127.0.0.1',0)); print(s.getsockname()[1]); s.close()
PY
}

rand_hex(){ python3 -c 'import secrets;print(secrets.token_hex(8))'; }
rand_pass(){ python3 -c 'import secrets;print(secrets.token_urlsafe(12))'; }

pubip(){
  local ip
  for u in https://api.ipify.org https://icanhazip.com https://ifconfig.me/ip; do
    ip=$(curl -fsS4 --max-time 8 "$u" 2>/dev/null | tr -d '[:space:]') || true
    [ -n "${ip:-}" ] && { echo "$ip"; return 0; }
  done
  return 1
}

# 从本仓库取一个静态资源（JS/CSS，不做 Python 语法检查）
fetch_asset(){
  local name="$1" dest="$2" src
  src="$(dirname "${BASH_SOURCE[0]}")/$name"
  if [ -f "$src" ]; then
    cp "$src" "$dest"
  else
    curl -fsSL "${HUB_RAW_URL%/install.sh}/$name?ts=$(date +%s)" -o "$dest" \
      || die "下载 $name 失败"
  fi
  chmod 644 "$dest"
}

# 从本仓库取一个文件（hub.py / agent.py）：优先同目录（本地调试），否则按 RAW 地址拉
fetch_file(){
  local name="$1" dest="$2" src
  src="$(dirname "${BASH_SOURCE[0]}")/$name"
  if [ -f "$src" ]; then
    cp "$src" "$dest"
  else
    curl -fsSL "${HUB_RAW_URL%/install.sh}/$name" -o "$dest" \
      || die "下载 $name 失败"
  fi
  sed -i "s/HUB_VERSION/$VERSION/g" "$dest"
  python3 -c "import ast,sys; ast.parse(open(sys.argv[1]).read())" "$dest" \
    || die "$name 语法检查不通过"
  chmod 700 "$dest"
}

# ---------------------------------------------------------------- 面板机（机器1）
install_panel(){
  need_root; install_deps

  local port path pass hub_url listen secure trust
  mkdir -p "$HUB_DIR" "$HUB_ETC" "$HUB_STATE"
  chmod 700 "$HUB_ETC" "$HUB_STATE"

  if [ -f "$HUB_ETC/hub.env" ]; then
    info "已有配置，保留端口/路径/密码，只更新程序"
    cp -a "$HUB_ETC/hub.env" "$HUB_ETC/hub.env.bak.$(date +%s)"
    # shellcheck disable=SC1091
    port=$(grep -E '^WEB_PORT=' "$HUB_ETC/hub.env" | cut -d= -f2)
    path=$(grep -E '^WEB_PATH=' "$HUB_ETC/hub.env" | cut -d= -f2)
    pass=$(grep -E '^WEB_PASS=' "$HUB_ETC/hub.env" | cut -d= -f2)
    # 域名/HTTPS 相关设置也要保留，否则升级会把地址打回 IP、把监听放回 0.0.0.0
    hub_url="${HUB_URL:-$(grep -E '^HUB_URL=' "$HUB_ETC/hub.env" | cut -d= -f2- || true)}"
    listen="${HUB_LISTEN:-$(grep -E '^WEB_LISTEN=' "$HUB_ETC/hub.env" | cut -d= -f2 || true)}"
    secure="${HUB_COOKIE_SECURE:-$(grep -E '^WEB_COOKIE_SECURE=' "$HUB_ETC/hub.env" | cut -d= -f2 || true)}"
    trust="${HUB_TRUST_PROXY:-$(grep -E '^WEB_TRUST_PROXY=' "$HUB_ETC/hub.env" | cut -d= -f2 || true)}"
  else
    port="${HUB_PORT:-$(free_port)}"
    path="${HUB_PATH:-$(rand_hex)}"
    pass="${HUB_PASS:-$(rand_pass)}"
  fi

  hub_url="${hub_url:-${HUB_URL:-}}"
  listen="${listen:-${HUB_LISTEN:-0.0.0.0}}"
  secure="${secure:-${HUB_COOKIE_SECURE:-0}}"
  trust="${trust:-${HUB_TRUST_PROXY:-0}}"
  if [ -z "$hub_url" ]; then
    local ip; ip=$(pubip) || die "取不到公网 IP，请用 HUB_URL=http://你的IP:端口/路径 指定"
    hub_url="http://$ip:$port/$path"
  fi

  fetch_file hub.py "$HUB_DIR/hub.py"
  fetch_file sshterm.py "$HUB_DIR/sshterm.py"
  mkdir -p "$HUB_DIR/static"
  fetch_asset static/xterm.js "$HUB_DIR/static/xterm.js"
  fetch_asset static/xterm.css "$HUB_DIR/static/xterm.css"
  fetch_asset static/addon-fit.js "$HUB_DIR/static/addon-fit.js"
  fetch_asset static/addon-webgl.js "$HUB_DIR/static/addon-webgl.js"

  cat > "$HUB_ETC/hub.env" <<EOF
# att-tunnel-hub 面板配置（v$VERSION）
WEB_PORT=$port
WEB_PATH=$path
WEB_PASS=$pass
# 默认监听 0.0.0.0；套了 nginx/域名 后改成 127.0.0.1 更安全
WEB_LISTEN=$listen
# agent 回连用的面板外网地址（带根路径）
HUB_URL=$hub_url
# 生成一键代码用的本脚本地址
HUB_RAW_URL=$HUB_RAW_URL
# 上了 HTTPS 后改 1
WEB_COOKIE_SECURE=$secure
# 在 nginx 后面时改 1，让登录限速看真实 IP
WEB_TRUST_PROXY=$trust
EOF
  chmod 600 "$HUB_ETC/hub.env"

  write_panel_unit
  systemctl daemon-reload
  systemctl enable att-hub >/dev/null 2>&1 || true
  # 必须 restart：服务已在跑时 enable --now 会直接成功，|| restart 永远不触发，
  # 结果新代码落了盘但还是老进程在对外服务（升级看不到新功能）。
  systemctl restart att-hub
  sleep 1
  systemctl is-active --quiet att-hub || { journalctl -u att-hub -n 20 --no-pager; die "面板启动失败"; }

  open_fw "$port"
  echo
  ok "面板机安装完成"
  echo "  地址：${CYN}$hub_url/${RST}"
  echo "  密码：${CYN}$pass${RST}"
  echo
  echo "下一步：登录面板 → 「＋ 添加转发机」填转发机 IP → 把生成的一键代码跑在转发机上"
  echo "管理命令：${CYN}att-hub${RST}（看地址/改密码/重启/卸载）"
}

# ---------------------------------------------------------------- systemd / 防火墙
write_panel_unit(){
  cat > /etc/systemd/system/att-hub.service <<EOF
[Unit]
Description=att-tunnel-hub panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $HUB_DIR/hub.py
Environment=HUB_ENV=$HUB_ETC/hub.env
Environment=HUB_STATE=$HUB_STATE/state.json
Environment=PYTHONUNBUFFERED=1
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF
}

write_agent_unit(){
  cat > /etc/systemd/system/att-hub-agent.service <<EOF
[Unit]
Description=att-tunnel-hub agent (forwarder)
After=network-online.target att-tunnel.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $AG_DIR/agent.py
Environment=AGENT_ENV=$AG_ETC/agent.env
Environment=PYTHONUNBUFFERED=1
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
}

open_fw(){
  local p="$1"
  if have ufw && ufw status 2>/dev/null | grep -q '^Status: active'; then
    ufw allow "$p/tcp" >/dev/null 2>&1 && info "ufw 已放行 $p/tcp" || true
  fi
  warn "云厂商安全组记得放行 $p/tcp"
}


# ---------------------------------------------------------------- 端口日流量限额
QUOTA_DIR=/usr/local/lib/att-quota
QUOTA_ETC=/etc/att-quota
QUOTA_STATE=/var/lib/att-quota

install_quota(){
  local ports wg
  [ -f /etc/att-tunnel/a.env ] || { warn "没有 a.env，跳过流量限额"; return 0; }
  # 端口以实际 config.json 为准（a.env 的 USER_PORT 可能停留在迁移前的值）
  ports=$(python3 - <<'PY' 2>/dev/null || true
import json
d=json.load(open('/usr/local/etc/att-tunnel/config.json'))
for i in d.get('inbounds',[]):
    tag=str(i.get('tag',''))
    if tag=='probe-in' or tag.startswith('probe'):
        continue
    p=i.get('port')
    if isinstance(p,int) and p>0:
        print('tcp:%d'%p)
PY
)
  wg=$(python3 -c "import json;print(json.load(open('/etc/att-tunnel/wg.json')).get('port',''))" 2>/dev/null || true)
  [ -n "$wg" ] && ports="$ports udp:$wg"
  ports=$(echo $ports | tr ' ' '\n' | sort -u | tr '\n' ' ')
  [ -n "$ports" ] || { warn "读不到 att-tunnel 端口，跳过限额"; return 0; }
  mkdir -p "$QUOTA_DIR" "$QUOTA_ETC" "$(dirname "$QUOTA_STATE")"
  fetch_file quota2.py "$QUOTA_DIR/quota.py" || { warn "quota.py 下载失败，跳过限额"; return 0; }
  chmod 700 "$QUOTA_DIR/quota.py"
  umask 077
  cat > "$QUOTA_ETC/quota.env" <<EOF
# att-tunnel 端口日流量限额（北京时间 00:00 重置）
HUB_URL=$hub
HUB_TOKEN=$token
PORTS=$ports
THRESHOLD=${ATT_QUOTA_THRESHOLD:-50G}
EOF
  chmod 600 "$QUOTA_ETC/quota.env"
  umask 022
  cat > /etc/systemd/system/att-quota.service <<EOF
[Unit]
Description=att-tunnel port daily quota
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 $QUOTA_DIR/quota.py
EOF
  cat > /etc/systemd/system/att-quota.timer <<EOF
[Unit]
Description=run att-tunnel quota every minute

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s

[Install]
WantedBy=timers.target
EOF
  if ! iptables -L INPUT -n >/dev/null 2>&1; then
    mkdir -p "$QUOTA_STATE"
    {
      echo "iptables missing; try apt"
      apt-get update 2>&1 | tail -3
      apt-get install -y --reinstall iptables 2>&1 | tail -6
      update-alternatives --set iptables /usr/sbin/iptables-nft 2>&1 | tail -2 || true
    } > "$QUOTA_STATE/install.log" 2>&1 || true
    iptables -L INPUT -n >/dev/null 2>&1 || tail -1 "$QUOTA_STATE/install.log" > "$QUOTA_STATE/error.log" 2>/dev/null || true
  fi
  if ! have conntrack; then
    (apt-get install -y -qq conntrack >/dev/null 2>&1 || true)
  fi
  have iptables || warn "iptables 仍不可用，端口限额无法生效"
  systemctl daemon-reload
  systemctl enable --now att-quota.timer >/dev/null 2>&1 || true
  /usr/bin/python3 "$QUOTA_DIR/quota.py" || warn "首次配额检查失败，请查看 journalctl -u att-quota"
  ok "端口限额已启用（每端口每日 ${ATT_QUOTA_THRESHOLD:-50G}，北京时间 00:00 重置）"
}

# 秘书3：把 Gost 1000 的封停做成开机自启（只在该机执行）

install_ipmeter(){
  [ -f /etc/att-tunnel/a.env ] || return 0
  local dir=/usr/local/lib/att-quota etc=/etc/att-quota
  mkdir -p "$dir" "$etc" /var/lib/att-quota
  fetch_file ipmeter.py "$dir/ipmeter.py" || { warn "ipmeter.py 下载失败，跳过单 IP 告警"; return 0; }
  chmod 700 "$dir/ipmeter.py"
  umask 077
  cat > "$etc/ipmeter.env" <<EOF
HUB_URL=$hub
HUB_TOKEN=$token
IP_THRESHOLD=${ATT_IP_THRESHOLD:-20G}
EOF
  chmod 600 "$etc/ipmeter.env"
  umask 022
  if ! have conntrack; then
    (apt-get install -y -qq conntrack >/dev/null 2>&1 || true)
  fi
  echo 'net.netfilter.nf_conntrack_acct=1' > /etc/sysctl.d/99-att-ipmeter.conf
  sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1 || true
  cat > /etc/systemd/system/att-ipmeter.service <<EOF
[Unit]
Description=att-tunnel per-IP hourly traffic alert
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 $dir/ipmeter.py
EOF
  cat > /etc/systemd/system/att-ipmeter.timer <<EOF
[Unit]
Description=run att-tunnel IP meter every minute

[Timer]
OnBootSec=45s
OnUnitActiveSec=60s

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now att-ipmeter.timer >/dev/null 2>&1 || true
  /usr/bin/python3 "$dir/ipmeter.py" || warn "首次单 IP 检查失败，请查看 journalctl -u att-ipmeter"
  ok "单 IP 告警已启用（滚动 1 小时 ≥ ${ATT_IP_THRESHOLD:-20G}，所有端口）"
}

install_gost_block(){
  local ip
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
  [ "$ip" = "45.139.193.125" ] || return 0
  cat > /usr/local/sbin/att-block-gost1000.sh <<'EOF'
#!/bin/bash
set -e
add(){ iptables -C "$@" 2>/dev/null || iptables -I "$@"; }
add INPUT -p tcp --dport 1000 -j REJECT
add OUTPUT -p tcp -d 192.220.73.39 --dport 44519 -j REJECT
add OUTPUT -p udp -d 192.220.73.39 --dport 44519 -j REJECT
mkdir -p /var/lib/att-quota
echo on > /var/lib/att-quota/gost1000.status
EOF
  chmod 700 /usr/local/sbin/att-block-gost1000.sh
  cat > /etc/systemd/system/att-block-gost1000.service <<'EOF'
[Unit]
Description=persist block of Gost 1000 forward
After=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/att-block-gost1000.sh

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now att-block-gost1000.service >/dev/null 2>&1 || true
  ok "Gost 1000 封停已持久化（开机自启）"
}

# ---------------------------------------------------------------- 转发机（机器2/3）
install_forwarder(){
  local hub="${1:-}" token="${2:-}" sni="${3:-}"
  need_root
  [ -n "$hub" ] && [ -n "$token" ] \
    || die "用法：./install.sh -a <面板地址> -s <密钥>（请从面板「添加转发机」复制整条命令）"
  case "$hub" in
    http://*|https://*) ;;
    *) die "面板地址要带 http:// 或 https://" ;;
  esac
  hub="${hub%/}"
  install_deps
  command -v flock >/dev/null 2>&1 || { info "安装 flock"; apt-get install -y -qq util-linux; }

  # att-tunnel 脚本：全程用同一份，--server-a 和 --web 都走它。
  # 注意：att-tunnel 不会在 PATH 里装 CLI，/usr/local/lib/att-tunnel/att-tunnel.sh
  # 只有开过面板后才存在，所以不能指望「att-tunnel --web」这条命令存在。
  local att=/tmp/att-tunnel-install.$$.sh
  curl -fsSL "$ATT_REPO_RAW" -o "$att" || die "下载 att-tunnel 脚本失败（$ATT_REPO_RAW）"
  bash -n "$att" || { rm -f "$att"; die "att-tunnel 脚本语法检查不通过"; }

  # 1. 本机是否已有 att-tunnel，以哪个角色跑
  local fresh=0
  if [ -f /etc/att-tunnel/a.env ]; then
    ok "本机已在跑 att-tunnel 入口端（A 端），不重装、不动现有节点和分享链接"
  elif [ -f /etc/att-tunnel/b.env ]; then
    die "本机是 att-tunnel 出口端（B 端，也就是落地机），不能当转发机。
落地机不需要跑这条命令，它由对应转发机的面板里「添加节点」生成的命令安装。"
  else
    info "本机还没有 att-tunnel，先装入口端（A 端）"
    # 全程零交互：ATT_SNI 必须有值，否则 deploy_a 会弹出伪装域名选单让人选
    # （ATT_NONINTERACTIVE 管不到那一处）。给定值后 att-tunnel 会先实测它，
    # 不支持 TLS 1.3 就自动改用它自己的预置列表逐个试，仍然不用人管。
    ATT_RAW_URL="$ATT_REPO_RAW" ATT_NONINTERACTIVE=1 ATT_SNI="${sni:-$DEFAULT_SNI}" \
      bash "$att" --server-a || { rm -f "$att"; die "att-tunnel A 端安装失败"; }
    fresh=1
  fi

  # 1a. TCP 调优（tcp_retries2=5 + BBR）。新装时 --server-a 已做过；
  # 老转发机重跑本命令也补上。A 端不重启 att-tunnel，新连接即用 BBR。
  if [ "$fresh" = 0 ]; then
    ATT_NONINTERACTIVE=1 bash "$att" --tune || warn "TCP 调优（BBR）没成功，不影响使用"
  fi

  # 1a-2. DNS 过滤（SVCB 64 / HTTPS 65）。
  # 老转发机点「更新」时不会走 --server-a，所以这一步必须放在这里，
  # 否则只有全新装的机器才会带上，已装的永远补不上。svcb_enable 幂等。
  svcb_enable || true

  # 1b. att-tunnel 装入口端时会在配置模板里写死一个节点 node1（并绑一个空出口）。
  # 这不是面板加的，但结果是“添加转发机就白送一个节点”。默认把它删掉，
  # 让转发机以零节点干净起步，节点由你自己在面板里加。
  # 零节点配置是合法的：主入口端口保留、clients 为空，xray -test 和 att-tunnel 自检都过。
  # 只在本次新装时做；本机原有 att-tunnel 的话绝不动它的节点。
  if [ "$fresh" = 1 ] && [ "${ATT_HUB_KEEP_NODE:-0}" != 1 ]; then
    info "移除 att-tunnel 自建的默认节点 node1（节点由你在面板里自己加）"
    if ATT_RAW_URL="$ATT_REPO_RAW" ATT_NONINTERACTIVE=1 ATT_YES=1 \
         bash "$att" --del node1 >/tmp/att-del.$$.log 2>&1; then
      ok "已移除默认节点，这台转发机现在是零节点"
    else
      warn "默认节点 node1 没删掉（不影响使用，你可以在面板里手动删）："
      tail -5 /tmp/att-del.$$.log | sed 's/^/    /'
    fi
    rm -f /tmp/att-del.$$.log
  fi

  # 2. 开 att-tunnel 自带面板（转发机加/删落地机的页面就是它）
  #    已经开过也再跑一次：幂等，顺便把面板程序和脚本副本刷到当前版本
  if [ -f /etc/att-tunnel/web.env ]; then
    info "att-tunnel 面板已开过，刷新到当前版本（端口/路径/密码保留）"
  else
    warn "首次开面板要启用流量统计，att-tunnel 会重启，现有连接会断几秒"
    warn "（分享链接、节点配置、落地机那边都不变，断完自动恢复）"
  fi
  # ATT_RAW_URL：让面板里生成的落地机命令也指向同一版本脚本
  ATT_RAW_URL="$ATT_REPO_RAW" ATT_NONINTERACTIVE=1 bash "$att" --web >/tmp/att-web.$$.log 2>&1 || {
    tail -15 /tmp/att-web.$$.log; rm -f /tmp/att-web.$$.log "$att"
    die "开启 att-tunnel 面板失败"; }
  rm -f /tmp/att-web.$$.log "$att"
  [ -f /etc/att-tunnel/web.env ] || die "att-tunnel 面板未开启成功"
  ok "att-tunnel 面板就绪"
  # 本机面板只给 agent 用，收回到 127.0.0.1，不对外暴露
  harden_att_web
  # 配额/封停必须在重启 agent 之前装好：同步重启会连带杀掉本安装脚本
  install_quota || true
  install_ipmeter || true
  install_gost_block || true

  # 3. 装 agent
  mkdir -p "$AG_DIR" "$AG_ETC"; chmod 700 "$AG_ETC"
  fetch_file agent.py "$AG_DIR/agent.py"
  umask 077
  cat > "$AG_ETC/agent.env" <<EOF
# att-hub-agent 配置（v$VERSION）
HUB_URL=$hub
HUB_TOKEN=$token
EOF
  umask 022
  chmod 600 "$AG_ETC/agent.env"

  write_agent_unit
  systemctl daemon-reload
  systemctl enable att-hub-agent >/dev/null 2>&1 || true
  # 面板更新由 agent 自己调用；同步 restart 会连同安装脚本和回包线程一起杀死。
  # 比较 systemd invocation，兼容已经部署、还不知道延迟重启选项的老 agent。
  local agent_invocation
  agent_invocation=$(systemctl show -p InvocationID --value att-hub-agent 2>/dev/null || true)
  if [ -n "${INVOCATION_ID:-}" ] && [ "$INVOCATION_ID" = "$agent_invocation" ]; then
    systemd-run --quiet --unit="att-hub-agent-restart-$(date +%s)-$$" \
      --on-active=15s /bin/systemctl restart att-hub-agent \
      || die "无法安排 agent 重启，更新未完成"
    ok "agent 文件已更新，将在 15 秒后重启（先向面板回传结果）"
  else
    systemctl restart att-hub-agent
    sleep 3
    systemctl is-active --quiet att-hub-agent \
      || { journalctl -u att-hub-agent -n 20 --no-pager; die "agent 启动失败"; }
  fi

  echo
  ok "转发机安装完成，已回连面板 $hub"
  echo "回面板刷新，这台应该变成「在线」；点「管理落地机」就是 att-tunnel 原生页面。"
  echo "日志：${CYN}journalctl -u att-hub-agent -f${RST}"
}

# 转发机本机的 att-tunnel 面板只服务 agent，收到 127.0.0.1
harden_att_web(){
  local f=/etc/att-tunnel/web.env
  grep -qE '^WEB_LISTEN=127\.0\.0\.1$' "$f" && return 0
  cp -a "$f" "$f.bak.$(date +%s)"
  local cur; cur=$(grep -E '^WEB_LISTEN=' "$f" | cut -d= -f2 || true)
  grep -v '^WEB_LISTEN=' "$f" > "$f.tmp"
  echo 'WEB_LISTEN=127.0.0.1' >> "$f.tmp"
  chmod 600 "$f.tmp"; mv "$f.tmp" "$f"
  info "att-tunnel 面板改为只监听 127.0.0.1（原 ${cur:-0.0.0.0}），统一从面板机访问"
  systemctl restart att-tunnel-web >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------- 管理命令 att-hub
install_cli(){
  printf '%s\n' '#!/usr/bin/env bash' "exec bash $HUB_DIR/manage.sh \"\$@\"" \
    > /usr/local/bin/att-hub
  chmod 755 /usr/local/bin/att-hub
  write_manage
}

# 拉取 bash 文件（manage.sh）：同样优先同目录，否则走 RAW
write_manage(){
  local dest="$HUB_DIR/manage.sh" src
  src="$(dirname "${BASH_SOURCE[0]}")/manage.sh"
  if [ -f "$src" ]; then
    cp "$src" "$dest"
  else
    curl -fsSL "${HUB_RAW_URL%/install.sh}/manage.sh" -o "$dest" || die "下载 manage.sh 失败"
  fi
  bash -n "$dest" || die "manage.sh 语法检查不通过"
  chmod 700 "$dest"
}

usage(){
  cat <<EOF
att-tunnel-hub v$VERSION—转发机统一管理整合项目

  机器1 面板机：   ./install.sh --panel
  机器2/3 转发机： ./install.sh -a <面板地址> -s <密钥> [-d <伪装域名>]
                      （这条由面板「添加转发机」自动生成，复制粘贴即可，全程零交互）
  落地机：         在面板里进对应转发机 →「管理落地机」→「＋ 添加节点」生成命令

  -d 不填时用 $DEFAULT_SNI；它不可用时 att-tunnel 自动换预置列表里可用的。
  --dns-block / --dns-unblock / --dns-status  屏蔽或恢复 SVCB(64)/HTTPS(65) DNS 记录
  装完面板机后用 ${CYN}att-hub${RST} 看地址/改密码/重启/卸载。
EOF
}

need_root

# 参数：以 duola 那种方式为准（-a 地址 -s 密钥），全程不问任何问题。
# 旧式 --forwarder <地址> <密钥> 照旧能用，免得已发出去的命令失效。
MODE=""; HUB_ADDR=""; HUB_SECRET=""; SNI_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    -a|--addr|--hub-url)  HUB_ADDR="${2:-}"; MODE="${MODE:-forwarder}"; shift 2 ;;
    -s|--secret|--token)  HUB_SECRET="${2:-}"; MODE="${MODE:-forwarder}"; shift 2 ;;
    -d|--sni|--domain)    SNI_ARG="${2:-}"; shift 2 ;;
    --panel|--hub|--server-1) MODE=panel; shift ;;
    --forwarder|--fwd)
      MODE=forwarder
      [ -n "${2:-}" ] && [ "${2#-}" = "$2" ] && { HUB_ADDR="$2"; shift; }
      [ -n "${2:-}" ] && [ "${2#-}" = "$2" ] && { HUB_SECRET="$2"; shift; }
      shift ;;
    --dns-block)          svcb_enable; exit 0 ;;
    --dns-unblock)        svcb_disable; exit 0 ;;
    --dns-status)         svcb_status; exit 0 ;;
    --version|-v)         echo "$VERSION"; exit 0 ;;
    --help|-h)            usage; exit 0 ;;
    *)                    die "未知参数：$1（用 --help 看用法）" ;;
  esac
done

case "$MODE" in
  panel)     install_panel; install_cli; svcb_enable ;;
  forwarder) install_forwarder "$HUB_ADDR" "$HUB_SECRET" "$SNI_ARG" ;;
  *)         usage ;;
esac
