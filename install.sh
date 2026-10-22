#!/usr/bin/env bash
# att-tunnel-hub 一键安装脚本
#
#   机器1 面板机：  bash <(curl -fsSL <RAW>) --panel
#   机器2/3 转发机：bash <(curl -fsSL <RAW>) --forwarder <面板地址> <token>
#                   （这条命令由面板里「添加转发机」自动生成，不用手敲）
#   落地机：        由转发机面板里「添加落地机」生成命令，走 att-tunnel 原生流程
#
# 架构：面板机不过流量；转发机 = att-tunnel A 端 + agent（主动回连面板）；
#       落地机 = att-tunnel B 端，主动外拨连转发机，与节点 1:1。
set -Eeuo pipefail

VERSION="1.0.0"
ATT_REPO_RAW="${ATT_REPO_RAW:-https://raw.githubusercontent.com/dabao9037/att-tunnel/main/install.sh}"
HUB_RAW_URL="${HUB_RAW_URL:-https://raw.githubusercontent.com/dabao9037/att-tunnel-hub/main/install.sh}"

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

  local port path pass hub_url
  mkdir -p "$HUB_DIR" "$HUB_ETC" "$HUB_STATE"
  chmod 700 "$HUB_ETC" "$HUB_STATE"

  if [ -f "$HUB_ETC/hub.env" ]; then
    info "已有配置，保留端口/路径/密码，只更新程序"
    cp -a "$HUB_ETC/hub.env" "$HUB_ETC/hub.env.bak.$(date +%s)"
    # shellcheck disable=SC1091
    port=$(grep -E '^WEB_PORT=' "$HUB_ETC/hub.env" | cut -d= -f2)
    path=$(grep -E '^WEB_PATH=' "$HUB_ETC/hub.env" | cut -d= -f2)
    pass=$(grep -E '^WEB_PASS=' "$HUB_ETC/hub.env" | cut -d= -f2)
  else
    port="${HUB_PORT:-$(free_port)}"
    path="${HUB_PATH:-$(rand_hex)}"
    pass="${HUB_PASS:-$(rand_pass)}"
  fi

  hub_url="${HUB_URL:-}"
  if [ -z "$hub_url" ]; then
    local ip; ip=$(pubip) || die "取不到公网 IP，请用 HUB_URL=http://你的IP:端口/路径 指定"
    hub_url="http://$ip:$port/$path"
  fi

  fetch_file hub.py "$HUB_DIR/hub.py"

  cat > "$HUB_ETC/hub.env" <<EOF
# att-tunnel-hub 面板配置（v$VERSION）
WEB_PORT=$port
WEB_PATH=$path
WEB_PASS=$pass
# 默认监听 0.0.0.0；套了 nginx/域名 后改成 127.0.0.1 更安全
WEB_LISTEN=${HUB_LISTEN:-0.0.0.0}
# agent 回连用的面板外网地址（带根路径）
HUB_URL=$hub_url
# 生成一键代码用的本脚本地址
HUB_RAW_URL=$HUB_RAW_URL
# 上了 HTTPS 后改 1
WEB_COOKIE_SECURE=${HUB_COOKIE_SECURE:-0}
# 在 nginx 后面时改 1，让登录限速看真实 IP
WEB_TRUST_PROXY=${HUB_TRUST_PROXY:-0}
EOF
  chmod 600 "$HUB_ETC/hub.env"

  write_panel_unit
  systemctl daemon-reload
  systemctl enable --now att-hub >/dev/null 2>&1 || systemctl restart att-hub
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

# ---------------------------------------------------------------- 转发机（机器2/3）
install_forwarder(){
  local hub="${1:-}" token="${2:-}"
  need_root
  [ -n "$hub" ] && [ -n "$token" ] \
    || die "用法：--forwarder <面板地址> <token>（请从面板「添加转发机」复制整条命令）"
  case "$hub" in
    http://*|https://*) ;;
    *) die "面板地址要带 http:// 或 https://" ;;
  esac
  hub="${hub%/}"
  install_deps

  # 1. 装/备 att-tunnel A 端（入口端）和它自己的面板
  if [ -f /usr/local/etc/att-tunnel/config.json ]; then
    ok "本机已有 att-tunnel，不重装"
  else
    info "安装 att-tunnel A 端（入口端）"
    curl -fsSL "$ATT_REPO_RAW" -o /tmp/att-install.sh || die "下载 att-tunnel 失败"
    ATT_NONINTERACTIVE=1 bash /tmp/att-install.sh --server-a || die "att-tunnel A 端安装失败"
    rm -f /tmp/att-install.sh
  fi

  # 2. 确保 att-tunnel 自带面板已开（转发机加/删落地机的页面就是它）
  if [ ! -f /etc/att-tunnel/web.env ]; then
    info "开启 att-tunnel 本机面板"
    att-tunnel --web >/dev/null 2>&1 || att_web_fallback
  fi
  [ -f /etc/att-tunnel/web.env ] || die "att-tunnel 面板未开启成功"
  # 本机面板只给 agent 用，收回到 127.0.0.1，不对外暴露
  harden_att_web

  # 3. 装 agent
  mkdir -p "$AG_DIR" "$AG_ETC"; chmod 700 "$AG_ETC"
  fetch_file agent.py "$AG_DIR/agent.py"
  cat > "$AG_ETC/agent.env" <<EOF
# att-hub-agent 配置（v$VERSION）
HUB_URL=$hub
HUB_TOKEN=$token
EOF
  chmod 600 "$AG_ETC/agent.env"

  write_agent_unit
  systemctl daemon-reload
  systemctl enable --now att-hub-agent >/dev/null 2>&1 || systemctl restart att-hub-agent
  sleep 2
  systemctl is-active --quiet att-hub-agent \
    || { journalctl -u att-hub-agent -n 20 --no-pager; die "agent 启动失败"; }

  echo
  ok "转发机安装完成，已回连面板 $hub"
  echo "回面板刷新，这台应该变成「在线」；点「管理落地机」就是 att-tunnel 原生页面。"
  echo "日志：${CYN}journalctl -u att-hub-agent -f${RST}"
}

att_web_fallback(){
  [ -f /usr/local/lib/att-tunnel/att-tunnel.sh ] \
    && bash /usr/local/lib/att-tunnel/att-tunnel.sh --web >/dev/null 2>&1 \
    || die "无法开启 att-tunnel 面板，请先在本机跑 att-tunnel 菜单里的「网页面板」"
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

  机器1 面板机：   bash install.sh --panel
  机器2/3 转发机： bash install.sh --forwarder <面板地址> <token>
                      （这条由面板「添加转发机」自动生成，不用手敲）
  落地机：         在面板里进对应转发机 →「管理落地机」→「＋ 添加节点」生成命令

  装完面板机后用 ${CYN}att-hub${RST} 看地址/改密码/重启/卸载。
EOF
}

need_root
case "${1:-}" in
  --panel|--hub|--server-1) install_panel; install_cli ;;
  --forwarder|--fwd)        install_forwarder "${2:-}" "${3:-}" ;;
  --version|-v)             echo "$VERSION" ;;
  --help|-h|'')             usage ;;
  *)                        die "未知参数：$1（可用：--panel | --forwarder <地址> <token>）" ;;
esac
