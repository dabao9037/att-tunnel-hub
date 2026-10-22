#!/usr/bin/env bash
set -Eeuo pipefail
HUB_ETC=/etc/att-hub
HUB_DIR=/usr/local/lib/att-hub
CYN=$'\e[36m'; GRN=$'\e[32m'; RED=$'\e[31m'; RST=$'\e[0m'
[ "$(id -u)" = 0 ] || { echo "请用 root 运行" >&2; exit 1; }
[ -f "$HUB_ETC/hub.env" ] || { echo "本机没有装 att-tunnel-hub 面板" >&2; exit 1; }

get(){ grep -E "^$1=" "$HUB_ETC/hub.env" | cut -d= -f2-; }

setkv(){
  cp -a "$HUB_ETC/hub.env" "$HUB_ETC/hub.env.bak.$(date +%s)"
  grep -v "^$1=" "$HUB_ETC/hub.env" > "$HUB_ETC/hub.env.tmp"
  echo "$1=$2" >> "$HUB_ETC/hub.env.tmp"
  chmod 600 "$HUB_ETC/hub.env.tmp"; mv "$HUB_ETC/hub.env.tmp" "$HUB_ETC/hub.env"
}

fwd_count(){
  python3 - <<'PY' 2>/dev/null || echo 0
import json
try:
    d = json.load(open('/var/lib/att-hub/state.json'))
    print(len(d.get('forwarders') or {}))
except Exception:
    print(0)
PY
}

info_show(){
  echo "面板地址：${CYN}$(get HUB_URL)/${RST}"
  echo "密  码：${CYN}$(get WEB_PASS)${RST}"
  echo "监  听：$(get WEB_LISTEN):$(get WEB_PORT)，路径 /$(get WEB_PATH)"
  if systemctl is-active --quiet att-hub; then
    echo "状  态：${GRN}运行中${RST}"
  else
    echo "状  态：${RED}未运行${RST}"
  fi
  echo "转发机：$(fwd_count) 台"
}

case "${1:-info}" in
  info)    info_show ;;
  restart) systemctl restart att-hub && echo "已重启" ;;
  log)     journalctl -u att-hub -n "${2:-80}" --no-pager ;;
  passwd)
    p="${2:-$(python3 -c 'import secrets;print(secrets.token_urlsafe(12))')}"
    [ "${#p}" -ge 8 ] || { echo "密码至少 8 位" >&2; exit 1; }
    setkv WEB_PASS "$p"; systemctl restart att-hub
    echo "新密码：${CYN}$p${RST}" ;;
  url)
    [ -n "${2:-}" ] || { echo "用法：att-hub url https://域名/路径" >&2; exit 1; }
    setkv HUB_URL "${2%/}"; systemctl restart att-hub
    echo "已更新。注意：已装好的转发机 agent 还用老地址，"
    echo "要改就在转发机上改 /etc/att-hub-agent/agent.env 的 HUB_URL 再重启 att-hub-agent。" ;;
  listen)
    [ -n "${2:-}" ] || { echo "用法：att-hub listen 127.0.0.1|0.0.0.0" >&2; exit 1; }
    setkv WEB_LISTEN "$2"; systemctl restart att-hub; echo "已改为监听 $2" ;;
  uninstall)
    read -rp "确认卸载面板？输 yes：" a; [ "$a" = yes ] || exit 0
    systemctl disable --now att-hub >/dev/null 2>&1 || true
    rm -f /etc/systemd/system/att-hub.service; systemctl daemon-reload
    rm -rf "$HUB_DIR" /usr/local/bin/att-hub
    echo "已卸载。配置和记录保留在 $HUB_ETC 和 /var/lib/att-hub，如不要请自行删除。" ;;
  *) echo "用法：att-hub [info|restart|log [行数]|passwd [新密码]|url <地址>|listen <IP>|uninstall]" ;;
esac
