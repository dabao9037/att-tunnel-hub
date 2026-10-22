# att-tunnel-hub

**att-tunnel 整合项目**：在面板机上装一个 Web 端，统一管理所有转发机和它们下面的落地机。

基于 [att-tunnel](https://github.com/dabao9037/att-tunnel) 的 Xray VLESS Reverse 反向隧道。隧道本身的行为、配置和「转发机添加落地机」的页面都以 att-tunnel 为准 —— 面板里点进转发机看到的就是该机 att-tunnel 面板的原生页面。

## 架构

```
      机器1 面板机（att-tunnel-hub）
      不过流量，只管理
               ▲  agent 主动外拨回连（转发机不用开入站端口）
      ┌────────┴────────┐
  机器2 转发机        机器3 转发机      ← 客户端连这里
  att-tunnel A 端     att-tunnel A 端
      ▲                   ▲
      │ 落地机主动外拨     │            ← 落地机零入站，换 IP 自动重连
  ┌───┴───┐           ┌───┴───┐
 落地机    落地机       落地机           ← 与节点 1:1，每个落地机一条独立分享链接
```

- **面板机**只管理，不碰流量；它既不保存转发机的 SSH 密码，也从不主动去连转发机。
- **转发机**跑 att-tunnel 入口端 + `att-hub-agent`。agent 全程主动外拨 long-poll 面板，所以转发机不需要为面板开任何入站端口。
- **落地机**是 att-tunnel 的出口端，主动外拨连转发机，自己零入站。每台落地机在转发机上占一个独立节点、独立端口、独立分享链接（1:1）。

## 安装

### 1. 面板机（机器1）

```bash
curl -L https://raw.githubusercontent.com/dabao9037/att-tunnel-hub/main/install.sh -o ./install.sh && chmod +x ./install.sh && ./install.sh --panel
```

装完会打印面板地址和密码。面板默认用随机端口 + 随机根路径 + 随机密码。

### 2. 转发机（机器2、机器3）

不用手敲命令。登录面板 →「＋ 添加转发机」填公网 IP → 面板生成该机专属的一键代码 → 用 root 在那台机器上跑：

```bash
curl -L .../install.sh -o ./install.sh && chmod +x ./install.sh && ./install.sh -a <面板地址> -s <密钥>
```

**全程零交互**，不会问伪装域名、不会问端口、不用选任何东西。伪装域名由脚本自己定（默认 `www.atlasobscura.com`，不可用时 att-tunnel 自动换成预置列表里可用的那个）；要指定就加 `-d <域名>`。

它会装好 att-tunnel 入口端和 agent，装完面板里这台就变成「在线」。本机已经在跑 att-tunnel 的话不重装，现有节点和分享链接都不动。

新装的转发机以**零节点**起步：att-tunnel 装入口端时会在配置里自建一个默认节点 `node1`，脚本会把它删掉，节点由你自己在面板里加。想保留那个默认节点就加环境变量 `ATT_HUB_KEEP_NODE=1`。

### 3. 落地机（若干台）

面板里点转发机的「管理落地机」→ 进入该机 att-tunnel 原生面板 →「＋ 添加节点」→ 复制生成的命令，在落地机上跑。

## 面板能做什么

- 看所有转发机的在线状态、落地机数量、最后上报时间
- 添加 / 编辑 / 删除转发机，随时重新查看某台的一键代码
- 编辑可改名称、IP、备注；密钥不变，所以改完不用重装 agent，落地机也不受影响
- 点进任意转发机，用 att-tunnel 原生页面加 / 删落地机、看流量、出口 IP、分享链接

## 管理命令

面板机上装好后有 `att-hub`：

```bash
att-hub              # 看地址、密码、状态、转发机数量
att-hub passwd       # 改密码（不带参数则随机生成）
att-hub url <地址>   # 改面板对外地址（上了域名后用）
att-hub listen 127.0.0.1   # 套了 nginx 后收回本地监听
att-hub log          # 看日志
att-hub restart
att-hub uninstall    # 卸载面板程序，保留配置和记录
```

转发机上的 agent 用 `systemctl status att-hub-agent` 和 `journalctl -u att-hub-agent -f` 看。

## 安全说明

- 面板：随机端口 + 随机根路径 + 密码登录；Cookie `HttpOnly`/`SameSite=Strict`；所有 POST 要会话 + CSRF + 同源校验；登录失败限速。
- 每台转发机一个独立 token。token 只在生成一键代码时显示，等于那台机器的凭据，请当密码保管。
- 面板发给 agent 的只有「打给本机 att-tunnel 面板的 HTTP 请求」，**没有任意命令执行通道**。
- 转发机本机的 att-tunnel 面板会被收回只监听 `127.0.0.1`，只有 agent 能访问，不对外暴露。
- 面板默认是明文 HTTP。放到公网请套域名 + HTTPS（nginx + certbot），然后 `att-hub listen 127.0.0.1` 收回本地监听，并在 `hub.env` 里设 `WEB_COOKIE_SECURE=1`、`WEB_TRUST_PROXY=1`。

## 依赖

面板机和转发机都只需要 `python3 >= 3.8` 和 `curl`，没有第三方 Python 包，没有外部 CDN。Debian / Ubuntu。

## 许可

MIT
