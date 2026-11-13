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

**全程零交互**，不会问伪装域名、不会问端口、不用选任何东西。伪装域名由脚本自己定（默认 `www.debian.org`，不可用时 att-tunnel 自动换成预置列表里可用的那个）；要指定就加 `-d <域名>`。

它会装好 att-tunnel 入口端和 agent，装完面板里这台就变成「在线」。本机已经在跑 att-tunnel 的话不重装，现有节点和分享链接都不动。

新装的转发机以**零节点**起步：att-tunnel 装入口端时会在配置里自建一个默认节点 `node1`，脚本会把它删掉，节点由你自己在面板里加。想保留那个默认节点就加环境变量 `ATT_HUB_KEEP_NODE=1`。

### 3. 落地机（若干台）

面板里点转发机的「管理落地机」→ 进入该机 att-tunnel 原生面板 →「＋ 添加节点」→ 复制生成的命令，在落地机上跑。

## 面板能做什么

- 看所有转发机的在线状态、落地机数量、最后上报时间，以及该转发机的实时上下行网速和累计流量（取自转发机物理网卡，重启后归零）
- 添加 / 编辑 / 删除转发机，随时重新查看某台的一键代码
- 编辑可改名称、IP、备注；密钥不变，所以改完不用重装 agent，落地机也不受影响
- 点进任意转发机，用 att-tunnel 原生页面加 / 删落地机、看流量、出口 IP、分享链接
- 「落地节点汇总」页一张表看完所有转发机下面的落地节点：在线状态、出口 IP、入口端口、伪装域名、累计流量和当前速率；哪台转发机没取到数据会单独提示原因
- **在线 SSH**：输入 IP / 端口 / 用户名 / 密码，直接在浏览器里开一个终端；只做终端，不支持上传/下载
  - 会话保活：服务端每 25 秒发 WebSocket ping，前端每 20 秒发保活；切后台/切标签页回来会重新适配终端。
  - 快捷输入：内置「IP 检测」（`bash <(curl -sL IP.Check.Place)`）和「TQ」（`bash <(curl -fsSL https://raw.githubusercontent.com/ibsgss/TcpQuality/main/runTcpQuality.sh)`）两个按钮，点一下直接执行。
  - 终端会在连接前按容器尺寸自适应；手机/窄屏自动换行，不再左右裁切。提供「复制选中」「复制全部」按钮，Ctrl/Cmd+C 复制选中内容。
  - 连接后进入全屏终端（参考 NodeLite 的终端页）：上下滑动只在终端内滚动，不带动网页；点「选择文本」打开原生可选择文本层，手机可长按选择/复制。
  - 记住服务器：勾选「记住这台服务器」后，地址/用户名/密码保存在本浏览器 localStorage，下次打开自动填；可保存多台、切换、删除。服务器本身不保存 SSH 密码。
  - 会话续接：WebSocket 断开（切后台、锁屏、断网）后，面板机上的 SSH 会话保留 10 分钟；页面自动重连同一个 shell，并补发断线期间的输出。刷新页面可点「继续上次会话」；会话过期且已保存密码时会自动新建。

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

## DNS：屏蔽 SVCB(64) / HTTPS(65) 记录（默认开启）

安装时会在本机起一个独立的 dnsmasq 实例（机器上已有 dnsmasq 在跑时则只注入配置、不另起实例），只做一件事：**丢弃 SVCB(Type 64) 与 HTTPS(Type 65) 两类 DNS 记录**。

为什么：

- 这两类 RR 的应答里带 `ipv4hint` / `ipv6hint`（**真实地址**）和 `ech`（加密 SNI 配置）。
- 在 Fake-IP 代理体系下，客户端拿到 hint 会直接按真实 IP 连，绕过假 IP 与域名分流；`alpn=h3` 又会把流量推进 QUIC(UDP/443)，于是出口 IP 和 DNS 一起漏。
- 过滤后客户端按 RFC 9460/9461 自动回退 A/AAAA + h2，业务功能不受影响，代价只是失去 HTTP/3 与 ECH。

行为与保护：

- 依赖 dnsmasq >= 2.86（`filter-rr` 自 2.86 起提供）。版本不够时**跳过**并告警，不会把系统 DNS 改坏。
- 会把 `/etc/resolv.conf` 备份后指向 `127.0.0.1`，同时让出 53 端口：systemd-resolved 写 `DNSStubListener=no`，NetworkManager 写 `dns=none`。
- 任何一步失败立即回滚、恢复原 resolv.conf。
- 上游 DNS 沿用系统原有配置（自动剔除环回地址，不会自环）。
- 只过滤 DNS，不封 UDP/443；浏览器已缓存的 Alt-Svc 仍可能继续走 QUIC，需要时在 `chrome://net-internals/#sockets` 里 Flush sockets。

开关：

```bash
SVCB_BLOCK=0 bash install.sh install   # 本次安装不做屏蔽（默认 1 = 做）
./install.sh --dns-block        # 只开屏蔽
./install.sh --dns-status       # 看状态并实测
./install.sh --dns-unblock      # 关闭并还原
```

验证：

```bash
dig +short A     example.com @127.0.0.1   # 有答案
dig +short HTTPS example.com @127.0.0.1   # 空 = 已过滤
```


## 安全说明

- 面板：随机端口 + 随机根路径 + 密码登录；Cookie `HttpOnly`/`SameSite=Strict`；所有 POST 要会话 + CSRF + 同源校验；登录失败限速。
- 每台转发机一个独立 token。token 只在生成一键代码时显示，等于那台机器的凭据，请当密码保管。
- 面板发给 agent 的只有「打给本机 att-tunnel 面板的 HTTP 请求」，**没有任意命令执行通道**。
- 转发机本机的 att-tunnel 面板会被收回只监听 `127.0.0.1`，只有 agent 能访问，不对外暴露。
- 在线 SSH：密码只存在内存和本次会话的 0600 临时文件里，连接结束即删除；主机指纹首次连接自动接受（临时 known_hosts），面板不保存 SSH 凭据；WebSocket 需要面板登录会话 + 一次性 ticket。
- 面板默认是明文 HTTP。放到公网请套域名 + HTTPS（nginx + certbot），然后 `att-hub listen 127.0.0.1` 收回本地监听，并在 `hub.env` 里设 `WEB_COOKIE_SECURE=1`、`WEB_TRUST_PROXY=1`。

## 依赖

面板机和转发机都只需要 `python3 >= 3.8` 和 `curl`，没有第三方 Python 包，没有外部 CDN。在线 SSH 需要 `ssh` 和 `sshpass`（面板机安装脚本会检查；没有的话该功能会明确报错）。前端终端使用 vendored 的 xterm.js 5.x（MIT，见 `static/LICENSE-xterm`）。Debian / Ubuntu。

## 许可

MIT


### 更新范围（面板「更新」到底改了什么）

面板上每台转发机一个「更新」，右上角还有一个「⇈ 全部更新」：把所有在线且不在更新中的转发机排进队列，**按顺序逐台执行**，一台跑完再下一台，不会让 5 台同时重启 att-tunnel 把落地机全断。

一次更新在转发机上依次做四件事：

1. 重跑 att-tunnel 入口端（`--tune`，TCP 调优）
2. 启用 / 刷新 DNS 过滤（SVCB 64 / HTTPS 65），见上一节
3. 刷新 att-tunnel 面板程序到当前版本
4. 替换 `att-hub-agent` 并重启它

所以**已装的转发机点更新就能拿到新功能，不需要重装**。全新装的自然也带。中途离线的机器会被跳过并记进面板日志。

### 更新结果反馈

转发机「更新」现在立即创建后台任务（HTTP 202），由 `/api/status` 返回持久化的进度和结果。页面关闭、刷新或重新登录不会清除已经保存的结果，进行中的重复点击不会创建第二次更新。

- **更新成功**：收到 agent 的安装脚本正常退出回执；不是根据在线状态或版本号猜测。
- **更新失败**：收到非成功回执，请查看转发机 `journalctl -u att-hub-agent`。
- **结果未确认**：等待回执超时或面板在任务期间重启；不能视作成功或确定失败，先核对日志，不要连续重复更新。

回归测试（不操作真实转发机）：

```sh
python3 tests/test_upgrade.py
# 可选真实浏览器测试，需已安装 Playwright 和 Chromium
python3 tests/browser_upgrade.py
```
