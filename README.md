WSS (WebSocket Secure) SSH 隧道管理面板 (Axiom V1.7.0)

本项目是一个高性能、安全加固的 WSS (WebSocket Secure) SSH 隧道管理系统，基于 Node.js 构建。

它旨在通过标准的 WebSocket 协议（运行于 80/443 等自定义端口）转发 SSH 流量，同时提供一个功能完善的 Web UI 来管理用户、流量、速率和安全策略。

V1.7.0 架构的核心设计理念是最小权限和完全解耦：

**控制平面（Control Plane）与数据平面（Data Plane）**完全分离。

面板权限最小化，Web服务（控制平面）不再以 root 权限运行，而是作为一个受限的系统用户（例如 admin）运行，通过 sudo 执行特定授权命令。

WSS 隧道与Stunnel Shell 访问完全分离。

核心架构 (Axiom V1.7.0)

系统由两个独立的 Node.js 进程、两个独立的 SSHD 服务和一个 sudoers 策略组成：

1. 控制平面 (Control Plane)

服务: wss_panel.service

脚本: wss_panel.js

运行用户: admin (或您在安装时自定义的 $panel_user)

职责:

提供基于 Express 的 Web 管理面板 (UI)，监听自定义端口 (例如 54321)。

安全: 实现登录页速率限制（防爆破）。

管理一个 SQLite 数据库 (wss_panel.db)，使用 WAL 模式（防止锁竞争）存储所有用户信息（密码哈希、配额、速率限制等）。

提供一个内部认证 API (/internal/auth)，供数据平面调用以验证用户连接。

运行一个后台 syncUserStatus 循环，定期从数据平面拉取流量统计，并检查用户状态。

核心 (最小权限): 当需要锁定/解锁用户或管理服务时，它会通过 sudo 无密码执行 sudoers 文件中明确授权的命令 (例如 sudo usermod -L <user>)。

2. 数据平面 (Data Plane)

服务: wss.service

脚本: wss_proxy.js

运行用户: root (必须，因为它需要绑定到 80/443 等特权端口)

职责:

监听公共端口 (例如 80 和 443)。

Payload Eater: 智能处理“哑”HTTP请求和“升级”请求的TCP流水线。

Host 检查: 检查 Host 头是否在 hosts.json 白名单中。

认证卸载: 回调控制平面的 /internal/auth API 来验证用户凭据，自身不执行任何昂贵的 bcrypt 或数据库操作。

策略执行: 根据从控制平面获取的限制，对每个用户实施速率限制（令牌桶算法）和并发连接数限制。

流量转发: 将所有合法流量转发到主 SSHD 服务 (例如 127.0.0.1:22)。

提供一个内部统计 API (/stats)，供控制平面调用。

3. Stunnel (Shell) 平面

服务: stunnel4.service 和 sshd_stunnel.service

职责:

stunnel4 监听自定义端口 (例如 444)，负责 SSL 卸载。

stunnel4 将解密的流量转发到独立的 Stunnel SSHD 服务 (例如 127.0.0.1:2222)。

sshd_stunnel.service 是一个专用的 SSHD 实例，其配置 (sshd_config_stunnel) 中包含 AllowGroups shell_users 指令。

安全: 只有在面板中被授予 "Allow Shell" 权限（即被添加到 shell_users 组）的用户才能通过此端口登录。

详细逻辑实现

场景 1: WSS (80/443) 隧道连接流程

客户端 (例如 HTTP Injector) 向 wss_proxy.js (端口 80) 发起连接。

wss_proxy.js 收到请求，检查 Host 头是否在 hosts.json 白名单中。

Payload Eater: 客户端首先发送一个“哑”HTTP请求 (例如 GET / HTTP/1.1)。wss_proxy.js 识别出这不是升级请求，回复 HTTP/1.1 200 OK 并保持连接。

客户端在同一个 TCP 连接上发送第二个请求 (例如 GET /?user=A_user HTTP/1.1 并包含 Upgrade: websocket 头)。

wss_proxy.js 检测到 Upgrade 关键字。

parseAuth() 启动：

路径 1 (令牌优先): 检查 Proxy-Authorization 头。如果存在 (例如 B_user 的令牌)，则立即使用此令牌调用控制平面。

路径 2 (URI 备选): 如果没有 Proxy-Authorization 头，则检查 URI 中的 /?user=A_user。

wss_proxy.js 通过内部 API (例如 http://127.0.0.1:54321/internal/auth) 请求 wss_panel.js。

wss_panel.js (作为 admin 用户) 收到请求，查询 SQLite 数据库，使用 bcrypt.compare 验证密码哈希，并检查用户 status 是否为 active。

wss_panel.js 回复 wss_proxy.js 认证结果 (例如 {"success": true, "limits": {"rate_kbps": 5000}})。

wss_proxy.js 收到成功响应，执行 checkConcurrency() 检查并发连接数。

检查通过，wss_proxy.js 向客户端回复 HTTP/1.1 101 Switching Protocols。

wss_proxy.js 建立到内部主 SSHD (127.0.0.1:22) 的 TCP 连接。

数据开始双向转发。wss_proxy.js 中的令牌桶 (TokenBucket) 开始对该用户的上行/下行流量实施速率限制。

场景 2: Stunnel (444) Shell 访问流程

客户端 (例如 OpenSSH) 通过 stunnel 客户端连接到服务器的 444 端口。

服务器上的 stunnel4.service 接收连接，进行 SSL 卸载。

stunnel4 将解密后的 SSH 流量转发到 127.0.0.1:2222 (Stunnel SSHD 端口)。

sshd_stunnel.service 收到连接。

sshd_stunnel 检查认证用户的系统组。由于配置了 AllowGroups shell_users，只有属于 shell_users 组的用户才被允许继续。

sshd 检查用户的系统密码，并检查账户是否被锁定 (/etc/shadow 中是否有 ! 标记)。

认证成功，用户获得 Shell 访问权限。

场景 3: 后台同步与系统锁定 (核心安全)

wss_panel.js 中的 syncUserStatus 计时器（每 30 秒）触发。

wss_panel.js (作为 admin 用户) 调用 wss_proxy.js (root) 的 /stats API。

wss_proxy.js 返回所有用户的实时流量增量 (delta) 和连接数，并清空自己的计数器。

wss_panel.js 遍历统计数据，更新 SQLite 数据库中每个用户的 usage_gb 和 active_connections。

wss_panel.js 检查用户是否已到期 (expiration_date) 或超额 (usage_gb > quota_gb)。

决策点: 发现 user_A 已超额，其数据库 status 从 active 变为 exceeded。

执行 (最小权限): wss_panel.js 执行 safeRunCommand(['usermod', '-L', 'user_A'])。

safeRunCommand 函数检测到 usermod 在 SUDO_COMMANDS 列表中，自动将其转换为 ['sudo', 'usermod', '-L', 'user_A']。

admin 用户通过 /etc/sudoers.d/99-wss-panel 中授予的权限，无密码成功执行了 sudo usermod -L user_A。

user_A 的系统账户被锁定。现在，即使 user_A 尝试通过 Stunnel (444) 登录，也会因系统账户锁定而失败。

安装与部署

本项目使用 install.sh 脚本进行一键部署。

# 1. 克隆仓库
git clone [https://github.com/2019xuanying/SSH-Node-test.git](https://github.com/2019xuanying/SSH-Node-test.git)
cd SSH-Node-test

# 2. 运行安装脚本
chmod +x install.sh
./install.sh


安装脚本会自动：

交互式提示：要求您设置所有服务端口（WSS, Stunnel, Panel 等）和 Panel 服务用户名。

安装依赖：安装 nodejs, stunnel4, build-essential, sudo 等。

创建服务用户：创建您指定的 Panel 服务用户 (例如 admin)。

配置 Sudoers：创建 /etc/sudoers.d/99-wss-panel 文件，授予服务用户执行特定命令的权限。

安装 Node 依赖：包括 express-rate-limit 用于防爆破。

安全加固：为所有密钥文件设置 chmod 600。

配置服务：根据您的端口设置，生成所有 systemd 服务文件和 sshd 配置文件。

启动服务：启动 wss_panel, wss, stunnel4, sshd_stunnel 等。

卸载

chmod +x NOinstall.sh
./NOinstall.sh


卸载脚本会自动检测您安装时设置的服务用户名，并彻底清除所有服务、配置文件、sudoers 规则、用户组和服务用户。

故障排查 (Fault Diagnosis)

症状

可能原因

排查步骤 (Axiom 建议)

Web 面板 (54321) 无法访问

1. Panel 服务未运行。



2. 端口冲突。



3. sudoers 配置错误。

1. sudo systemctl status wss_panel 查看服务状态。



2. sudo journalctl -u wss_panel -f 查看实时日志。



3. 检查日志中是否有 sudo 权限错误或 npm 模块失败。



4. 检查端口占用: sudo lsof -i:54321 (使用您的 Panel 端口)。

登录面板提示 "次数过多"

登录防爆破机制已触发。

这是正常功能。请等待 15 分钟后再试，或从受信任的 IP 登录。

WSS (80/443) 无法连接

1. Proxy 服务未运行。



2. 端口 80/443 被占用 (例如 Nginx, Apache)。

1. sudo systemctl status wss 查看服务状态。



2. sudo journalctl -u wss -f 查看实时日志。



3. 检查端口占用: sudo lsof -i:80 和 sudo lsof -i:443。

WSS 连接提示 401/403

1. 客户端 Proxy-Authorization 令牌 (Base64) 错误。



2. 尝试免认证 (/?user=...) 但用户未配置 require_auth_header = 0。



3. Host 头不在白名单中。

1. 检查 wss_proxy.js 日志: sudo journalctl -u wss -f。日志会显示 AUTH_FAILED, AUTH_MISSING 或 REJECTED_HOST。



2. 检查 wss_panel.js 日志: sudo journalctl -u wss_panel -f。查看 /internal/auth API 的调用结果。



3. 检查数据库: sudo sqlite3 /etc/wss-panel/wss_panel.db "SELECT username, status, require_auth_header FROM users;"

Stunnel (444) 无法连接

1. stunnel4 服务未运行。



2. sshd_stunnel 服务未运行。



3. 用户未启用 "Allow Shell" (不在 shell_users 组)。



4. 用户账户被面板锁定 (usermod -L)。

1. sudo systemctl status stunnel4 和 sudo systemctl status sshd_stunnel。



2. sudo journalctl -u stunnel4 -f (查看 SSL 握手)。



3. (关键) sudo journalctl -u sshd_stunnel -f (查看 SSH 认证日志，通常会显示 AllowGroups 拒绝信息)。



4. 检查用户组: getent group shell_users。



5. 检查账户锁定: sudo passwd -S <username> (查看是否有 L 标记)。

面板操作 (创建/暂停用户) 失败

1. sudoers 权限配置错误。



2. admin 用户无法执行 sudo 命令。

1. sudo journalctl -u wss_panel -f 查看执行 safeRunCommand 时的 sudo 错误。



2. (关键) 检查 sudoers 语法: sudo visudo -c -f /etc/sudoers.d/99-wss-panel。

关键文件路径

文件/目录

目的

所有者

/etc/wss-panel/

主配置目录 (数据库, 密钥)

admin (或 $panel_user)

/etc/wss-panel/wss_panel.db

SQLite 数据库 (WAL 模式)

admin

/etc/wss-panel/root_hash.txt

面板 root 用户密码哈希

admin (600 权限)

/etc/wss-panel/internal_secret.txt

内部 API 密钥

admin (600 权限)

/usr/local/bin/wss_proxy.js

数据平面 (Proxy) 脚本

root

/etc/systemd/system/wss_panel.service

控制平面 (Panel) 服务文件

root

/etc/systemd/system/wss.service

数据平面 (Proxy) 服务文件

root

/etc/systemd/system/sshd_stunnel.service

Stunnel SSHD 服务文件

root

/etc/ssh/sshd_config_stunnel

Stunnel SSHD 配置文件

root (600 权限)

/etc/sudoers.d/99-wss-panel

(核心安全) 最小权限策略文件

root (440 权限)
