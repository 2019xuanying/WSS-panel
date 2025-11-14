#!/usr/bin/env bash

# 设置：遇到错误或使用未定义变量时退出
set -eu

# ==========================================================
# WSS 隧道与用户管理面板模块化部署脚本
# V2.0.5 (Axiom Refactor)
#
# [AXIOM V2.0.5 BUGFIX]
# - 修复: "sudo: a password is required" for "systemctl is-active"
# - wss_panel.js 在 getSystemStatus() 中需要 "systemctl is-active" 权限
#   来检查仪表盘的服务状态。
# - 已将 "$CMD_SYSTEMCTL is-active" 添加到 NOPASSWD: 列表中。
# - 修复: IPC 架构。移除了 "INTERNAL_IPC_PORT (54323)"，
#   IPC (WS) 将共享 "PANEL_PORT (54321)"。
#
# [AXIOM V2.0.3 BUGFIX]
# - 修复: "sudo: a password is required" 错误。
# - wss_panel.js 需要 `getent shadow` 来同步系统锁状态。
# - 重新在 "配置 Sudoers" 步骤中添加了 $CMD_GETENT (getent 命令)
#   到 NOPASSWD: 列表中。
# ==========================================================


# =============================
# 文件路径定义
# =============================
REPO_ROOT=$(dirname "$0")

# 安装目录
PANEL_DIR="/etc/wss-panel"
WSS_LOG_FILE="/var/log/wss.log" 
# [AXIOM V2.0] 新增: 配置文件路径
CONFIG_PATH="$PANEL_DIR/config.json"
ROOT_HASH_FILE="$PANEL_DIR/root_hash.txt"
SECRET_KEY_FILE="$PANEL_DIR/secret_key.txt"
INTERNAL_SECRET_PATH="$PANEL_DIR/internal_secret.txt" # 内部 API 密钥文件
IPTABLES_RULES="/etc/iptables/rules.v4"
DB_PATH="$PANEL_DIR/wss_panel.db"

# 脚本目标路径
WSS_PROXY_PATH="/usr/local/bin/wss_proxy.js"
PANEL_BACKEND_FILE="wss_panel.js"
PANEL_BACKEND_DEST="$PANEL_DIR/$PANEL_BACKEND_FILE" 
PANEL_HTML_DEST="$PANEL_DIR/index.html"
# [AXIOM V2.0] 新增: 分离的 JS 文件
PANEL_JS_DEST="$PANEL_DIR/app.js"
LOGIN_HTML_DEST="$PANEL_DIR/login.html" 
PACKAGE_JSON_DEST="$PANEL_DIR/package.json"

# SSHD Stunnel 路径
SSHD_STUNNEL_CONFIG="/etc/ssh/sshd_config_stunnel"
SSHD_STUNNEL_SERVICE="/etc/systemd/system/sshd_stunnel.service"


# 创建基础目录
mkdir -p "$PANEL_DIR" 
mkdir -p /etc/stunnel/certs
mkdir -p /var/log/stunnel4
touch "$WSS_LOG_FILE"

# =============================
# [AXIOM V2.0] 交互式端口和用户配置
# =============================
echo "----------------------------------"
echo "==== WSS 基础设施配置 (V2.0.5) ===="
echo "请确认或修改以下端口和服务用户设置 (回车以使用默认值)。"

# 1. 端口
read -p "  1. WSS HTTP 端口 [80]: " WSS_HTTP_PORT
WSS_HTTP_PORT=${WSS_HTTP_PORT:-80}

read -p "  2. WSS TLS 端口 [443]: " WSS_TLS_PORT
WSS_TLS_PORT=${WSS_TLS_PORT:-443}

read -p "  3. Stunnel (SSH/TLS) 端口 [444]: " STUNNEL_PORT
STUNNEL_PORT=${STUNNEL_PORT:-444}

read -p "  4. UDPGW (Badvpn) 端口 [7300]: " UDPGW_PORT
UDPGW_PORT=${UDPGW_PORT:-7300}

read -p "  5. Web 面板端口 [54321]: " PANEL_PORT
PANEL_PORT=${PANEL_PORT:-54321}

read -p "  6. 内部 SSH (WSS) 转发端口 [22]: " INTERNAL_FORWARD_PORT
INTERNAL_FORWARD_PORT=${INTERNAL_FORWARD_PORT:-22}

read -p "  7. 内部 SSH (Stunnel) 转发端口 [2222]: " SSHD_STUNNEL_PORT
SSHD_STUNNEL_PORT=${SSHD_STUNNEL_PORT:-2222}

# 2. 服务用户 (最小权限)
read -p "  8. Panel 服务用户名 [admin]: " panel_user
panel_user=${panel_user:-admin}

# --- IPC (进程间通信) 端口配置 ---
INTERNAL_API_PORT=54322 # 此端口仅用于 127.0.0.1，无需提示
# [AXIOM V2.0.5] 移除: INTERNAL_IPC_PORT，IPC 将共享 PANEL_PORT
PANEL_API_URL="http://127.0.0.1:$PANEL_PORT/internal"
PROXY_API_URL="http://127.0.0.1:$INTERNAL_API_PORT"

echo "---------------------------------"
echo "配置确认："
echo "Panel 用户: $panel_user"
echo "WSS (80/443) -> $WSS_HTTP_PORT/$WSS_TLS_PORT (转发至 $INTERNAL_FORWARD_PORT)"
echo "Stunnel (444) -> $STUNNEL_PORT (转发至 $SSHD_STUNNEL_PORT)"
echo "Web Panel (HTTP) & IPC (WS) -> $PANEL_PORT"
echo "---------------------------------"


# 交互式设置 ROOT 密码
if [ -f "$ROOT_HASH_FILE" ]; then
    echo "使用已保存的面板 Root 密码。面板端口: $PANEL_PORT"
else
    echo "==== 管理面板配置 (首次或重置) ===="
    
    echo "请为 Web 面板的 'root' 用户设置密码（输入时隐藏）。"
    while true; do
      read -s -p "面板密码: " pw1 && echo
      read -s -p "请再次确认密码: " pw2 && echo
      if [ -z "$pw1" ]; then
        echo "密码不能为空，请重新输入。"
        continue
      fi
      if [ "$pw1" != "$pw2" ]; then
        echo "两次输入不一致，请重试。"
        continue
      fi
      PANEL_ROOT_PASS_RAW="$pw1"
      break
    done
fi


echo "----------------------------------"
echo "==== 系统清理与依赖检查 (V2.0) ===="
# 停止所有相关服务并清理旧文件
systemctl stop wss stunnel4 udpgw wss_panel sshd_stunnel || true

# 依赖检查和安装
apt update -y
# 安装 Node.js (V8.0 依赖 Node 18+ 的 fetch)
if ! command -v node >/dev/null; then
    echo "正在安装 Node.js (推荐 v18/v20 LTS)..."
    curl -fsSL https://deb.nodesource.com/setup_lts.x | bash -
    apt install -y nodejs
fi

# [AXIOM V1.7.0] 增加 sudo 依赖
apt install -y wget curl git net-tools cmake build-essential openssl stunnel4 iproute2 iptables procps libsqlite3-dev passwd sudo || echo "警告: 依赖安装失败，可能影响功能。"

# [AXIOM V1.7.0] 创建 Panel 专用系统用户
if ! id -u "$panel_user" >/dev/null 2>&1; then
    echo "正在创建系统用户 '$panel_user'..."
    adduser --system --no-create-home "$panel_user"
else
    echo "系统用户 '$panel_user' 已存在。"
fi

# 安装 NPM 依赖 (V8.0 依赖 bcrypt)
echo "安装 Node.js 依赖 (bcrypt, sqlite3, express-rate-limit, ws)..."
cp "$REPO_ROOT/package.json" "$PACKAGE_JSON_DEST"
cd "$PANEL_DIR"
# [AXIOM V1.7.0] 新增 express-rate-limit
# [AXIOM V2.0] 新增 ws
if ! npm install --production; then
    echo "严重警告: Node.js 核心依赖安装失败。"
    exit 1
fi
echo "Node.js 依赖安装成功。"

# 首次部署，计算 ROOT hash
if [ ! -f "$ROOT_HASH_FILE" ] && [ -n "${PANEL_ROOT_PASS_RAW:-}" ]; then
    PANEL_ROOT_PASS_HASH=$(node -e "const bcrypt = require('bcrypt'); const hash = bcrypt.hashSync('$PANEL_ROOT_PASS_RAW', 12); console.log(hash);")
    echo "$PANEL_ROOT_PASS_HASH" > "$ROOT_HASH_FILE"
    echo "使用 bcrypt 生成 ROOT 密码哈希并保存。"
fi

# --- 生成/加载持久化的 Session Secret Key ---
if [ ! -f "$SECRET_KEY_FILE" ]; then
    SECRET_KEY=$(openssl rand -hex 32)
    echo "$SECRET_KEY" > "$SECRET_KEY_FILE"
fi

# --- 生成/加载内部 API Secret Key (新增) ---
if [ ! -f "$INTERNAL_SECRET_PATH" ]; then
    INTERNAL_SECRET=$(openssl rand -hex 32)
    echo "$INTERNAL_SECRET" > "$INTERNAL_SECRET_PATH"
    echo "生成并保存内部 API Secret Key。"
fi
INTERNAL_SECRET=$(cat "$INTERNAL_SECRET_PATH")

# [AXIOM V1.7.0] 安全加固：设置密钥文件权限
chmod 600 "$ROOT_HASH_FILE"
chmod 600 "$SECRET_KEY_FILE"
chmod 600 "$INTERNAL_SECRET_PATH"
echo "密钥文件权限已加固 (600)。"

# [AXIOM V2.0.5] 创建 config.json 配置文件 (移除 internal_ipc_port)
echo "正在创建 config.json 配置文件..."
tee "$CONFIG_PATH" > /dev/null <<EOF
{
  "panel_user": "$panel_user",
  "panel_port": $PANEL_PORT,
  "wss_http_port": $WSS_HTTP_PORT,
  "wss_tls_port": $WSS_TLS_PORT,
  "stunnel_port": $STUNNEL_PORT,
  "udpgw_port": $UDPGW_PORT,
  "internal_forward_port": $INTERNAL_FORWARD_PORT,
  "internal_api_port": $INTERNAL_API_PORT,
  "internal_api_secret": "$INTERNAL_SECRET",
  "panel_api_url": "$PANEL_API_URL",
  "proxy_api_url": "$PROXY_API_URL"
}
EOF
chmod 600 "$CONFIG_PATH"
echo "$CONFIG_PATH 已创建并加固 (600)。"

echo "----------------------------------"


# =============================
# [AXIOM V2.0.5] 配置 Sudoers (修复)
# =============================
echo "==== 配置 Sudoers (最小权限) (V2.0.5) ===="
SUDOERS_FILE="/etc/sudoers.d/99-wss-panel"
echo "正在为 '$panel_user' 创建 $SUDOERS_FILE ..."

# 获取命令的绝对路径
CMD_USERADD=$(command -v useradd)
CMD_USERMOD=$(command -v usermod)
CMD_USERDEL=$(command -v userdel)
CMD_GPGPASSWD=$(command -v gpasswd)
CMD_CHPASSWD=$(command -v chpasswd)
CMD_PKILL=$(command -v pkill)
CMD_IPTABLES=$(command -v iptables)
CMD_IPTABLES_SAVE=$(command -v iptables-save)
CMD_JOURNALCTL=$(command -v journalctl)
CMD_SYSTEMCTL=$(command -v systemctl)
# [AXIOM V2.0.3] 修复: 添加 getent 命令
CMD_GETENT=$(command -v getent)

# 写入 sudoers 配置文件
# 注意: 'tee' 用于以 root 权限写入
tee "$SUDOERS_FILE" > /dev/null <<EOF
# WSS Panel Service User ($panel_user)
# 此文件由 install.sh 自动管理
$panel_user ALL=(ALL) NOPASSWD: $CMD_USERADD
$panel_user ALL=(ALL) NOPASSWD: $CMD_USERMOD
$panel_user ALL=(ALL) NOPASSWD: $CMD_USERDEL
$panel_user ALL=(ALL) NOPASSWD: $CMD_GPGPASSWD
$panel_user ALL=(ALL) NOPASSWD: $CMD_CHPASSWD
$panel_user ALL=(ALL) NOPASSWD: $CMD_PKILL
$panel_user ALL=(ALL) NOPASSWD: $CMD_IPTABLES
$panel_user ALL=(ALL) NOPASSWD: $CMD_IPTABLES_SAVE
$panel_user ALL=(ALL) NOPASSWD: $CMD_JOURNALCTL
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart wss
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart stunnel4
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart udpgw
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL restart wss_panel
# [AXIOM V2.0.3] 修复: 添加 getent 以允许 syncUserStatus 检查 /etc/shadow
$panel_user ALL=(ALL) NOPASSWD: $CMD_GETENT
# [AXIOM V2.0.5] 修复: 添加 systemctl is-active 以允许 getSystemStatus 检查服务
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active wss
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active stunnel4
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active udpgw
$panel_user ALL=(ALL) NOPASSWD: $CMD_SYSTEMCTL is-active wss_panel
EOF

# 设置 sudoers 文件权限
chmod 440 "$SUDOERS_FILE"

# 语法检查
if ! visudo -c -f "$SUDOERS_FILE"; then
    echo "严重错误: Sudoers 文件 ($SUDOERS_FILE) 语法检查失败！"
    echo "为安全起见，已删除该文件。请检查上述命令路径。"
    rm -f "$SUDOERS_FILE"
    exit 1
fi
echo "Sudoers 配置完成。"
echo "----------------------------------"


# =============================
# BBR 拥塞控制和网络调优
# =============================
echo "==== 配置 BBR 拥塞控制和网络优化 ===="
sed -i '/# WSS_NET_START/,/# WSS_NET_END/d' /etc/sysctl.conf
cat >> /etc/sysctl.conf <<EOF
# WSS_NET_START
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_max_syn_backlog = 65536
net.core.somaxconn = 65536
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_keepalive_time = 60
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 5
# WSS_NET_END
EOF
sysctl -p > /dev/null
echo "BBR 拥塞控制和网络参数优化完成。"
echo "----------------------------------"

# =============================
# 部署代码文件
# =============================
echo "==== 部署 Node.js 代码文件 ===="
# 1. 复制 WSS Proxy
cp "$REPO_ROOT/wss_proxy.js" "$WSS_PROXY_PATH"
chmod +x "$WSS_PROXY_PATH"
echo "WSS Proxy 脚本复制到 $WSS_PROXY_PATH"

# 2. 复制 Panel Backend
cp "$REPO_ROOT/wss_panel.js" "$PANEL_BACKEND_DEST"
chmod +x "$PANEL_BACKEND_DEST"
echo "Panel Backend 脚本复制到 $PANEL_BACKEND_DEST"

# 3. 复制 Panel Frontend
cp "$REPO_ROOT/index.html" "$PANEL_HTML_DEST"
# [AXIOM V2.0.1] 复制分离的 app.js
cp "$REPO_ROOT/app.js" "$PANEL_JS_DEST"
cp "$REPO_ROOT/login.html" "$LOGIN_HTML_DEST"
echo "Panel Frontend 模板 (index.html, app.js, login.html) 复制完成。"

# 4. 初始化数据库文件
if [ ! -f "$DB_PATH" ]; then
    echo "SQLite 数据库将在 Panel 首次启动时初始化。"
fi
[ ! -f "$WSS_LOG_FILE" ] && touch "$WSS_LOG_FILE"
[ ! -f "$PANEL_DIR/audit.log" ] && touch "$PANEL_DIR/audit.log"
[ ! -f "$PANEL_DIR/hosts.json" ] && echo '[]' > "$PANEL_DIR/hosts.json"
echo "----------------------------------"


# =============================
# 安装 Stunnel4 并生成证书
# =============================
echo "==== 重新安装 Stunnel4 & 证书 (V1.7.0) ===="

# [AXIOM V1.6.0] 创建 Stunnel (444) 访问控制组
if ! getent group shell_users >/dev/null; then
    groupadd shell_users
    echo "创建 Linux 组 'shell_users' (用于 Stunnel 444 访问控制)。"
fi

openssl req -x509 -nodes -newkey rsa:2048 \
-keyout /etc/stunnel/certs/stunnel.key \
-out /etc/stunnel/certs/stunnel.crt \
-days 1095 \
-subj "/CN=example.com" > /dev/null 2>&1
sh -c 'cat /etc/stunnel/certs/stunnel.key /etc/stunnel/certs/stunnel.crt > /etc/stunnel/certs/stunnel.pem'
chmod 600 /etc/stunnel/certs/*.key
chmod 600 /etc/stunnel/certs/*.pem
chmod 644 /etc/stunnel/certs/*.crt

# [AXIOM V1.7.0] 使用自定义端口
tee /etc/stunnel/ssh-tls.conf > /dev/null <<EOF
pid=/var/run/stunnel.pid
setuid=root
setgid=root
client = no
debug = 5
output = /var/log/stunnel4/stunnel.log
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[ssh-tls-gateway]
accept = 0.0.0.0:$STUNNEL_PORT
cert = /etc/stunnel/certs/stunnel.pem
key = /etc/stunnel/certs/stunnel.pem
connect = 127.0.0.1:$SSHD_STUNNEL_PORT
EOF

systemctl enable stunnel4
systemctl restart stunnel4
echo "Stunnel4 重新启动完成，端口 $STUNNEL_PORT (转发至 $SSHD_STUNNEL_PORT)"
echo "----------------------------------"


# =============================
# 安装 UDPGW
# =============================
echo "==== 重新部署 UDPGW ===="
if [ ! -d "/root/badvpn" ]; then
    git clone https://github.com/ambrop72/badvpn.git /root/badvpn > /dev/null 2>&1
fi
mkdir -p /root/badvpn/badvpn-build
cd /root/badvpn/badvpn-build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 > /dev/null 2>&1
make -j$(nproc) > /dev/null 2>&1
cd - > /dev/null

UDPGW_SERVICE_PATH="/etc/systemd/system/udpgw.service"
UDPGW_TEMPLATE="$REPO_ROOT/udpgw.service.template"
if [ ! -f "$UDPGW_TEMPLATE" ]; then
    echo "严重错误: 找不到 UDPGW 服务模板文件: $UDPGW_TEMPLATE."
    exit 1
fi
cp "$UDPGW_TEMPLATE" "$UDPGW_SERVICE_PATH"
# [AXIOM V1.7.0] 使用自定义端口
sed -i "s|@UDPGW_PORT@|$UDPGW_PORT|g" "$UDPGW_SERVICE_PATH"

systemctl daemon-reload
systemctl enable udpgw
systemctl restart udpgw
echo "UDPGW 已部署并重启，端口: $UDPGW_PORT"
echo "----------------------------------"

# =============================
# Traffic Control (移除)
# =============================
echo "==== 清理旧的 Traffic Control (tc) 配置 ===="
IP_DEV=$(ip route | grep default | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1)

if [ -z "$IP_DEV" ]; then
    echo "警告: 无法找到主网络接口，跳过 tc 清理。"
else
    # 移除 TC 规则, 不再添加
    tc qdisc del dev "$IP_DEV" root || true
    echo "Traffic Control (tc) 规则已移除 (内存限速)。"
fi
echo "----------------------------------"

# =============================
# IPTABLES 基础配置 (移除统计)
# =============================
echo "==== 配置 IPTABLES 基础链 (IP 封禁) ===="
BLOCK_CHAIN="WSS_IP_BLOCK"

# --- 强制清理所有旧的统计链钩子 ---
echo "正在清理旧的 IPTABLES 统计链钩子..."
# 1. 清理 BLOCK_CHAIN 钩子 (通常只有一个)
while iptables -D INPUT -j $BLOCK_CHAIN 2>/dev/null; do
    echo "移除旧的 $BLOCK_CHAIN 钩子..."
done
# 2. 清理所有旧的 QUOTA_CHAIN 钩子
while iptables -D OUTPUT -j "WSS_QUOTA_OUTPUT" 2>/dev/null; do
    echo "移除旧的 WSS_QUOTA_OUTPUT 钩子..."
done
# 3. 清理所有旧的 FORWARD 钩子
while iptables -D FORWARD -j "WSS_QUOTA_FORWARD" 2>/dev/null; do
    echo "移除旧的 WSS_QUOTA_FORWARD 钩子..."
done
echo "旧钩子清理完毕。"
# ---------------------------------------------------

# 清理旧的 WSS 链和规则
iptables -F $BLOCK_CHAIN 2>/dev/null || true
iptables -X $BLOCK_CHAIN 2>/dev/null || true

# 清理并删除旧的 QUOTA 统计链
iptables -t filter -F "WSS_QUOTA_OUTPUT" 2>/dev/null || true
iptables -t filter -X "WSS_QUOTA_OUTPUT" 2>/dev/null || true
iptables -t filter -F "WSS_QUOTA_FORWARD" 2>/dev/null || true
iptables -t filter -X "WSS_QUOTA_FORWARD" 2>/dev/null || true

# 1. 创建并插入 IP 阻断链 (保留)
iptables -N $BLOCK_CHAIN 2>/dev/null || true
iptables -I INPUT 1 -j $BLOCK_CHAIN 

# 2. 不再创建 WSS_QUOTA 链

echo "IPTABLES 基础链配置完成 (内存统计)。"
echo "----------------------------------"

# IPTABLES 规则持久化 (保留)
echo "==== 配置 IPTABLES 规则持久化 ===="
if ! command -v netfilter-persistent >/dev/null; then
    DEBIAN_FRONTEND=noninteractive apt install -y netfilter-persistent iptables-persistent || echo "警告: 无法安装 iptables-persistent。"
fi
if command -v netfilter-persistent >/dev/null; then
    /sbin/iptables-save > "$IPTABLES_RULES" || echo "警告: 无法保存 IPTABLES 规则到 $IPTABLES_RULES"
    if ! systemctl is-enabled netfilter-persistent >/dev/null 2>&1; then
        systemctl enable netfilter-persistent || true
    fi
    systemctl start netfilter-persistent || true
    echo "IPTABLES 规则已保存并配置为持久化。"
else
    echo "警告: 未找到 netfilter-persistent。"
fi
echo "----------------------------------"


# =============================
# 部署 Systemd 服务
# =============================
echo "==== 部署 Systemd 服务 ===="

# 1. 部署 WSS Proxy Service
WSS_SERVICE_PATH="/etc/systemd/system/wss.service"
WSS_TEMPLATE="$REPO_ROOT/wss.service.template"
if [ ! -f "$WSS_TEMPLATE" ]; then
    echo "严重错误: 找不到 WSS 服务模板文件: $WSS_TEMPLATE."
    exit 1
fi
cp "$WSS_TEMPLATE" "$WSS_SERVICE_PATH"
# [AXIOM V2.0.2] 修复: 重新添加必要的 sed 替换
sed -i "s|@WSS_LOG_FILE_PATH@|$WSS_LOG_FILE|g" "$WSS_SERVICE_PATH"
sed -i "s|@WSS_PROXY_SCRIPT_PATH@|$WSS_PROXY_PATH|g" "$WSS_SERVICE_PATH"


# 2. 部署 Panel Service
PANEL_SERVICE_PATH="/etc/systemd/system/wss_panel.service"
PANEL_TEMPLATE="$REPO_ROOT/wss_panel.service.template"
if [ ! -f "$PANEL_TEMPLATE" ]; then
    echo "严重错误: 找不到 PANEL 服务模板文件: $PANEL_TEMPLATE."
    exit 1
fi
cp "$PANEL_TEMPLATE" "$PANEL_SERVICE_PATH"
# [AXIOM V2.0.2] 修复: 重新添加必要的 sed 替换
sed -i "s|@PANEL_DIR@|$PANEL_DIR|g" "$PANEL_SERVICE_PATH"
sed -i "s|@PANEL_USER@|$panel_user|g" "$PANEL_SERVICE_PATH"
sed -i "s|@PANEL_BACKEND_SCRIPT_PATH@|$PANEL_BACKEND_FILE|g" "$PANEL_SERVICE_PATH"


# [AXIOM V1.7.0] 更改文件所有权，以便 $panel_user 可以访问
chown -R "$panel_user:$panel_user" "$PANEL_DIR"
chown "$panel_user:$panel_user" "$WSS_LOG_FILE"
# [AXIOM V2.0] 确保 config.json 也是 $panel_user 所有
chown "$panel_user:$panel_user" "$CONFIG_PATH"
chmod 600 "$CONFIG_PATH" # 再次确认权限
echo "已将 $PANEL_DIR 和 $WSS_LOG_FILE 的所有权交给 $panel_user"


# 3. [AXIOM V1.6.0] 部署 Stunnel SSHD Service (新增)
# (将在 SSHD 配置部分创建)

systemctl daemon-reload
# 启动顺序: Panel 先启动, WSS 后启动
systemctl enable wss_panel
systemctl start wss_panel
systemctl enable wss
systemctl start wss
echo "WSS V2.0 (Panel & Proxy) 服务已部署并启动。"
echo "----------------------------------"

# =============================
# SSHD 安全配置 (V1.7.0 Refactor)
# =============================
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak.wss$(date +%s)"
SSHD_SERVICE=$(systemctl list-units --full -all | grep -q "sshd.service" && echo "sshd" || echo "ssh")

echo "==== 配置 SSHD 隧道策略 (V1.7.0) ===="
cp -a "$SSHD_CONFIG" "${SSHD_CONFIG}${BACKUP_SUFFIX}"
echo "SSHD 配置已备份到 ${SSHD_CONFIG}${BACKUP_SUFFIX}"

# --- 1. 配置主 SSHD (WSS 专用, 端口 $INTERNAL_FORWARD_PORT) ---
sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_CONFIG"
# 确保主 SSHD 监听 $INTERNAL_FORWARD_PORT
if ! grep -q "^Port $INTERNAL_FORWARD_PORT" "$SSHD_CONFIG" && [ "$INTERNAL_FORWARD_PORT" != "22" ]; then
    echo "警告：正在修改主 SSHD 端口为 $INTERNAL_FORWARD_PORT。"
    sed -i -E "/^[#\s]*Port /d" "$SSHD_CONFIG" # 删除所有旧 Port
    echo "Port $INTERNAL_FORWARD_PORT" >> "$SSHD_CONFIG"
fi

echo "" >> "$SSHD_CONFIG" || true
cat >> "$SSHD_CONFIG" <<EOF
# WSS_TUNNEL_BLOCK_START -- WSS (80/443) -> Port $INTERNAL_FORWARD_PORT
Match Address 127.0.0.1,::1
    PasswordAuthentication yes
    KbdInteractiveAuthentication yes
    AllowTcpForwarding yes
    # ForceCommand /bin/false # 禁用, 允许 WSS 转发
# WSS_TUNNEL_BLOCK_END -- managed by modular-deploy.sh
EOF

# --- 2. 创建 Stunnel SSHD 配置文件 (Stunnel 专用, 端口 $SSHD_STUNNEL_PORT) ---
cp "$SSHD_CONFIG" "$SSHD_STUNNEL_CONFIG"
# 移除 WSS 块 (if it exists)
sed -i '/# WSS_TUNNEL_BLOCK_START/,/# WSS_TUNNEL_BLOCK_END/d' "$SSHD_STUNNEL_CONFIG"

# [AXIOM V1.6.1] 修复: 移除所有现有的 Port 和 ListenAddress 
sed -i -E "/^[#\s]*Port /d" "$SSHD_STUNNEL_CONFIG"
sed -i -E "/^[#\s]*ListenAddress /d" "$SSHD_STUNNEL_CONFIG"

# 添加 Stunnel 专用块 (核心安全控制)
echo "" >> "$SSHD_STUNNEL_CONFIG" || true
cat >> "$SSHD_STUNNEL_CONFIG" <<EOF
# WSS_STUNNEL_BLOCK_START -- Stunnel (444) -> Port $SSHD_STUNNEL_PORT
Port $SSHD_STUNNEL_PORT
ListenAddress 127.0.0.1
ListenAddress ::1
PasswordAuthentication yes
KbdInteractiveAuthentication yes
AllowTcpForwarding yes
AllowGroups shell_users
# WSS_STUNNEL_BLOCK_END -- managed by modular-deploy.sh
EOF

# --- 3. 创建 Stunnel SSHD Systemd 服务 ---
tee "$SSHD_STUNNEL_SERVICE" > /dev/null <<EOF
[Unit]
Description=OpenSSH Stunnel (Port $STUNNEL_PORT) Service
After=network.target auditd.service
ConditionPathExists=!/etc/ssh/sshd_not_to_be_run

[Service]
ExecStart=/usr/sbin/sshd -D -f $SSHD_STUNNEL_CONFIG
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=42s

[Install]
WantedBy=multi-user.target
EOF


chmod 600 "$SSHD_CONFIG"
chmod 600 "$SSHD_STUNNEL_CONFIG"

echo "重新加载并重启所有 ssh 服务 ($SSHD_SERVICE, sshd_stunnel)"
if ! /usr/sbin/sshd -t -f "$SSHD_CONFIG" 2>/dev/null; then
    echo "--------------------------------------------------------"
    echo "⚠️ 警告: 主 SSHD ($SSHD_CONFIG) 配置语法测试失败。将使用备份文件还原配置。"
    echo "--------------------------------------------------------"
    cp "${SSHD_CONFIG}${BACKUP_SUFFIX}" "$SSHD_CONFIG" || true
    systemctl daemon-reload
    systemctl restart "$SSHD_SERVICE" || true
    echo "配置还原完成。SSH服务已重启，但WSS隧道配置未应用。"
    exit 1
fi
if ! /usr/sbin/sshd -t -f "$SSHD_STUNNEL_CONFIG" 2>/dev/null; then
    echo "--------------------------------------------------------"
    echo "⚠️ 警告: Stunnel SSHD ($SSHD_STUNNEL_CONFIG) 配置语法测试失败。"
    echo "--------------------------------------------------------"
    rm -f "$SSHD_STUNNEL_CONFIG"
    rm -f "$SSHD_STUNNEL_SERVICE"
    systemctl daemon-reload
    exit 1
fi

systemctl daemon-reload
systemctl restart "$SSHD_SERVICE"
systemctl enable sshd_stunnel
systemctl restart sshd_stunnel

echo "SSHD 配置更新完成。"
echo "WSS ($WSS_HTTP_PORT/$WSS_TLS_PORT) -> 转发至 $SSHD_SERVICE (端口 $INTERNAL_FORWARD_PORT)"
echo "Stunnel ($STUNNEL_PORT) -> 转发至 sshd_stunnel (端口 $SSHD_STUNNEL_PORT)"
echo "----------------------------------"


# =============================
# 最终重启所有关键服务
# =============================
echo "==== 最终重启所有关键服务，确保配置生效 ===="
if command -v netfilter-persistent >/dev/null; then
    echo "最终保存 IPTABLES 规则 (仅含 IP 封禁)..."
    /sbin/iptables-save > "$IPTABLES_RULES" || echo "警告: 最终保存 IPTABLES 规则失败。"
    systemctl restart netfilter-persistent || true
fi

# 确保启动顺序
systemctl restart stunnel4 udpgw
systemctl restart wss_panel
systemctl restart wss
systemctl restart "$SSHD_SERVICE"
systemctl restart sshd_stunnel

echo "所有服务重启完成：Stunnel4, UDPGW, Web Panel, WSS Proxy, SSHD(x2)。"
echo "----------------------------------"


# 清理敏感变量
unset PANEL_ROOT_PASS_RAW
unset INTERNAL_SECRET

echo "=================================================="
echo "✅ V2.0.5 架构部署完成！(已修复 Sudoers 和 IPC 启动)"
echo "=================================================="
echo ""
echo "🔥 WSS & Stunnel 基础设施已启动。"
echo "🌐 WSS 用户管理面板 (V2.0.5) 已在后台运行。"
echo "⚡ WSS 代理 (V8.2.0) 已启动, 负责认证、统计和限速。"
echo "🔌 实时 IPC 管道已激活。"
echo ""
echo "--- 访问信息 ---"
echo "Web 面板地址: http://[您的服务器IP]:$PANEL_PORT"
echo "Web 面板用户名: root"
echo "Web 面板密码: [您刚才设置的密码]"
echo ""
echo "--- 故障排查 ---"
echo "WSS 代理 (Data Plane) 状态: sudo systemctl status wss"
echo "Stunnel 状态: sudo systemctl status stunnel4"
echo "Web 面板 (Control Plane) 状态: sudo systemctl status wss_panel"
echo "SSH (WSS) 状态监控: sudo journalctl -u $SSHD_SERVICE -f"
echo "SSH (Stunnel) 状态监控: sudo journalctl -u sshd_stunnel -f"
echo "=================================================="
