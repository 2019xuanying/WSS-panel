/**
 * WSS Panel Backend (Node.js + Express + SQLite)
 * V8.2.0 (Axiom Refactor V2.0.5)
 *
 * [AXIOM V2.0.5 CHANGELOG]
 * - [CRITICAL BUGFIX] 修复了 IPC 架构。
 * - "connect ECONNREFUSED 127.0.0.1:54323"
 * - "net::ERR_CONNECTION_REFUSED" on port 54321
 * - 移除了 `internal_ipc_port` (54323)。
 * - 重写了 `startApp` 和 `startIpcServer`。
 * - `Express` (app) 和 `WebSocketServer` (wssIpc) 现在共享
 * 同一个 `http.createServer` (server)。
 * - `server` 监听 `config.panel_port` (例如 54321)。
 * - `server` 会捕获 "upgrade" 事件，并将路径为 "/ipc" 的
 * WebSocket 握手请求交给 `wssIpc` 处理。
 * - 这确保了 HTTP API (54321) 和 IPC WS (54321/ipc)
 * 都正确运行在同一个端口上。
 *
 * - [CRITICAL BUGFIX] 修复了 "sudo: a password is required" 错误。
 * - 在 `getSystemStatus` 中，`sudo systemctl is-active`
 * 调用失败，因为它没有被添加到 `install.sh` 的 sudoers 列表中。
 * - 已在 `install.sh` (V2.0.5) 中修复此问题。
 *
 * [AXIOM V2.0.0 CHANGELOG]
 * 1. [架构] 配置外部化:
 * - 不再使用 process.env。
 * - 从 /etc/wss-panel/config.json 加载所有配置。
 * - 新增 /api/settings/config API 用于前端获取和修改配置。
 * 2. [架构] 前端分离:
 * - 使用 express.static 托管 /etc/wss-panel/ 中的静态文件
 * (index.html, app.js, login.html)。
 * - 移除了所有 app.get('/') 和 app.get('/login') 中的
 * HTML 渲染和模板替换逻辑。
 * 3. [架构] 实时 IPC (推送):
 * - 引入 'ws' 库。
 * - 创建了一个 WebSocket 服务器 (wssIpc) 用于实时 IPC。
 * - 重构了 kickUser, saveUserSettings, pauseUser, killAll 等函数，
 * 使其立即通过 broadcastToProxies() "推送" 命令。
 * - syncUserStatus() 现在只负责同步流量，不再负责状态。
 *
 * [AXIOM V2.1.0 INTEGRATION]
 * - 新增: `tls` 和 `dns` 模块用于 SNI 查找器。
 * - 新增: API 路由 `/api/utils/find_sni`。
 */

// --- 核心依赖 ---
const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const bcrypt = require('bcrypt');
const { execFile, spawn, exec } = require('child_process'); // AXIOM: 修复: 添加 'exec'
const { promisify } = require('util');
const path = require('path');
const fs = require('fs/promises');
const fsSync = require('fs');
const os = require('os');
const sqlite3 = require('sqlite3');
const { open } = require('sqlite');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
// [AXIOM V2.0] 引入 http 和 ws
const http = require('http');
const { WebSocketServer } = require('ws');
// [AXIOM V2.1] 引入 tls 和 dns
const tls = require('tls');
const dns = require('dns');

const app = express();
const asyncExecFile = promisify(execFile);

// --- [AXIOM V2.0] 配置加载 ---
// 默认配置，防止 config.json 不存在时崩溃
let config = {
    panel_user: "admin",
    panel_port: 54321,
    wss_http_port: 80,
    wss_tls_port: 443,
    stunnel_port: 444,
    udpgw_port: 7300,
    internal_forward_port: 22,
    internal_api_port: 54322,
    internal_api_secret: "default-secret-key-please-change",
    panel_api_url: "http://127.0.0.1:54321/internal",
    proxy_api_url: "http://127.0.0.1:54322"
};

const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');

try {
    const configData = fsSync.readFileSync(CONFIG_PATH, 'utf8');
    config = JSON.parse(configData);
    console.log(`[AXIOM V2.0] 成功从 ${CONFIG_PATH} 加载配置。`);
} catch (e) {
    console.error(`[CRITICAL] 无法加载 ${CONFIG_PATH}: ${e.message}。将使用默认端口。`);
    // 写入默认配置，以便下次启动
    try {
        fsSync.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8');
        console.log(`[AXIOM V2.0] 已写入默认配置到 ${CONFIG_PATH}。`);
    } catch (writeErr) {
        console.error(`[CRITICAL] 无法写入默认配置: ${writeErr.message}`);
    }
}
// --- 结束配置加载 ---


// --- 核心常量 (现在从 config 读取) ---
const DB_PATH = path.join(PANEL_DIR, 'wss_panel.db');
const ROOT_HASH_FILE = path.join(PANEL_DIR, 'root_hash.txt');
const AUDIT_LOG_PATH = path.join(PANEL_DIR, 'audit.log');
const SECRET_KEY_PATH = path.join(PANEL_DIR, 'secret_key.txt');
const INTERNAL_SECRET_PATH = path.join(PANEL_DIR, 'internal_secret.txt');
const HOSTS_DB_PATH = path.join(PANEL_DIR, 'hosts.json');
// [AXIOM V2.0] 移除 HTML 路径，因为我们使用 express.static
const ROOT_USERNAME = "root";
const GIGA_BYTE = 1024 * 1024 * 1024;
const BLOCK_CHAIN = "WSS_IP_BLOCK";
const BACKGROUND_SYNC_INTERVAL = 30000;
const SHELL_DEFAULT = "/sbin/nologin";
const SHELL_INTERACTIVE = "/sbin/nologin";
const CORE_SERVICES = {
    'wss': 'WSS Proxy',
    'stunnel4': 'Stunnel4',
    'udpgw': 'UDPGW',
    'wss_panel': 'Web Panel'
};
let db;
// [AXIOM V2.0] 用于 IPC 的 WebSocket 服务器实例
let wssIpc = null;

// [AXIOM V1.7.0] 需要 sudo 的命令列表
// [AXIOM V2.0.5] 修复: 添加 systemctl is-active
const SUDO_COMMANDS = new Set([
    'useradd', 'usermod', 'userdel', 'gpasswd', 'chpasswd', 'pkill',
    'iptables', 'iptables-save', 'journalctl', 
    'systemctl', // 包含 'systemctl restart'
    'getent', 
    'systemctl is-active' // 'is-active' 是 'systemctl' 的子命令，但为清晰起见单独处理
]);

// --- 辅助函数 ---

/**
 * [AXIOM V1.7.0] 运行系统命令的安全封装 (集成 sudo)
 */
async function safeRunCommand(command, inputData = null) {
    let fullCommand = [...command];
    let baseCommand = command[0];

    // [AXIOM V2.0.5] 特殊处理 "systemctl is-active"
    if (command[0] === 'systemctl' && command[1] === 'is-active') {
        baseCommand = 'systemctl is-active';
    }

    // [AXIOM V1.7.0] 最小权限: 检查是否需要 sudo
    if (SUDO_COMMANDS.has(baseCommand)) {
        fullCommand.unshift('sudo');
    }

    // [AXIOM V1.3] 使用 spawn 处理 chpasswd 的 stdin
    if (command[0] === 'chpasswd' || (command[0] === 'sudo' && command[1] === 'chpasswd') && inputData) {
        return new Promise((resolve, reject) => {
            const child = spawn(fullCommand[0], fullCommand.slice(1), {
                stdio: ['pipe', 'pipe', 'pipe'],
                env: { ...process.env, PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' }
            });
            let stdout = '';
            let stderr = '';
            child.stdout.on('data', (data) => { stdout += data.toString(); });
            child.stderr.on('data', (data) => { stderr += data.toString(); });
            child.on('close', (code) => {
                if (code === 0) {
                    resolve({ success: true, output: stdout.trim() });
                } else {
                    console.error(`safeRunCommand (spawn) Stderr (Command: ${fullCommand.join(' ')}): ${stderr.trim()}`);
                    resolve({ success: false, output: stderr.trim() || `Command ${fullCommand.join(' ')} failed with code ${code}` });
                }
            });
             child.on('error', (err) => {
                 console.error(`safeRunCommand (spawn) Error (Command: ${fullCommand.join(' ')}): ${err.message}`);
                resolve({ success: false, output: err.message });
            });
            try {
                child.stdin.write(inputData);
                child.stdin.end();
            } catch (e) {
                 resolve({ success: false, output: e.message });
            }
        });
    }

    // [AXIOM V1.3] 保持原有的 asyncExecFile 用于其他命令
    try {
        const { stdout, stderr } = await asyncExecFile(fullCommand[0], fullCommand.slice(1), {
            timeout: 10000,
            input: inputData,
            env: { ...process.env, PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' }
        });
        const output = (stdout + stderr).trim();
        
        if (stderr && 
            !stderr.includes('user not found') &&
            !stderr.includes('userdel: user') &&
            !stderr.includes('already exists')
           ) {
             console.warn(`safeRunCommand (asyncExecFile) Non-fatal Stderr (Command: ${fullCommand.join(' ')}): ${stderr.trim()}`);
             // Don't return false, just warn
        }
        
        return { success: true, output: stdout.trim() };

    } catch (e) {
        
        // [AXIOM V2.0.5] 修复: 'systemctl is-active' 在服务未运行时返回 code 3
        if (baseCommand === 'systemctl is-active' && e.code === 3) {
            return { success: false, output: 'inactive' };
        }
        
        if (e.code === 1) {
             console.warn(`safeRunCommand (asyncExecFile) Ignored Exit Code 1 (Command: ${fullCommand.join(' ')}): Stderr=${e.stderr || 'N/A'}`);
             return { success: true, output: e.stdout.trim() };
        }
        
        if (e.code !== 'ETIMEDOUT') {
            console.error(`safeRunCommand (asyncExecFile) Fatal Error (Command: ${fullCommand.join(' ')}): Code=${e.code}, Stderr=${e.stderr || 'N/A'}, Msg=${e.message}`);
        }
        return { success: false, output: e.stderr || e.message || `Command ${fullCommand[0]} failed.` };
    }
}


/** 异步记录管理员操作日志。 */
async function logAction(actionType, username, details = "") {
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    const operatorIp = '127.0.0.1 (System)'; 
    const logEntry = `[${timestamp}] [USER:${username}] [IP:${operatorIp}] ACTION:${actionType} DETAILS: ${details}\n`;
    try {
        await fs.appendFile(AUDIT_LOG_PATH, logEntry);
    } catch (e) {
        console.error(`Error writing to audit log: ${e.message}`);
    }
}

/**
 * [AXIOM V1.7.0] 批量获取所有系统用户的锁定状态 (使用 sudo)。
 */
async function getSystemLockStatus() {
    try {
        // [AXIOM V1.7.0] 'getent shadow' 需要 root 权限，使用 sudo
        const { success, output } = await safeRunCommand(['getent', 'shadow']);
        if (!success) {
            console.error("[CRITICAL] getSystemLockStatus: Failed to run 'sudo getent shadow'. Falling back to empty map.");
            return new Set();
        }
        const lockedUsers = new Set();
        output.split('\n').forEach(line => {
            const parts = line.split(':');
            if (parts.length > 1) {
                const username = parts[0];
                const passwordHash = parts[1];
                if (passwordHash.startsWith('!') || passwordHash.startsWith('*')) {
                    lockedUsers.add(username);
                }
            }
        });
        return lockedUsers;
    } catch (e) {
        console.error(`[CRITICAL] getSystemLockStatus Error: ${e.message}`);
        return new Set();
    }
}

// --- 数据库 Setup and User Retrieval ---

async function initDb() {
    // [AXIOM V1.5.1]
    db = await open({
        filename: DB_PATH,
        driver: sqlite3.Database
    });

    // [AXIOM V1.6.1 WAL PATCH] 启用 WAL (Write-Ahead Logging) 模式
    try {
        await db.exec('PRAGMA journal_mode = WAL;');
        console.log("[DB] WAL (Write-Ahead Logging) mode enabled.");
    } catch (e) {
        console.error(`[DB] Failed to enable WAL mode: ${e.message}`);
    }
    // [END WAL PATCH]

    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY, password_hash TEXT, created_at TEXT,
            status TEXT, expiration_date TEXT, quota_gb REAL,
            usage_gb REAL DEFAULT 0.0, rate_kbps INTEGER DEFAULT 0,
            max_connections INTEGER DEFAULT 0,
            require_auth_header INTEGER DEFAULT 1, realtime_speed_up REAL DEFAULT 0.0,
            realtime_speed_down REAL DEFAULT 0.0, active_connections INTEGER DEFAULT 0,
            status_text TEXT, allow_shell INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS ip_bans ( ip TEXT PRIMARY KEY, reason TEXT, added_by TEXT, timestamp TEXT );
        CREATE TABLE IF NOT EXISTS traffic_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL,
            date TEXT NOT NULL, usage_gb REAL DEFAULT 0.0, UNIQUE(username, date)
        );
        CREATE TABLE IF NOT EXISTS global_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    `);
    await db.exec(`CREATE INDEX IF NOT EXISTS idx_traffic_history_user_date ON traffic_history (username, date);`);
    
    // --- 数据库字段迁移检查 (确保字段存在) ---
    try { await db.exec('ALTER TABLE users ADD COLUMN password_hash TEXT'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN max_connections INTEGER DEFAULT 0'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN require_auth_header INTEGER DEFAULT 1'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN realtime_speed_up REAL DEFAULT 0.0'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN realtime_speed_down REAL DEFAULT 0.0'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN active_connections INTEGER DEFAULT 0'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN status_text TEXT'); } catch (e) { /* ignore */ }
    try { await db.exec('ALTER TABLE users ADD COLUMN allow_shell INTEGER DEFAULT 0'); } catch (e) { /* ignore */ }

    // [AXIOM V1.5.1] 迁移旧的 fuse_threshold_kbps (如果存在)
    let oldFuseColumnExists = false;
    try {
        await db.exec('ALTER TABLE users ADD COLUMN fuse_threshold_kbps INTEGER DEFAULT 0');
    } catch (e) {
        if (e.message.includes("duplicate column name")) {
            oldFuseColumnExists = true;
        }
    }
    
    // [AXIOM V1.5.2] 确保在迁移前 `global_settings` 已有默认值
    await db.run("INSERT OR IGNORE INTO global_settings (key, value) VALUES (?, ?)", 'fuse_threshold_kbps', '0');

    if (oldFuseColumnExists) {
        console.log("[MIGRATE] Old 'fuse_threshold_kbps' column detected. Migrating to global_settings table...");
        try {
            const firstUser = await db.get('SELECT fuse_threshold_kbps FROM users WHERE fuse_threshold_kbps > 0 LIMIT 1');
            if (firstUser && firstUser.fuse_threshold_kbps > 0) {
                await db.run(
                    "UPDATE global_settings SET value = ? WHERE key = ?", 
                    firstUser.fuse_threshold_kbps.toString(),
                    'fuse_threshold_kbps'
                );
                console.log(`[MIGRATE] Migrated fuse value ${firstUser.fuse_threshold_kbps} to global_settings.`);
            }
        } catch (e) {
            console.error(`[MIGRATE] Failed to migrate old fuse setting: ${e.message}`);
        }
    }
    
    console.log(`SQLite database initialized at ${DB_PATH}`);
}

async function getUserByUsername(username) {
    return db.get('SELECT * FROM users WHERE username = ?', username);
}

async function loadRootHash() {
    try {
        const hash = await fs.readFile(ROOT_HASH_FILE, 'utf8');
        return hash.trim();
    } catch (e) {
        console.error(`Root hash file not found: ${e.message}`);
        return null;
    }
}

function loadInternalSecret() {
    // [AXIOM V2.0] 从 config 对象读取
    return config.internal_api_secret;
}

async function loadHosts() {
    try {
        if (!fsSync.existsSync(HOSTS_DB_PATH)) {
            await fs.writeFile(HOSTS_DB_PATH, '[]', 'utf8');
            return [];
        }
        const data = await fs.readFile(HOSTS_DB_PATH, 'utf8');
        const hosts = JSON.parse(data);
        if (Array.isArray(hosts)) {
            return hosts.map(h => String(h).toLowerCase()).filter(h => h);
        }
        return [];
    } catch (e) {
        console.error(`Error loading hosts file: ${e.message}`);
        return [];
    }
}

// --- Authentication Middleware ---

function loadSecretKey() {
    try {
        return fsSync.readFileSync(SECRET_KEY_PATH, 'utf8').trim();
    } catch (e) {
        const key = require('crypto').randomBytes(32).toString('hex');
        fsSync.writeFileSync(SECRET_KEY_PATH, key, 'utf8');
        return key;
    }
}

app.use(session({
    secret: loadSecretKey(),
    resave: false,
    saveUninitialized: true,
    cookie: { 
        secure: false, httpOnly: true,
        maxAge: 3600000 * 24, sameSite: 'lax'
    }
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

function loginRequired(req, res, next) {
    if (req.session.loggedIn) {
        next();
    } else {
        if (req.path.startsWith('/api/')) {
            return res.status(401).json({ success: false, message: "Authentication failed or session expired" });
        }
        // [AXIOM V2.0] 登录失败时重定向到静态 login.html
        return res.redirect('/login.html');
    }
}

// --- Business Logic / System Sync (Optimized) ---

/**
 * [AXIOM V2.0] 重构: 广播命令到所有连接的 Proxy 实例
 * @param {object} message - 要发送的 JSON 对象 (例如 { action: 'kick', username: 'test' })
 */
function broadcastToProxies(message) {
    if (!wssIpc || wssIpc.clients.size === 0) {
        console.warn("[IPC_WSS] 无法广播: 没有连接的数据平面 (Proxy) 实例。");
        return;
    }
    
    const payload = JSON.stringify(message);
    console.log(`[IPC_WSS] 正在广播 (-> ${wssIpc.clients.size} 个代理): ${payload}`);
    
    wssIpc.clients.forEach((client) => {
        if (client.readyState === 1) { // 1 = WebSocket.OPEN
            client.send(payload, (err) => {
                if (err) {
                    console.error(`[IPC_WSS] 发送消息到代理失败: ${err.message}`);
                }
            });
        }
    });
}


/**
 * [AXIOM V2.0] 重构: kickUserFromProxy 不再使用 API，而是通过 IPC 推送
 */
async function kickUserFromProxy(username) {
    broadcastToProxies({
        action: 'kick',
        username: username
    });
    return true; // 假设推送成功
}

/**
 * [AXIOM V1.7.0] 状态同步 (已适配 sudo)
 */
async function syncUserStatus() {
    
    let proxyStats = {}; 
    const systemLockedUsers = await getSystemLockStatus();
    
    let globalFuseLimit = 0;
    try {
        const fuseSetting = await db.get("SELECT value FROM global_settings WHERE key = 'fuse_threshold_kbps'");
        if (fuseSetting) {
            globalFuseLimit = parseInt(fuseSetting.value) || 0;
        }
    } catch (e) {
        console.error(`[SYNC] Failed to read global_settings: ${e.message}`);
    }

    let allUsers = [];
    try {
        allUsers = await db.all('SELECT * FROM users');
    } catch (e) {
        console.error(`[SYNC] Failed to fetch users from DB: ${e.message}`);
        return;
    }
    
    try {
        const response = await fetch(config.proxy_api_url + '/stats', {
            method: 'GET',
            headers: { 'x-internal-secret': loadInternalSecret() }
        });
        if (response.ok) { proxyStats = await response.json(); }
        else { throw new Error(`Proxy stats API failed with status ${response.status}`); }
    } catch (e) {
        // [AXIOM V2.0.3] 修复: 降低此日志的级别
        console.warn(`[SYNC] 无法获取 wss_proxy 的 /stats API: ${e.message}`);
    }

    const today = new Date().toISOString().split('T')[0];
    const usersToUpdate = []; 
    
    for (const user of allUsers) {
        const username = user.username;
        const stats = proxyStats[username] || null;
        
        // --- 1. 更新流量和速度 (来自 Proxy) ---
        const liveSpeed = (stats && stats.speed_kbps) ? stats.speed_kbps : { upload: 0, download: 0 };
        const liveConnections = (stats && stats.connections) ? stats.connections : 0;
        const deltaBytes = (stats && stats.traffic_delta) ? stats.traffic_delta : 0;
        const oldUsageGb = user.usage_gb || 0;
        let usageUpdated = false;
        if (deltaBytes > 0) {
            user.usage_gb = (oldUsageGb) + (deltaBytes / GIGA_BYTE);
            user.usage_gb = parseFloat(user.usage_gb.toFixed(4));
            usageUpdated = true;
            try {
                await db.run('INSERT OR IGNORE INTO traffic_history (username, date, usage_gb) VALUES (?, ?, 0.0)', [username, today]);
                await db.run('UPDATE traffic_history SET usage_gb = usage_gb + ? WHERE username = ? AND date = ?', [deltaBytes / GIGA_BYTE, username, today]);
            } catch (e) { console.error(`[CRITICAL] Failed to update traffic_history for ${username}: ${e.message}`); }
        }
        const speedChanged = user.realtime_speed_up !== liveSpeed.upload ||
                             user.realtime_speed_down !== liveSpeed.download ||
                             user.active_connections !== liveConnections;
        user.realtime_speed_up = liveSpeed.upload;
        user.realtime_speed_down = liveSpeed.download;
        user.active_connections = liveConnections;

        // --- 2. 确定 DB 状态 (用于 80/443) ---
        let isExpired = false, isOverQuota = false, isOverSpeed = false, isOverConn = false;
        
        if (user.expiration_date) {
            try {
                const expiry = new Date(user.expiration_date);
                if (!isNaN(expiry) && expiry < new Date()) { isExpired = true; }
            } catch (e) { /* ignore */ }
        }
        if (user.quota_gb > 0 && user.usage_gb >= user.quota_gb) { isOverQuota = true; }
        
        const totalSpeed = user.realtime_speed_up + user.realtime_speed_down;
        if (globalFuseLimit > 0 && totalSpeed >= globalFuseLimit) { isOverSpeed = true; }
        
        // [AXIOM V2.0] 并发检查 (isOverConn) 已从 sync 移除
        // 它现在完全由 wss_proxy 在连接时实时处理。
        
        const currentDbStatus = user.status; // (active, paused, expired, exceeded, fused)
        let newDbStatus = currentDbStatus;
        let statusChanged = false;

        // [AXIOM V2.0] 移除 isOverConn 检查
        
        if (isOverSpeed) {
            if (currentDbStatus !== 'fused') {
                newDbStatus = 'fused';
                statusChanged = true;
                await logAction("USER_FUSED", "SYSTEM", `User ${username} exceeded speed limit (${totalSpeed} KB/s). Kicking.`);
                await kickUserFromProxy(username); // 踢 WSS
            }
        } else if (isExpired) {
            if (currentDbStatus !== 'expired') { newDbStatus = 'expired'; statusChanged = true; }
        } else if (isOverQuota) {
            if (currentDbStatus !== 'exceeded') { newDbStatus = 'exceeded'; statusChanged = true; }
        } else if (currentDbStatus === 'paused') {
            newDbStatus = 'paused';
        } else {
            if (currentDbStatus !== 'active') { newDbStatus = 'active'; statusChanged = true; }
        }
        
        user.status = newDbStatus;

        // --- 3. 确定系统锁状态 (用于 444) ---
        const systemLocked = systemLockedUsers.has(username);
        
        // =================================================================
        // [AXIOM V1.5.4] 修复: 真正解耦 WSS(80/443) 和 Shell(444)
        // [AXIOM V1.7.0] 适配: 使用 sudo usermod
        // =================================================================
        const shouldBeLocked_SYS = (user.status !== 'active');
        
        if (shouldBeLocked_SYS && !systemLocked) {
            // [AXIOM V1.7.0] 适配 sudo
            await safeRunCommand(['usermod', '-L', username]);
        } else if (!shouldBeLocked_SYS && systemLocked) {
            // [AXIOM V1.7.0] 适配 sudo
            await safeRunCommand(['usermod', '-U', username]);
        }
        
        // --- 4. 更新状态文本 ---
        if (user.status === 'active') {
            user.status_text = '启用 (Active)';
        } else if (user.status === 'paused') {
            user.status_text = (user.allow_shell === 0) ? '暂停 (Shell Off)' : '暂停 (Manual)';
        } else if (user.status === 'expired') {
            user.status_text = '已到期 (Expired)';
        } else if (user.status === 'exceeded') {
            user.status_text = '超额 (Quota)';
        } else if (user.status === 'fused') {
            user.status_text = '熔断 (Fused)';
        } else {
            user.status_text = '未知';
        }

        if (statusChanged || usageUpdated || speedChanged) {
             usersToUpdate.push(user);
        }
    }
    
    // --- 5. 批量更新 DB ---
    if (usersToUpdate.length > 0) {
        try {
            await db.run('BEGIN TRANSACTION');
            for (const u of usersToUpdate) {
                await db.run(`UPDATE users SET 
                                status = ?, usage_gb = ?, realtime_speed_up = ?, 
                                realtime_speed_down = ?, active_connections = ?, status_text = ?
                              WHERE username = ?`,
                    u.status, u.usage_gb, u.realtime_speed_up, 
                    u.realtime_speed_down, u.active_connections, u.status_text,
                    u.username);
            }
            await db.run('COMMIT');
            console.log(`[SYNC] Background sync completed. Updated ${usersToUpdate.length} users.`);
        } catch (e) {
            await db.run('ROLLBACK').catch(()=>{});
            console.error(`[SYNC] CRITICAL: Background sync DB update failed: ${e.message}`);
        }
    } else {
        // [AXIOM V2.0.3] 修复: 降低此日志的级别
        // console.log(`[SYNC] Background sync completed. No changes detected.`);
    }
}

async function getProxyLiveConnections() {
    let liveIps = [];
    try {
        const response = await fetch(config.proxy_api_url + '/stats', {
            method: 'GET',
            headers: { 'x-internal-secret': loadInternalSecret() }
        });
        if (!response.ok) { throw new Error(`Proxy stats API failed with status ${response.status}`); }
        const data = await response.json();
        liveIps = Object.keys(data.live_ips || {}).map(ip => ({ ip: ip, username: data.live_ips[ip] }));
    } catch (e) {
        console.error(`[LIVE_IP] Failed to fetch live connections from wss_proxy: ${e.message}`);
    }
    const ipList = await Promise.all(
        liveIps.map(async item => {
            const isBanned = (await manageIpIptables(item.ip, 'check')).success;
            return { ip: item.ip, is_banned: isBanned, username: item.username };
        })
    );
    return ipList;
}

/**
 * [AXIOM V1.7.0] 适配 sudo
 */
async function manageIpIptables(ip, action, chainName = BLOCK_CHAIN) {
    // [AXIOM V1.7.0] 适配 sudo
    if (action === 'check') {
        const result = await asyncExecFile('sudo', ['iptables', '-C', chainName, '-s', ip, '-j', 'DROP'], { timeout: 2000 }).catch(e => e);
        return { success: result.code === 0 };
    }
    let command;
    if (action === 'block') {
        await safeRunCommand(['iptables', '-D', chainName, '-s', ip, '-j', 'DROP']);
        command = ['iptables', '-I', chainName, '1', '-s', ip, '-j', 'DROP'];
    } else if (action === 'unblock') {
        command = ['iptables', '-D', chainName, '-s', ip, '-j', 'DROP'];
    } else {
        return { success: false, output: "Invalid action" };
    }
    // [AXIOM V1.7.0] safeRunCommand 将自动添加 sudo
    const result = await safeRunCommand(command);
    if (result.success) {
        // [AXIOM V1.7.0] safeRunCommand 将自动添加 sudo
        safeRunCommand(['iptables-save'], null, true)
            .then(({ output }) => fs.writeFile('/etc/iptables/rules.v4', output))
            .catch(e => console.error(`Warning: Failed to save iptables rules: ${e.message}`));
    }
    return result;
}

// --- API Routes (Admin Panel) ---

// [AXIOM V2.0] 静态文件服务
// 托管 /etc/wss-panel/ 目录下的所有前端文件
app.use(express.static(PANEL_DIR));

// [AXIOM V2.0] 移除 app.get('/') 和 app.get('/login')
// 它们现在由 express.static 自动处理

// [AXIOM V1.7.0] 登录防爆破
const loginLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 分钟
	max: 5, // 限制每个 IP 在 15 分钟内 5 次登录请求
	message: '登录尝试次数过多，IP已被限制，请 15 分钟后再试',
    // keyGenerator: (req, res) => req.ip, // 默认使用 req.ip
    handler: (req, res, next, options) => {
        // [AXIOM V2.0] 重定向到静态 login.html
        res.redirect(`/login.html?error=${encodeURIComponent(options.message)}`);
    },
	standardHeaders: true, // 返回速率限制信息 (RateLimit-Limit, RateLimit-Remaining, RateLimit-Reset)
	legacyHeaders: false, // 禁用 'X-RateLimit-*' headers
});

app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;
    const rootHash = await loadRootHash();
    if (username === ROOT_USERNAME && password && rootHash) {
        try {
            const match = await bcrypt.compare(password, rootHash);
            if (match) {
                req.session.loggedIn = true;
                req.session.username = ROOT_USERNAME;
                await logAction("LOGIN_SUCCESS", ROOT_USERNAME, "Web UI Login");
                // [AXIOM V2.0] 重定向到静态 index.html
                return res.redirect('/index.html');
            }
        } catch (e) { console.error(`Bcrypt comparison failed: ${e.message}`); }
    }
    await logAction("LOGIN_FAILED", username, "Wrong credentials or invalid username attempt");
    // [AXIOM V2.0] 重定向到静态 login.html
    res.redirect('/login.html?error=' + encodeURIComponent('用户名或密码错误。'));
});

app.get('/logout', (req, res) => {
    logAction("LOGOUT_SUCCESS", req.session.username || ROOT_USERNAME, "Web UI Logout");
    req.session.destroy();
    // [AXIOM V2.0] 重定向到静态 login.html
    res.redirect('/login.html');
});

// --- Internal API (For Proxy) ---
const internalApi = express.Router();
internalApi.use((req, res, next) => {
    const clientIp = req.ip;
    if (clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '::ffff:127.0.0.1') {
        next();
    } else {
        console.warn(`[AUTH] Denied external access attempt to /internal API from ${clientIp}`);
        res.status(403).json({ success: false, message: 'Forbidden' });
    }
});

/**
 * [AXIOM V1.5.1] 认证 API (已修复 阻塞I/O 瓶颈)
 */
internalApi.post('/auth', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Missing credentials' });
    }
    try {
        const user = await getUserByUsername(username);
        if (!user || !user.password_hash) {
            await logAction("PROXY_AUTH_FAIL", username, "User not found or no password hash in DB.");
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
        const match = await bcrypt.compare(password, user.password_hash);
        if (match) {
            if (user.status !== 'active') {
                 await logAction("PROXY_AUTH_LOCKED", username, `User locked in DB (Status: ${user.status}).`);
                 return res.status(403).json({ success: false, message: 'User locked or disabled' });
            }
            await logAction("PROXY_AUTH_SUCCESS", username, "Proxy auth success.");
            res.json({
                success: true,
                limits: {
                    rate_kbps: user.rate_kbps || 0,
                    max_connections: user.max_connections || 0,
                },
                require_auth_header: user.require_auth_header === 0 ? 0 : 1
            });
        } else {
            await logAction("PROXY_AUTH_FAIL", username, "Invalid password (bcrypt mismatch).");
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    } catch (e) {
        await logAction("PROXY_AUTH_ERROR", username, `Internal auth error: ${e.message}`);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});

internalApi.get('/auth/user-settings', async (req, res) => {
    const { username } = req.query;
    if (!username) {
        return res.status(400).json({ success: false, message: 'Missing username' });
    }
    try {
        const user = await getUserByUsername(username);
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        res.json({
            success: true,
            require_auth_header: user.require_auth_header === 0 ? 0 : 1
        });
    } catch (e) {
        console.error(`[PROXY_SETTINGS] Internal API error: ${e.message}`);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
});
app.use('/internal', internalApi);

// --- Public API (For Admin Panel UI) ---
const api = express.Router();

/**
 * [AXIOM V2.0.5] 修复: "sudo: a password is required"
 * 为 'systemctl is-active' 添加 NOPASSWD 权限
 */
api.get('/system/status', async (req, res) => {
    try {
        let diskUsedPercent = 55.0; 
        try {
             const { stdout } = await promisify(exec)('df -P / | tail -1'); 
             const parts = stdout.trim().split(/\s+/);
             if (parts.length >= 5) { diskUsedPercent = parseFloat(parts[4].replace('%', '')); }
        } catch (e) { /* ignore */ }
        const mem = os.totalmem();
        const memFree = os.freemem();
        const serviceStatuses = {};
        for (const [id, name] of Object.entries(CORE_SERVICES)) {
            // [AXIOM V2.0.5] 修复: 'systemctl is-active' 现在有 sudo 权限
            const { success } = await safeRunCommand(['systemctl', 'is-active', id]);
            const status = success ? 'running' : 'failed';
            serviceStatuses[id] = { name, status, label: status === 'running' ? "运行中" : "失败" };
        }
        const ports = [
            { name: 'WSS_HTTP', port: config.wss_http_port, protocol: 'TCP', status: 'LISTEN' },
            { name: 'WSS_TLS', port: config.wss_tls_port, protocol: 'TCP', status: 'LISTEN' },
            { name: 'STUNNEL', port: config.stunnel_port, protocol: 'TCP', status: 'LISTEN' },
            { name: 'UDPGW', port: config.udpgw_port, protocol: 'UDP', status: 'LISTEN' },
            { name: 'PANEL', port: config.panel_port, protocol: 'TCP', status: 'LISTEN' },
            { name: 'SSH_INTERNAL', port: config.internal_forward_port, protocol: 'TCP', status: 'LISTEN' }
        ];
        
        let liveIpCount = 0;
        try {
            const response = await fetch(config.proxy_api_url + '/stats', {
                method: 'GET',
                headers: { 'x-internal-secret': loadInternalSecret() }
            });
            if (response.ok) {
                const proxyStats = await response.json();
                liveIpCount = Object.keys(proxyStats.live_ips || {}).length;
            }
        } catch (e) {
            console.warn(`[SYSTEM_STATUS] Could not fetch proxy stats for live IP count: ${e.message}`);
        }
        const users = await db.all('SELECT * FROM users');
        let totalTraffic = 0, pausedCount = 0, expiredCount = 0, exceededCount = 0, fusedCount = 0;
        for (const user of users) {
            totalTraffic += user.usage_gb || 0;
            if (user.status === 'paused') pausedCount++;
            else if (user.status === 'expired') expiredCount++;
            else if (user.status === 'exceeded') exceededCount++;
            else if (user.status === 'fused') fusedCount++;
        }
        res.json({
            success: true,
            cpu_usage: (os.loadavg()[0] / os.cpus().length) * 100,
            memory_used_gb: (mem - memFree) / GIGA_BYTE,
            memory_total_gb: mem / GIGA_BYTE,
            disk_used_percent: diskUsedPercent,
            services: serviceStatuses,
            ports: ports,
            user_stats: {
                total: users.length, active: liveIpCount, paused: pausedCount,
                expired: expiredCount, exceeded: exceededCount,
                fused: fusedCount, total_traffic_gb: totalTraffic
            }
        });
    } catch (e) {
        await logAction("SYSTEM_STATUS_ERROR", req.session.username, `Status check failed: ${e.message}`);
        res.status(500).json({ success: false, message: `System status check failed: ${e.message}` });
    }
});


api.post('/system/control', async (req, res) => {
    // [AXIOM V1.7.0] 适配 sudo
    const { service, action } = req.body;
    if (!CORE_SERVICES[service] || action !== 'restart') {
        return res.status(400).json({ success: false, message: "无效的服务或操作" });
    }
    // [AXIOM V1.7.0] safeRunCommand 将自动添加 sudo
    const { success, output } = await safeRunCommand(['systemctl', action, service]);
    if (success) {
        await logAction("SERVICE_CONTROL_SUCCESS", req.session.username, `Successfully executed ${action} on ${service}`);
        res.json({ success: true, message: `服务 ${CORE_SERVICES[service]} 已成功执行 ${action} 操作。` });
    } else {
        await logAction("SERVICE_CONTROL_FAIL", req.session.username, `Failed to ${action} ${service}: ${output}`);
        res.status(500).json({ success: false, message: `服务 ${CORE_SERVICES[service]} 操作失败: ${output}` });
    }
});

api.post('/system/logs', async (req, res) => {
    // [AXIOM V1.7.0] 适配 sudo
    const serviceName = req.body.service;
    if (!CORE_SERVICES[serviceName]) { return res.status(400).json({ success: false, message: "无效的服务名称。" }); }
    try {
        // [AXIOM V1.7.0] safeRunCommand 将自动添加 sudo
        const { success, output } = await safeRunCommand(['journalctl', '-u', serviceName, '-n', '50', '--no-pager', '--utc']);
        res.json({ success: true, logs: success ? output : `错误: 无法获取 ${serviceName} 日志. ${output}` });
    } catch (e) {
        res.status(500).json({ success: false, message: `日志获取异常: ${e.message}` });
    }
});

api.get('/system/audit_logs', async (req, res) => {
    try {
        const logContent = await fs.readFile(AUDIT_LOG_PATH, 'utf8');
        const logs = logContent.trim().split('\n').filter(line => line.trim().length > 0).slice(-20);
        res.json({ success: true, logs });
    } catch (e) {
        res.json({ success: true, logs: ["读取日志失败或日志文件为空。"] });
    }
});

api.get('/system/active_ips', async (req, res) => {
    try {
        const ipList = await getProxyLiveConnections();
        res.json({ success: true, active_ips: ipList });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

api.get('/users/live-stats', async (req, res) => {
    try {
        const response = await fetch(config.proxy_api_url + '/stats', {
            method: 'GET',
            headers: { 'x-internal-secret': loadInternalSecret() }
        });
        if (!response.ok) { throw new Error(`Proxy stats API failed with status ${response.status}`); }
        const proxyStats = await response.json();
        const userStats = Object.keys(proxyStats)
            .filter(key => key !== 'live_ips')
            .reduce((acc, key) => { acc[key] = proxyStats[key]; return acc; }, {});
        res.json({ success: true, stats: userStats });
    } catch (e) {
        res.status(500).json({ success: false, message: e.message });
    }
});

api.get('/users/list', async (req, res) => {
    // ... (函数内容无变化, V1.4 逻辑已正确) ...
    try {
        let users = await db.all('SELECT *, realtime_speed_up, realtime_speed_down, active_connections, status_text, allow_shell FROM users');
        users.forEach(u => {
            u.status_text = u.status_text || (u.status === 'active' ? '启用 (Active)' : 
                               (u.status === 'paused' ? '暂停 (Manual)' : 
                               (u.status === 'expired' ? '已到期 (Expired)' : 
                               (u.status === 'exceeded' ? '超额 (Quota)' :
                               (u.status === 'fused' ? '熔断 (Fused)' : '未知')))));
            u.allow_shell = u.allow_shell || 0;
        });
        res.json({ success: true, users: users });
    } catch (e) {
        res.status(500).json({ success: false, message: `Failed to fetch users: ${e.message}` });
    }
});


/**
 * [AXIOM V1.7.0] /users/add (适配 sudo)
 */
api.post('/users/add', async (req, res) => {
    const { username, password, expiration_days, quota_gb, rate_kbps, max_connections, require_auth_header, allow_shell } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: "缺少用户名或密码" });
    if (!/^[a-z0-9_]{3,16}$/.test(username)) return res.status(400).json({ success: false, message: "用户名格式不正确" });
    const existingUser = await getUserByUsername(username);
    if (existingUser) return res.status(409).json({ success: false, message: `用户组 ${username} 已存在于面板` });
    try {
        // [AXIOM V1.6.0] Shell is always nologin
        const shell = SHELL_DEFAULT; 
        // [AXIOM V1.7.0] safeRunCommand 将自动添加 sudo
        const { success: userAddSuccess, output: userAddOutput } = await safeRunCommand(['useradd', '-m', '-s', shell, username]);
        if (!userAddSuccess && !userAddOutput.includes("already exists")) {
            throw new Error(`创建系统用户失败: ${userAddOutput}`);
        }
        
        // [AXIOM V1.7.0] safeRunCommand 将自动添加 sudo
        const chpasswdInput = `${username}:${password}`;
        const { success: chpassSuccess, output: chpassOutput } = await safeRunCommand(['chpasswd'], chpasswdInput);
        if (!chpassSuccess) { throw new Error(`设置系统密码失败: ${chpassOutput}`); }
        
        // [AXIOM V1.7.0] safeRunCommand 将自动添加 sudo
        const lockCmd = ['usermod', '-U', username];
        const { success: lockSuccess, output: lockOutput } = await safeRunCommand(lockCmd);
        if (!lockSuccess) { throw new Error(`解锁账户失败: ${lockOutput}`); }

        // [AXIOM V1.6.0] Add to shell_users group if allowed
        if (allow_shell) {
            // [AXIOM V1.7.0] safeRunCommand 将自动添加 sudo
            const { success: groupSuccess, output: groupOutput } = await safeRunCommand(['usermod', '-a', '-G', 'shell_users', username]);
            if (!groupSuccess) {
                console.warn(`[V1.6.0] Failed to add ${username} to shell_users group: ${groupOutput}. Maybe group doesn't exist?`);
            }
        }

        const passwordHash = await bcrypt.hash(password, 12);
        const expiryDate = new Date(Date.now() + expiration_days * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
        
        const newStatus = "active";
        const newStatusText = "启用 (Active)";
        
        const newUser = {
            username: username, password_hash: passwordHash,
            created_at: new Date().toISOString().replace('T', ' ').substring(0, 19),
            status: newStatus,
            expiration_date: expiryDate, 
            quota_gb: parseFloat(quota_gb), usage_gb: 0.0, 
            rate_kbps: parseInt(rate_kbps), 
            max_connections: parseInt(max_connections) || 0,
            require_auth_header: require_auth_header ? 1 : 0,
            realtime_speed_up: 0.0, realtime_speed_down: 0.0,
            active_connections: 0, 
            status_text: newStatusText,
            allow_shell: allow_shell ? 1 : 0
        };
        await db.run(`INSERT INTO users (
                        username, password_hash, created_at, status, expiration_date, 
                        quota_gb, usage_gb, rate_kbps, max_connections, 
                        require_auth_header, realtime_speed_up, realtime_speed_down, active_connections, status_text,
                        allow_shell
                      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                      Object.values(newUser));
        await logAction("USER_ADD_SUCCESS", req.session.username, `User ${username} created (Shell: ${shell}, Lock: UNLOCKED, Shell Group: ${allow_shell})`);
        
        // [AXIOM V2.0] IPC 推送: 立即通知所有 proxy 新用户
        broadcastToProxies({
            action: 'update_limits',
            username: username,
            limits: {
                rate_kbps: newUser.rate_kbps,
                max_connections: newUser.max_connections,
                require_auth_header: newUser.require_auth_header
            }
        });
        
        res.json({ success: true, message: `用户 ${username} 创建成功，有效期至 ${expiryDate}` });
    } catch (e) {
        // [AXIOM V1.7.0] safeRunCommand 将自动添加 sudo
        await safeRunCommand(['userdel', '-r', username]);
        await logAction("USER_ADD_FAIL", req.session.username, `Failed to create user ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});


api.post('/users/delete', async (req, res) => {
    // [AXIOM V1.7.0] 适配 sudo
    const { username } = req.body;
    const userToDelete = await getUserByUsername(username);
    if (!userToDelete) return res.status(404).json({ success: false, message: `用户组 ${username} 不存在` });
    try {
        await kickUserFromProxy(username); // 踢 WSS
        await safeRunCommand(['pkill', '-9', '-u', username]); // 踢 SSH
        await safeRunCommand(['userdel', '-r', username]); // 删系统用户
        await db.run('DELETE FROM users WHERE username = ?', username);
        await db.run('DELETE FROM traffic_history WHERE username = ?', username);
        
        // [AXIOM V2.0] IPC 推送: 立即通知所有 proxy 删除用户
        broadcastToProxies({
            action: 'delete',
            username: username
        });
        
        await logAction("USER_DELETE_SUCCESS", req.session.username, `Deleted user ${username}`);
        res.json({ success: true, message: `用户组 ${username} 已删除，会话已终止` });
    } catch (e) {
        await logAction("USER_DELETE_FAIL", req.session.username, `Failed to delete user ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `删除操作失败: ${e.message}` });
    }
});

/**
 * [AXIOM V2.0] /users/set_settings (重构以支持 IPC 推送)
 */
api.post('/users/set_settings', async (req, res) => {
    const { username, expiry_date, quota_gb, rate_kbps, max_connections, new_password, require_auth_header, allow_shell } = req.body;
    
    const user = await getUserByUsername(username);
    if (!user) return res.status(404).json({ success: false, message: `用户 ${username} 不存在` });
    
    try {
        const new_allow_shell = allow_shell ? 1 : 0;
        
        let updateFields = {
            expiration_date: expiry_date || "", 
            quota_gb: parseFloat(quota_gb), 
            rate_kbps: parseInt(rate_kbps), 
            max_connections: parseInt(max_connections) || 0,
            require_auth_header: require_auth_header ? 1 : 0,
            allow_shell: new_allow_shell
        };
        
        let updateSql = 'UPDATE users SET ';
        const updateValues = [];
        const fieldNames = Object.keys(updateFields);

        // 1. 更新密码 (Bcrypt + System)
        if (new_password) {
            // [AXIOM V1.7.0] safeRunCommand 将自动添加 sudo
            const chpasswdInput = `${username}:${new_password}`;
            const { success, output } = await safeRunCommand(['chpasswd'], chpasswdInput);
            if (!success) throw new Error(`Failed to update system password: ${output}`);
            const passwordHash = await bcrypt.hash(new_password, 12);
            updateSql += 'password_hash = ?, ';
            updateValues.push(passwordHash);
            await kickUserFromProxy(username); // 踢 WSS
            await safeRunCommand(['pkill', '-9', '-u', username]); // 踢 Stunnel/SSH
            await logAction("USER_PASS_CHANGE", req.session.username, `Password changed (DB + System) for ${username}. Kicking sessions.`);
        }
        
        // [AXIOM V1.6.0] 检查并更新 Shell Group
        if (user.allow_shell != new_allow_shell) {
            
            let groupCmd, groupActionLog;
            if (new_allow_shell === 1) {
                // [AXIOM V1.7.0] 适配 sudo
                groupCmd = ['usermod', '-a', '-G', 'shell_users', username];
                groupActionLog = "Added to shell_users group";
            } else {
                // [AXIOM V1.7.0] 适配 sudo
                groupCmd = ['gpasswd', '-d', username, 'shell_users'];
                groupActionLog = "Removed from shell_users group";
                await safeRunCommand(['pkill', '-9', '-u', username]);
            }
            
            // [AXIOM V1.7.0] safeRunCommand 将自动添加 sudo
            const { success: groupSuccess, output: groupOutput } = await safeRunCommand(groupCmd);
            if (!groupSuccess) {
                if (!groupOutput.includes("is not a member")) {
                    throw new Error(`Failed to update group membership: ${groupOutput}`);
                }
            }
            
            await logAction("USER_SHELL_CHANGE", req.session.username, `Stunnel (444) access for ${username} ${new_allow_shell ? 'ENABLED' : 'DISABLED'}. ${groupActionLog}.`);
        }

        // 3. 更新 DB 字段
        fieldNames.forEach(field => {
            updateSql += `${field} = ?, `;
            updateValues.push(updateFields[field]);
        });
        
        updateSql = updateSql.slice(0, -2); // 移除最后的逗号和空格
        updateSql += ' WHERE username = ?';
        updateValues.push(username);
        await db.run(updateSql, updateValues);
        
        // [AXIOM V2.0] IPC 推送: 立即通知所有 proxy 更新限制
        broadcastToProxies({
            action: 'update_limits',
            username: username,
            limits: {
                rate_kbps: updateFields.rate_kbps,
                max_connections: updateFields.max_connections,
                require_auth_header: updateFields.require_auth_header
            }
        });
        
        setTimeout(syncUserStatus, 1000); 

        await logAction("USER_SETTINGS_UPDATE", req.session.username, `Settings updated for ${username}.`);
        res.json({ success: true, message: `用户 ${username} 的设置已保存。` });

    } catch (e) {
        await logAction("USER_SETTINGS_FAIL", req.session.username, `Failed to update settings for ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});

/**
 * [AXIOM V2.0] /users/status (重构以支持 IPC 推送)
 */
api.post('/users/status', async (req, res) => {
    const { username, action } = req.body;
    const user = await getUserByUsername(username);
    if (!user) return res.status(404).json({ success: false, message: `用户 ${username} 不存在` });
    try {
        let newStatus = 'active';
        let newStatusText = '启用 (Active)';
        
        if (action === 'pause') {
            newStatus = 'paused';
            newStatusText = '暂停 (Manual)';
            // [AXIOM V1.7.0] safeRunCommand 将自动添加 sudo
            await safeRunCommand(['usermod', '-L', username]); 
            await kickUserFromProxy(username);
            await safeRunCommand(['pkill', '-9', '-u', username]);
            await logAction("USER_PAUSE", req.session.username, `User ${username} manually paused (System Locked).`);
        
        } else if (action === 'enable') {
            newStatus = 'active';
            newStatusText = '启用 (Active)';
            // [AXIOM V1.7.0] safeRunCommand 将自动添加 sudo
            await safeRunCommand(['usermod', '-U', username]); 
            await logAction("USER_ENABLE", req.session.username, `User ${username} manually enabled (System Unlocked).`);
        }
        
        await db.run(`UPDATE users SET status = ?, status_text = ? WHERE username = ?`, newStatus, newStatusText, username);
        res.json({ success: true, message: `用户 ${username} 状态已更新。` });
    } catch (e) {
        await logAction("USER_STATUS_FAIL", req.session.username, `Failed to change status for ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});

api.post('/users/reset_traffic', async (req, res) => {
    const { username } = req.body;
    const user = await getUserByUsername(username);
    if (!user) return res.status(404).json({ success: false, message: `用户 ${username} 不存在` });
    try {
        await db.run('BEGIN TRANSACTION');
        await db.run(`UPDATE users SET usage_gb = 0.0 WHERE username = ?`, username);
        await db.run(`DELETE FROM traffic_history WHERE username = ?`, username);
        
        // [AXIOM V2.0] IPC 推送: 立即通知所有 proxy 重置流量
        // (旧的 /reset_traffic API 已移除)
        broadcastToProxies({
            action: 'reset_traffic',
            username: username
        });
        
        await db.run('COMMIT');
        
        if (user.status === 'exceeded') {
             await db.run(`UPDATE users SET status = 'active', status_text = '启用 (Active)' WHERE username = ?`, username);
        }
        
        setTimeout(syncUserStatus, 1000);

        await logAction("USER_TRAFFIC_RESET", req.session.username, `Traffic usage reset for ${username}.`);
        res.json({ success: true, message: `用户 ${username} 的流量使用量和历史记录已重置。` });
    } catch (e) {
        await db.run('ROLLBACK').catch(() => {});
        await logAction("USER_TRAFFIC_FAIL", req.session.username, `Failed to reset traffic for ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});

api.post('/users/kill_all', async (req, res) => {
    // [AXIOM V1.7.0] 适配 sudo
    const { username } = req.body;
    const user = await getUserByUsername(username);
    if (!user) return res.status(404).json({ success: false, message: `用户 ${username} 不存在` });
    try {
        const wss_success = await kickUserFromProxy(username);
        // [AXIOM V1.7.0] safeRunCommand 将自动添加 sudo
        const ssh_success = (await safeRunCommand(['pkill', '-9', '-u', username])).success;
        if (wss_success || ssh_success) {
            await logAction("USER_KILL_SESSIONS", req.session.username, `All active sessions (WSS + SSHD) killed for ${username}.`);
            res.json({ success: true, message: `用户 ${username} 的所有活跃连接已强制断开。` });
        } else {
            throw new Error("Proxy /kick and pkill API failed.");
        }
    } catch (e) {
        await logAction("USER_KILL_FAIL", req.session.username, `Failed to kill sessions for ${username}: ${e.message}`);
        res.status(500).json({ success: false, message: `操作失败: ${e.message}` });
    }
});

api.post('/users/batch-action', async (req, res) => {
    // [AXIOM V2.0] 适配 IPC
    const { action, usernames, days } = req.body;
    if (!action || !Array.isArray(usernames) || usernames.length === 0) {
        return res.status(400).json({ success: false, message: "无效的请求参数。" });
    }
    let successCount = 0, failedCount = 0; const errors = [];
    try {
        if (action === 'delete') {
            await db.run('BEGIN TRANSACTION');
            for (const username of usernames) {
                try {
                    await kickUserFromProxy(username); 
                    await safeRunCommand(['pkill', '-9', '-u', username]);
                    await safeRunCommand(['userdel', '-r', username]); 
                    await db.run('DELETE FROM users WHERE username = ?', username);
                    await db.run('DELETE FROM traffic_history WHERE username = ?', username);
                    broadcastToProxies({ action: 'delete', username: username });
                    successCount++;
                } catch(e) { failedCount++; errors.push(`${username}: ${e.message}`); }
            }
            await db.run('COMMIT');
        } else if (action === 'pause') {
            await db.run('BEGIN TRANSACTION');
            for (const username of usernames) {
                try {
                    await db.run(`UPDATE users SET status = 'paused', status_text = '暂停 (Manual)' WHERE username = ?`, username);
                    await safeRunCommand(['usermod', '-L', username]); // 锁定
                    await kickUserFromProxy(username); 
                    await safeRunCommand(['pkill', '-9', '-u', username]);
                    successCount++;
                } catch(e) { failedCount++; errors.push(`${username}: ${e.message}`); }
            }
            await db.run('COMMIT');
        } else if (action === 'enable') {
            await db.run('BEGIN TRANSACTION');
            for (const username of usernames) {
                try {
                    const user = await getUserByUsername(username);
                    if (!user) { throw new Error("User not found"); }
                    
                    await db.run(`UPDATE users SET status = 'active', status_text = '启用 (Active)' WHERE username = ?`, username);
                    await safeRunCommand(['usermod', '-U', username]); // 解锁
                    successCount++;
                } catch(e) { failedCount++; errors.push(`${username}: ${e.message}`); }
            }
            await db.run('COMMIT');
        } else if (action === 'renew') {
            const renewDays = parseInt(days) || 30; const today = new Date();
            await db.run('BEGIN TRANSACTION');
            for (const username of usernames) {
                try {
                    const user = await getUserByUsername(username);
                    if (!user) { failedCount++; errors.push(`${username}: not found`); continue; }
                    let currentExpiry = null;
                    try { if (user.expiration_date) { currentExpiry = new Date(user.expiration_date); } } catch(e) {}
                    let baseDate = today;
                    if (currentExpiry && !isNaN(currentExpiry) && currentExpiry > today) { baseDate = currentExpiry; }
                    const newExpiryDate = new Date(baseDate.getTime() + renewDays * 24 * 60 * 60 * 1000);
                    const newExpiryString = newExpiryDate.toISOString().split('T')[0];
                    
                    await db.run(`UPDATE users SET expiration_date = ?, status = 'active', status_text = '启用 (Active)' WHERE username = ?`, newExpiryString, username);
                    await safeRunCommand(['usermod', '-U', username]); // 解锁
                    successCount++;
                } catch(e) { failedCount++; errors.push(`${username}: ${e.message}`); }
            }
            await db.run('COMMIT');
        } else {
            return res.status(400).json({ success: false, message: "无效的动作。" });
        }
        await logAction("USER_BATCH_ACTION", req.session.username, `Action: ${action}, Days: ${days || 'N/A'}, Success: ${successCount}, Failed: ${failedCount}.`);
        res.json({ success: true, message: `批量操作 "${action}" 完成。成功 ${successCount} 个, 失败 ${failedCount} 个。`, errors: errors });
    } catch (e) {
        await db.run('ROLLBACK').catch(() => {});
        await logAction("USER_BATCH_FAIL", req.session.username, `Action: ${action} failed: ${e.message}`);
        res.status(500).json({ success: false, message: `批量操作失败: ${e.message}` });
    }
});


api.get('/users/traffic-history', async (req, res) => {
    const { username } = req.query;
    if (!username) { return res.status(400).json({ success: false, message: "缺少用户名。" }); }
    try {
        const history = await db.all(`SELECT date, usage_gb FROM traffic_history WHERE username = ? ORDER BY date DESC LIMIT 30`, [username]);
        res.json({ success: true, history: history.reverse() }); 
    } catch (e) {
        res.status(500).json({ success: false, message: `获取流量历史失败: ${e.message}` });
    }
});


api.get('/settings/hosts', async (req, res) => {
    const hosts = await loadHosts();
    res.json({ success: true, hosts });
});

api.post('/settings/hosts', async (req, res) => {
    const { hosts: newHostsRaw } = req.body;
    if (!Array.isArray(newHostsRaw)) return res.status(400).json({ success: false, message: "Hosts 必须是列表格式" });
    try {
        const newHosts = newHostsRaw.map(h => String(h).trim().toLowerCase()).filter(h => h);
        await fs.writeFile(HOSTS_DB_PATH, JSON.stringify(newHosts, null, 4), 'utf8');
        
        // [AXIOM V2.0] IPC 推送: 立即通知所有 proxy 重载 hosts
        broadcastToProxies({
            action: 'reload_hosts'
        });
        
        await logAction("HOSTS_UPDATE", req.session.username, `Updated host whitelist. Count: ${newHosts.length}`);
        res.json({ success: true, message: `Host 白名单已更新，WSS 代理将自动热重载。` });
    } catch (e) {
        res.status(500).json({ success: false, message: `保存 Hosts 配置失败: ${e.message}` });
    }
});

api.get('/settings/global', async (req, res) => {
    try {
        const setting = await db.get("SELECT value FROM global_settings WHERE key = 'fuse_threshold_kbps'");
        res.json({
            success: true,
            settings: {
                fuse_threshold_kbps: setting ? parseInt(setting.value) : 0
            }
        });
    } catch (e) {
        res.status(500).json({ success: false, message: `获取全局设置失败: ${e.message}` });
    }
});

api.post('/settings/global', async (req, res) => {
    const { fuse_threshold_kbps } = req.body;
    if (fuse_threshold_kbps === undefined) { return res.status(400).json({ success: false, message: "缺少熔断阈值" }); }
    try {
        const threshold = parseInt(fuse_threshold_kbps) || 0;
        
        await db.run(
            "INSERT OR REPLACE INTO global_settings (key, value) VALUES (?, ?)", 
            'fuse_threshold_kbps', 
            threshold.toString()
        );

        // [AXIOM V2.0] IPC 推送: 立即通知所有 proxy 更新全局限制
        broadcastToProxies({
            action: 'update_global_limits',
            limits: {
                fuse_threshold_kbps: threshold
            }
        });

        await logAction("GLOBAL_SETTINGS_UPDATE", req.session.username, `Global fuse threshold set to ${threshold} KB/s.`);
        res.json({ success: true, message: `全局熔断阈值 (${threshold} KB/s) 已保存。` });

    } catch (e) {
        await logAction("GLOBAL_SETTINGS_FAIL", req.session.username, `Failed to save global settings: ${e.message}`);
        res.status(500).json({ success: false, message: `保存设置失败: ${e.message}` });
    }
});

// [AXIOM V2.0] 新增: API 用于获取和保存端口配置
api.get('/settings/config', (req, res) => {
    // config 变量在启动时已从 config.json 加载
    // (移除 internal_api_secret 以确保安全)
    const { internal_api_secret, ...safeConfig } = config;
    res.json({ success: true, config: safeConfig });
});

api.post('/settings/config', async (req, res) => {
    const newConfigData = req.body;
    if (!newConfigData) {
        return res.status(400).json({ success: false, message: "无效的配置数据。" });
    }

    try {
        // 1. 从内存加载当前配置 (包含密钥)
        let currentConfig = { ...config };
        
        // 2. 更新允许修改的字段
        const fieldsToUpdate = [
            'panel_port', 'wss_http_port', 'wss_tls_port', 
            'stunnel_port', 'udpgw_port', 'internal_forward_port'
        ];
        
        let requiresWssRestart = false;
        let requiresPanelRestart = false;
        let requiresStunnelRestart = false;
        let requiresUdpGwRestart = false;

        fieldsToUpdate.forEach(key => {
            const newValue = parseInt(newConfigData[key]);
            if (newValue && newValue !== currentConfig[key]) {
                console.log(`[CONFIG] 端口变更: ${key} 从 ${currentConfig[key]} -> ${newValue}`);
                currentConfig[key] = newValue;
                // 标记哪些服务需要重启
                if (key === 'panel_port') requiresPanelRestart = true;
                if (key === 'wss_http_port' || key === 'wss_tls_port' || key === 'internal_forward_port') requiresWssRestart = true;
                if (key === 'stunnel_port') requiresStunnelRestart = true;
                if (key === 'udpgw_port') requiresUdpGwRestart = true;
            }
        });
        
        // 3. 更新 URL
        currentConfig.panel_api_url = `http://127.0.0.1:${currentConfig.panel_port}/internal`;
        // proxy_api_url 不需要变，因为它基于 internal_api_port (54322)

        // 4. 将完整配置写回 config.json
        await fs.writeFile(CONFIG_PATH, JSON.stringify(currentConfig, null, 2), 'utf8');
        await logAction("CONFIG_SAVE_SUCCESS", req.session.username, `配置已保存到 ${CONFIG_PATH}`);
        
        // 5. [AXIOM V2.0] 异步重启所需的服务
        // (不需要等待，立即向前端返回成功)
        const restartServices = async () => {
            if (requiresWssRestart) {
                await safeRunCommand(['systemctl', 'restart', 'wss']);
            }
            if (requiresStunnelRestart) {
                await safeRunCommand(['systemctl', 'restart', 'stunnel4']);
            }
            if (requiresUdpGwRestart) {
                await safeRunCommand(['systemctl', 'restart', 'udpgw']);
            }
            // 面板必须最后重启
            if (requiresPanelRestart) {
                // 延迟 1 秒重启，确保此 API 请求已成功返回
                setTimeout(async () => {
                    await safeRunCommand(['systemctl', 'restart', 'wss_panel']);
                }, 1000);
            }
        };
        restartServices(); // 启动后不等待

        res.json({ success: true, message: `配置已保存！相关服务正在后台重启... (面板可能会在 ${requiresPanelRestart ? '1秒' : '0秒'} 后刷新)` });

    } catch (e) {
        await logAction("CONFIG_SAVE_FAIL", req.session.username, `Failed to save config: ${e.message}`);
        res.status(500).json({ success: false, message: `保存配置失败: ${e.message}` });
    }
});


api.post('/settings/change-password', async (req, res) => {
    const { old_password, new_password } = req.body;
    if (!old_password || !new_password) { return res.status(400).json({ success: false, message: "新旧密码均不能为空。" }); }
    if (new_password.length < 6) { return res.status(400).json({ success: false, message: "新密码长度必须至少为 6 位。" }); }
    try {
        const rootHash = await loadRootHash();
        if (!rootHash) { throw new Error("无法加载 root hash 文件。"); }
        const match = await bcrypt.compare(old_password, rootHash);
        if (!match) {
            await logAction("CHANGE_PASS_FAIL", req.session.username, "Failed to change panel password: Incorrect old password");
            return res.status(403).json({ success: false, message: "当前密码不正确。" });
        }
        const newHash = await bcrypt.hash(new_password, 12);
        await fs.writeFile(ROOT_HASH_FILE, newHash, 'utf8');
        await logAction("CHANGE_PASS_SUCCESS", req.session.username, "Panel admin password changed successfully.");
        res.json({ success: true, message: "管理员密码修改成功。" });
    } catch (e) {
        await logAction("CHANGE_PASS_FAIL", req.session.username, `Failed to change panel password: ${e.message}`);
        res.status(500).json({ success: false, message: `密码修改失败: ${e.message}` });
    }
});

api.post('/ips/ban_global', async (req, res) => {
    const { ip, reason } = req.body;
    if (!ip) return res.status(400).json({ success: false, message: "IP 地址不能为空" });
    try {
        const iptablesResult = await manageIpIptables(ip, 'block');
        if (!iptablesResult.success) throw new Error(iptablesResult.output);
        const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
        await db.run(`INSERT OR REPLACE INTO ip_bans (ip, reason, added_by, timestamp) VALUES (?, ?, ?, ?)`,
            ip, reason || 'Manual Panel Ban', req.session.username, timestamp
        );
        await logAction("IP_BAN_GLOBAL", req.session.username, `Globally banned IP ${ip}. Reason: ${reason}`);
        res.json({ success: true, message: `IP 地址 ${ip} 已全局封禁。` });
    } catch (e) {
        await logAction("IP_BAN_FAIL", req.session.username, `Failed to ban IP ${ip}: ${e.message}`);
        res.status(500).json({ success: false, message: `封禁操作失败: ${e.message}` });
    }
});

api.post('/ips/unban_global', async (req, res) => {
    const { ip } = req.body;
    if (!ip) return res.status(400).json({ success: false, message: "IP 地址不能为空" });
    try {
        const iptablesResult = await manageIpIptables(ip, 'unblock');
        if (!iptablesResult.success && !iptablesResult.output.includes('No chain/target/match')) {
            throw new Error(iptablesResult.output);
        }
        await db.run(`DELETE FROM ip_bans WHERE ip = ?`, ip);
        await logAction("IP_UNBAN_GLOBAL", req.session.username, `Globally unbanned IP ${ip}.`);
        res.json({ success: true, message: `IP 地址 ${ip} 已解除全局封禁。` });
    } catch (e) {
        await logAction("IP_UNBAN_FAIL", req.session.username, `Failed to unban IP ${ip}: ${e.message}`);
        res.status(500).json({ success: false, message: `解除封禁失败: ${e.message}` });
    }
});

api.get('/ips/global_list', async (req, res) => {
    try {
        const bans = await db.all('SELECT * FROM ip_bans ORDER BY timestamp DESC');
        const bansMap = bans.reduce((acc, item) => {
            acc[item.ip] = { reason: item.reason, timestamp: item.timestamp };
            return acc;
        }, {});
        res.json({ success: true, global_bans: bansMap });
    } catch (e) {
        res.status(500).json({ success: false, message: `Failed to fetch ban list: ${e.message}` });
    }
});

// [AXIOM V2.1] 新增: SNI 查找器 API
api.post('/utils/find_sni', async (req, res) => {
    const { hostname } = req.body;
    if (!hostname) {
        return res.status(400).json({ success: false, message: "Hostname 不能为空。" });
    }

    try {
        // 1. 解析 IP, 模拟 Python 的 gethostbyname
        const { address: ip_address } = await dns.promises.lookup(hostname);

        // 2. 建立 TLS 连接以获取证书
        const promise = new Promise((resolve, reject) => {
            const options = {
                port: 443,
                host: ip_address, // 连接到 IP
                servername: hostname, // <-- 这就是 SNI
                timeout: 8000, // 8 秒超时
                rejectUnauthorized: true // 验证证书 (在 Python 脚本中是默认的)
            };

            const socket = tls.connect(options, () => {
                const cert = socket.getPeerCertificate();
                socket.end();
                
                if (!cert || !cert.subjectaltname) {
                    return resolve([]); // 没有找到 SANs
                }
                
                // 3. 解析 subjectaltname (例如 "DNS:a.com, DNS:b.com")
                const altNames = cert.subjectaltname
                    .split(',')
                    .map(s => s.trim())
                    .filter(s => s.startsWith('DNS:'))
                    .map(s => s.substring(4)); // 移除 "DNS:"
                    
                resolve(altNames);
            });

            socket.on('timeout', () => {
                socket.destroy();
                reject(new Error(`连接到 ${hostname} (port 443) 超时。`));
            });

            socket.on('error', (err) => {
                // 捕获 Python 脚本中的 SSLCertVerificationError
                if (err.code === 'CERT_HAS_EXPIRED' || err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
                     reject(new Error(`SSL 证书验证失败: ${err.message}`));
                } else {
                     reject(new Error(`TLS 错误: ${err.message}`));
                }
            });
        });

        const sniHosts = await promise;
        res.json({ success: true, hosts: sniHosts, ip: ip_address });

    } catch (e) {
        let errorMessage = e.message;
        // 捕获 Python 脚本中的 socket.gaierror
        if (e.code === 'ENOTFOUND' || e.message.includes('getaddrinfo')) {
            errorMessage = `无法解析域名 '${hostname}'。`;
        }
        res.status(500).json({ success: false, message: errorMessage });
    }
});


// 将 API 路由挂载到 /api
app.use('/api', loginRequired, api);


// --- [AXIOM V2.0.5] 重构: IPC (WebSocket) 服务器 ---
function startIpcServer(httpServer) {
    console.log(`[AXIOM V2.0.5] 正在启动实时 IPC (WSS) ...`);
    
    wssIpc = new WebSocketServer({
        noServer: true, // 我们将手动处理 'upgrade'
        path: '/ipc'    // 只处理 /ipc 路径的 WS 连接
    });

    httpServer.on('upgrade', (request, socket, head) => {
        // 验证内部 API 密钥
        const secret = request.headers['x-internal-secret'];
        if (secret !== config.internal_api_secret) {
            console.error("[IPC_WSS] 拒绝连接: 内部 API 密钥 (x-internal-secret) 无效。");
            socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
            socket.destroy();
            return;
        }

        // 验证路径
        if (request.url !== '/ipc') {
             console.error(`[IPC_WSS] 拒绝连接: 路径无效 (${request.url})。`);
             socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
             socket.destroy();
             return;
        }

        // 将连接升级到 WebSocket
        wssIpc.handleUpgrade(request, socket, head, (ws) => {
            wssIpc.emit('connection', ws, request);
        });
    });

    wssIpc.on('connection', (ws, req) => {
        console.log('[IPC_WSS] 一个新的数据平面 (Proxy) 已连接。');
        
        ws.on('message', (message) => {
            console.log(`[IPC_WSS] 收到 Proxy 消息: ${message}`);
            // (未来可以实现双向通信, 例如 proxy 主动报告状态)
        });

        ws.on('close', () => {
            console.log('[IPC_WSS] 一个数据平面 (Proxy) 已断开连接。');
        });
        
        ws.on('error', (err) => {
            console.error(`[IPC_WSS] 客户端 WebSocket 错误: ${err.message}`);
        });
    });
    
    wssIpc.on('error', (err) => {
         console.error(`[IPC_WSS] 实时 IPC 服务器错误: ${err.message}`);
    });
    
    console.log(`[AXIOM V2.0.5] 实时 IPC (WSS) 已附加到主 HTTP 服务器 (路径: /ipc)。`);
}


// --- [AXIOM V2.0.5] 重构: Startup ---
async function startApp() {
    try {
        await initDb();
        
        // [AXIOM V2.0.5] 创建共享的 HTTP 服务器
        const server = http.createServer(app);
        
        // [AXIOM V2.0.5] 启动 IPC 服务器并将其附加到 HTTP 服务器
        startIpcServer(server);
        
        // 启动后台同步 (只同步流量)
        setInterval(syncUserStatus, BACKGROUND_SYNC_INTERVAL);
        setTimeout(syncUserStatus, 5000); 
        
        // [AXIOM V2.0.5] 启动共享服务器
        server.listen(config.panel_port, '0.0.0.0', () => {
            console.log(`[AXIOM V2.0.5] WSS Panel (HTTP) 运行在 port ${config.panel_port}`);
            console.log(`[AXIOM V2.0.5] 实时 IPC (WSS) 运行在 port ${config.panel_port} (路径: /ipc)`);
            console.log(`[AXIOM V2.0.5] 后台流量同步已启动 (Interval: ${BACKGROUND_SYNC_INTERVAL}ms)。`);
        });
        
        server.on('error', (err) => {
             if (err.code === 'EADDRINUSE') {
                console.error(`[CRITICAL] 启动失败: 端口 ${config.panel_port} 已被占用。`);
             } else {
                console.error(`[CRITICAL] Panel HTTP 服务器错误: ${err.message}`);
             }
             process.exit(1);
        });

    } catch (e) {
        console.error(`[CRITICAL] Panel App 启动失败: ${e.message}`);
        process.exit(1);
    }
}

startApp();
