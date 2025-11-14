/**
 * WSS Proxy Core (Node.js)
 * V8.2.0 (Axiom Refactor V2.0.5)
 *
 * [AXIOM V2.0.5 CHANGELOG]
 * - [CRITICAL BUGFIX] 修复 IPC 架构。
 * - 移除了 `internal_ipc_port` (54323) 的概念。
 * - `connectToIpcServer` 现在将连接到主 `panel_port` 上的 "/ipc" 路径
 * (例如: ws://127.0.0.1:54321/ipc)，
 * 与 HTTP API 共享同一个端口。
 * - 这修复了 "connect ECONNREFUSED 127.0.0.1:54323" 错误。
 *
 * [AXIOM V2.0.0 CHANGELOG]
 * 1. [架构] 配置外部化:
 * - 不再使用 process.env。
 * - 从 /etc/wss-panel/config.json 加载所有配置。
 * 2. [架构] 实时 IPC 客户端 (推送):
 * - 引入 'ws' 库。
 * - 启动时作为 WSC (客户端) 连接到 wss_panel.js (服务器)。
 * - 自动处理重连。
 * 3. [架构] 实时状态管理:
 * - 监听 "kick", "update_limits", "reload_hosts" 等命令。
 * - "update_limits" 会实时更新内存中的 TokenBucket 速率。
 * - "reload_hosts" 会实时重载 hosts.json。
 * - "kick" 会立即销毁用户套接字。
 *
 * [AXIOM V2.3.0] 架构: 集群模式
 * - 引入 'cluster' 和 'os' 模块。
 * - 主进程 (Master) 负责 fork 工作进程 (Workers)。
 * - 工作进程 (Workers) 负责运行 startServers()。
 * - 主进程监控工作进程崩溃并自动重启，实现高可用性。
 *
 * [AXIOM V2.3.2] 修复: 集群统计聚合
 * - 修复: `cluster` 模式导致 /stats API 只返回一个工作进程的数据。
 * - 更改: 只有主进程 (Master) 运行 `startInternalApiServer`。
 * - 更改: 主进程的 /stats API 现在通过 IPC (GET_STATS) 从所有工作进程收集数据。
 * - 更改: 工作进程通过 `process.on('message')` 响应 GET_STATS 请求。
 * - 更改: `startServers()` (在工作进程中运行) 不再启动 `startInternalApiServer`。
 * - 修复: 主进程监听 `STATS_RESPONSE` 消息 (之前是 STATS_UPDATE)。
 */

const net = require('net');
const tls = require('tls');
const fs = require('fs');
const path = require('path');
const http = require('http'); // 用于内部 API
const { URLSearchParams } = require('url');
// [AXIOM V2.0] 引入 ws (WebSocket 客户端)
const WebSocket = require('ws');
// [AXIOM V2.3.0] 引入 cluster 和 os
const cluster = require('cluster');
const os = require('os');


// --- [AXIOM V2.0] 配置加载 ---
const PANEL_DIR = process.env.PANEL_DIR_ENV || '/etc/wss-panel';
const CONFIG_PATH = path.join(PANEL_DIR, 'config.json');
let config = {};

function loadConfig() {
    try {
        const configData = fs.readFileSync(CONFIG_PATH, 'utf8');
        config = JSON.parse(configData);
        // [AXIOM V2.3.0] 仅在工作进程中记录详细信息，避免主进程日志混乱
        if (cluster.isWorker) {
            console.log(`[AXIOM V2.0] Worker ${cluster.worker.id} 成功从 ${CONFIG_PATH} 加载配置。`);
        }
    } catch (e) {
        console.error(`[CRITICAL] 无法加载 ${CONFIG_PATH}: ${e.message}。服务将退出。`);
        process.exit(1); // 关键服务没有配置无法启动
    }
}
loadConfig(); // 立即加载配置
// --- 结束配置加载 ---


// --- 核心常量 (现在从 config 读取) ---
const LISTEN_ADDR = '0.0.0.0';
const WSS_LOG_FILE = path.join(PANEL_DIR, 'wss.log'); // 从 Panel Dir 派生
const HOSTS_DB_PATH = path.join(PANEL_DIR, 'hosts.json');
const HTTP_PORT = config.wss_http_port;
const TLS_PORT = config.wss_tls_port;
const INTERNAL_FORWARD_PORT = config.internal_forward_port;
const INTERNAL_API_PORT = config.internal_api_port;
const PANEL_API_URL = config.panel_api_url;
const INTERNAL_API_SECRET = config.internal_api_secret;
const DEFAULT_TARGET = { host: '127.0.0.1', port: INTERNAL_FORWARD_PORT };
const TIMEOUT = 86400000; // 24 hours
const BUFFER_SIZE = 65536;
const CERT_FILE = '/etc/stunnel/certs/stunnel.pem';
const KEY_FILE = '/etc/stunnel/certs/stunnel.key';

// HTTP Responses
const FIRST_RESPONSE = Buffer.from('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\nOK\r\n\r\n');
const SWITCH_RESPONSE = Buffer.from('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n');
const FORBIDDEN_RESPONSE = Buffer.from('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n');
const UNAUTHORIZED_RESPONSE = Buffer.from('HTTP/1.1 401 Unauthorized\r\nProxy-Authenticate: Basic realm="WSS Proxy"\r\nContent-Length: 0\r\n\r\n');
const TOO_MANY_REQUESTS_RESPONSE = Buffer.from('HTTP/1.1 429 Too Many Requests\r\nContent-Length: 0\r\n\r\n');
const INTERNAL_ERROR_RESPONSE = Buffer.from('HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n');

let HOST_WHITELIST = new Set();
let logStream; 
// [AXIOM V2.0] 全局熔断阈值
let GLOBAL_FUSE_THRESHOLD_KBPS = 0;
// [AXIOM V2.3.1] 主进程用于聚合所有工作进程的统计数据
let allWorkerStats = new Map();


// --- 令牌桶 (Token Bucket) 限速器 ---
class TokenBucket {
    constructor(capacityKbps, fillRateKbps) {
        this.capacity = capacityKbps * 1024; 
        this.fillRate = fillRateKbps * 1024 / 1000; 
        this.tokens = this.capacity; 
        this.lastFill = Date.now();
    }
    _fillTokens() {
        const now = Date.now();
        const elapsed = now - this.lastFill;
        if (elapsed > 0) {
            const newTokens = elapsed * this.fillRate;
            this.tokens = Math.min(this.capacity, this.tokens + newTokens);
            this.lastFill = now;
        }
    }
    consume(bytesToConsume) {
        if (this.fillRate === 0) return bytesToConsume; 
        this._fillTokens();
        if (bytesToConsume <= this.tokens) {
            this.tokens -= bytesToConsume;
            return bytesToConsume; 
        }
        if (this.tokens > 0) {
             const allowedBytes = this.tokens;
             this.tokens = 0;
             return allowedBytes; 
        }
        return 0; 
    }
    /**
     * [AXIOM V2.0] 实时更新速率
     */
    updateRate(newCapacityKbps, newFillRateKbps) {
        // [AXIOM V2.3.0] 增加 Worker ID 日志
        // [AXIOM V2.3.1] 确保 cluster.worker 存在 (主进程没有)
        const workerId = cluster.isWorker ? `Worker ${cluster.worker.id}` : 'Master(N/A)';
        console.log(`[TokenBucket ${workerId}] Updating rate. Capacity: ${newCapacityKbps} KB/s, FillRate: ${newFillRateKbps} KB/s`);
        // 重新填充旧速率的令牌
        this._fillTokens();
        // 设置新速率
        this.capacity = newCapacityKbps * 1024;
        this.fillRate = newFillRateKbps * 1024 / 1000;
        // 将当前令牌限制在新的容量内
        this.tokens = Math.min(this.capacity, this.tokens);
        this.lastFill = Date.now();
    }
}

// --- 全局状态管理 ---
const userStats = new Map();
const SPEED_CALC_INTERVAL = 2000; 

/**
 * [AXIOM V2.0] 重构: getUserStat 现在存储完整的 TokenBucket 实例
 */
function getUserStat(username) {
    if (!userStats.has(username)) {
        userStats.set(username, {
            sockets: new Set(),
            ip_map: new Map(), // clientIp -> socket
            traffic_delta: { upload: 0, download: 0 }, 
            traffic_live: { upload: 0, download: 0 }, 
            speed_kbps: { upload: 0, download: 0 },
            lastSpeedCalc: { upload: 0, download: 0, time: Date.now() }, 
            // [AXIOM V2.0] 直接存储实例，默认无限制
            bucket_up: new TokenBucket(0, 0),
            bucket_down: new TokenBucket(0, 0),
            // [AXIOM V2.0] 存储从 /auth API 获取的原始限制
            limits: { rate_kbps: 0, max_connections: 0, require_auth_header: 1 }
        });
    }
    return userStats.get(username);
}

/** 实时速度计算器 */
function calculateSpeeds() {
    const now = Date.now();
    for (const [username, stats] of userStats.entries()) {
        const elapsed = now - stats.lastSpeedCalc.time;
        if (elapsed < (SPEED_CALC_INTERVAL / 2)) continue; 
        const elapsedSeconds = elapsed / 1000.0;
        
        const uploadDelta = stats.traffic_live.upload - stats.lastSpeedCalc.upload;
        stats.speed_kbps.upload = (uploadDelta / 1024) / elapsedSeconds;
        stats.lastSpeedCalc.upload = stats.traffic_live.upload;

        const downloadDelta = stats.traffic_live.download - stats.lastSpeedCalc.download;
        stats.speed_kbps.download = (downloadDelta / 1024) / elapsedSeconds;
        stats.lastSpeedCalc.download = stats.traffic_live.download;
        
        stats.lastSpeedCalc.time = now;
        
        // [AXIOM V2.0] 熔断检查
        if (GLOBAL_FUSE_THRESHOLD_KBPS > 0) {
            const totalSpeed = stats.speed_kbps.upload + stats.speed_kbps.download;
            if (totalSpeed >= GLOBAL_FUSE_THRESHOLD_KBPS) {
                // [AXIOM V2.3.0] 增加 Worker ID 日志
                console.warn(`[FUSE Worker ${cluster.worker.id}] 用户 ${username} 已触发全局熔断器! 速率: ${totalSpeed.toFixed(0)} KB/s. 正在踢出...`);
                // 立即踢出
                kickUser(username);
                // (注意: Panel 侧的 syncUserStatus 也会将其标记为 'fused')
            }
        }
        
        // 当没有活跃连接且没有增量流量时，清除用户状态
        if (stats.sockets.size === 0 && stats.traffic_delta.upload === 0 && stats.traffic_delta.download === 0) {
            userStats.delete(username);
        }
    }
}
setInterval(calculateSpeeds, SPEED_CALC_INTERVAL);


// --- [AXIOM V2.0] 实时 IPC 客户端 ---

/**
 * [AXIOM V2.0] 踢出一个用户的所有连接
 */
function kickUser(username) {
    const stats = userStats.get(username);
    if (stats && stats.sockets.size > 0) {
        // [AXIOM V2.3.0] 增加 Worker ID 日志
        console.log(`[IPC_CMD Worker ${cluster.worker.id}] 正在踢出用户 ${username} (${stats.sockets.size} 个连接)...`);
        for (const socket of stats.sockets) {
            socket.destroy(); 
        }
        stats.sockets.clear();
        stats.ip_map.clear();
    }
}

/**
 * [AXIOM V2.0] 实时更新用户的速率限制
 */
function updateUserLimits(username, limits) {
    if (!limits) return;
    const stats = getUserStat(username); // 获取或创建
    
    // [AXIOM V2.3.0] 增加 Worker ID 日志
    console.log(`[IPC_CMD Worker ${cluster.worker.id}] 正在更新用户 ${username} 的限制...`);
    
    // 1. 更新内存中的原始限制
    stats.limits = {
        rate_kbps: limits.rate_kbps || 0,
        max_connections: limits.max_connections || 0,
        require_auth_header: limits.require_auth_header === 0 ? 0 : 1
    };
    
    // 2. 实时更新令牌桶
    const rateUp = stats.limits.rate_kbps;
    stats.bucket_up.updateRate(rateUp * 2, rateUp); // 2x 突发
    
    const rateDown = stats.limits.rate_kbps; // (上/下行共享速率)
    stats.bucket_down.updateRate(rateDown * 2, rateDown); // 2x 突发
}

/**
 * [AXIOM V2.0] 实时更新全局限制
 */
function updateGlobalLimits(limits) {
    if (!limits) return;
    if (limits.fuse_threshold_kbps !== undefined) {
        GLOBAL_FUSE_THRESHOLD_KBPS = parseInt(limits.fuse_threshold_kbps) || 0;
        // [AXIOM V2.3.0] 增加 Worker ID 日志
        console.log(`[IPC_CMD Worker ${cluster.worker.id}] 全局熔断阈值已更新为: ${GLOBAL_FUSE_THRESHOLD_KBPS} KB/s`);
    }
}

/**
 * [AXIOM V2.0] 重置用户的流量计数器
 */
function resetUserTraffic(username) {
    const stats = userStats.get(username);
    if (stats) {
        // [AXIOM V2.3.0] 增加 Worker ID 日志
        console.log(`[IPC_CMD Worker ${cluster.worker.id}] 正在重置用户 ${username} 的流量计数器...`);
        stats.traffic_delta = { upload: 0, download: 0 };
        stats.traffic_live = { upload: 0, download: 0 };
        stats.lastSpeedCalc = { upload: 0, download: 0, time: Date.now() };
    }
}

/**
 * [AXIOM V2.0.5] 重构: 连接到共享端口的 /ipc 路径
 */
function connectToIpcServer() {
    // [AXIOM V2.0.5] 目标 URL 现在是 Panel Port 上的 /ipc 路径
    const ipcUrl = `ws://127.0.0.1:${config.panel_port}/ipc`;
    // [AXIOM V2.3.0] 增加 Worker ID 日志
    console.log(`[IPC_WSC Worker ${cluster.worker.id}] 正在连接到控制平面: ${ipcUrl}`);

    const ws = new WebSocket(ipcUrl, {
        headers: {
            'X-Internal-Secret': config.internal_api_secret
        }
    });

    ws.on('open', () => {
        // [AXIOM V2.3.0] 增加 Worker ID 日志
        console.log(`[IPC_WSC Worker ${cluster.worker.id}] 成功连接到控制平面 (Panel)。实时推送已激活。`);
    });

    ws.on('message', (data) => {
        try {
            const message = JSON.parse(data.toString());
            // console.log(`[IPC_WSC] 收到命令: ${data.toString()}`);
            
            switch (message.action) {
                case 'kick':
                    if (message.username) {
                        kickUser(message.username);
                    }
                    break;
                case 'update_limits':
                    if (message.username && message.limits) {
                        updateUserLimits(message.username, message.limits);
                    }
                    break;
                case 'update_global_limits':
                    if (message.limits) {
                        updateGlobalLimits(message.limits);
                    }
                    break;
                case 'reset_traffic':
                     if (message.username) {
                        resetUserTraffic(message.username);
                    }
                    break;
                case 'delete':
                    if (message.username) {
                        kickUser(message.username); // 踢出
                        if (userStats.has(message.username)) {
                            userStats.delete(message.username); // 从内存中删除
                        }
                    }
                    break;
                case 'reload_hosts':
                    // [AXIOM V2.3.0] 增加 Worker ID 日志
                    console.log(`[IPC_CMD Worker ${cluster.worker.id}] 收到重载 Hosts 命令...`);
                    loadHostWhitelist();
                    break;
            }
        } catch (e) {
            console.error(`[IPC_WSC Worker ${cluster.worker.id}] 解析 IPC 消息失败: ${e.message}`);
        }
    });

    ws.on('close', (code, reason) => {
        console.warn(`[IPC_WSC Worker ${cluster.worker.id}] 与控制平面的连接已断开。代码: ${code}, 原因: ${reason}. 将在 5 秒后重试...`);
        setTimeout(connectToIpcServer, 5000);
    });

    ws.on('error', (err) => {
        console.error(`[IPC_WSC Worker ${cluster.worker.id}] 无法连接到控制平面: ${err.message}`);
        // 'close' 事件会自动触发重连
    });
}


// --- 异步日志设置 ---
function setupLogStream() {
    try {
        logStream = fs.createWriteStream(WSS_LOG_FILE, { flags: 'a' });
        logStream.on('error', (err) => {
            console.error(`[CRITICAL] Error in WSS log stream: ${err.message}`);
        });
    } catch (e) {
        console.error(`[CRITICAL] Failed to create log stream: ${e.message}`);
    }
}

function logConnection(clientIp, clientPort, localPort, username, status) {
    if (!logStream) return;
    const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
    // [AXIOM V2.3.0] 增加 Worker ID 日志
    // [AXIOM V2.3.1] 确保 cluster.worker 存在
    const workerId = cluster.isWorker ? `Worker ${cluster.worker.id}` : 'Master(N/A)';
    const logEntry = `[${timestamp}] [${status}] [${workerId}] USER=${username} CLIENT_IP=${clientIp} LOCAL_PORT=${localPort}\n`;
    logStream.write(logEntry);
}

// --- Host 白名单管理 ---
function loadHostWhitelist() {
    try {
        if (!fs.existsSync(HOSTS_DB_PATH)) {
            console.warn("Warning: Host whitelist file not found. Using empty list (Strict mode).");
            HOST_WHITELIST = new Set();
            return;
        }
        const data = fs.readFileSync(HOSTS_DB_PATH, 'utf8');
        const hosts = JSON.parse(data);
        if (Array.isArray(hosts)) {
            const cleanHosts = new Set();
            hosts.forEach(host => {
                if (typeof host === 'string') {
                    let h = host.trim().toLowerCase();
                    if (h.includes(':')) h = h.split(':')[0]; 
                    if (h) cleanHosts.add(h);
                }
            });
            HOST_WHITELIST = cleanHosts;
            // [AXIOM V2.3.0] 增加 Worker ID 日志
            // [AXIOM V2.3.1] 确保 cluster.worker 存在
            if (cluster.isWorker) {
                console.log(`[Worker ${cluster.worker.id}] Host Whitelist loaded successfully. Count: ${HOST_WHITELIST.size}`);
            }
        } else {
            HOST_WHITELIST = new Set();
            console.error("Error: Host whitelist file format error (not an array). Using empty list (Strict mode).");
        }
    } catch (e) {
        HOST_WHITELIST = new Set();
        console.error(`Error loading Host Whitelist: ${e.message}. Using empty list (Strict mode).`);
    }
}

function checkHost(headers) {
    const hostMatch = headers.match(/Host:\s*([^\s\r\n]+)/i);
    if (!hostMatch) {
        if (HOST_WHITELIST.size > 0) {
            console.log(`Host check failed: Missing Host header. Access denied. Whitelist size: ${HOST_WHITELIST.size}`);
            return false;
        }
        return true; 
    }
    let requestedHost = hostMatch[1].trim().toLowerCase();
    if (requestedHost.includes(':')) requestedHost = requestedHost.split(':')[0];
    if (HOST_WHITELIST.size === 0) return true; 
    if (HOST_WHITELIST.has(requestedHost)) return true;
    
    console.log(`Host check failed for: ${requestedHost}. Access denied.`);
    return false;
}

// --- 认证与并发检查 ---
function parseAuth(headers) {
    const authMatch = headers.match(/Proxy-Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i);
    if (!authMatch) return null;
    try {
        const credentials = Buffer.from(authMatch[1], 'base64').toString('utf8');
        const [username, ...passwordParts] = credentials.split(':');
        const password = passwordParts.join(':');
        if (!username || !password) return null;
        return { username, password };
    } catch (e) {
        return null;
    }
}

async function authenticateUser(username, password) {
    try {
        const response = await fetch(PANEL_API_URL + '/auth', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        if (!response.ok) {
            const errorData = await response.json().catch(() => ({}));
            return { success: false, limits: null, requireAuthHeader: 1, message: errorData.message || `Auth failed with status ${response.status}` };
        }
        const data = await response.json();
        
        // [AXIOM V2.0] 认证成功后，立即更新/缓存内存中的限制
        updateUserLimits(username, data.limits);
        
        return { success: true, limits: data.limits, requireAuthHeader: data.require_auth_header, message: 'Auth successful' };
    } catch (e) {
        console.error(`[AUTH] Failed to fetch Panel /auth API: ${e.message}`);
        return { success: false, limits: null, requireAuthHeader: 1, message: 'Internal API connection error' };
    }
}

/** [目标 5c] 轻量级查询，获取免认证状态 */
async function getLiteAuthStatus(username) {
    try {
        const params = new URLSearchParams({ username });
        const response = await fetch(PANEL_API_URL + '/auth/user-settings?' + params.toString(), {
            method: 'GET',
        });
        if (!response.ok) {
            return { exists: false, requireAuthHeader: 1 };
        }
        const data = await response.json();
        
        // [AXIOM V2.0] 免认证用户也需要获取限制
        if (data.success && data.require_auth_header === 0) {
            // (注意: 这依赖于 wss_panel.js 在 V2.0 中也返回 /auth/user-settings 的 limits)
            // (回退) 如果 V1.7 的 Panel 未返回 limits，我们将稍后在 connectToTarget 中
            // 从内存 (userStats) 中获取，该内存由 IPC 更新。
            if (data.limits) {
                updateUserLimits(username, data.limits);
            }
        }
        
        return { exists: data.success, requireAuthHeader: data.require_auth_header || 1 };
    } catch (e) {
        console.error(`[LITE_AUTH] Failed to fetch Panel /auth/user-settings API: ${e.message}`);
        return { exists: false, requireAuthHeader: 1 };
    }
}

function checkConcurrency(username, maxConnections) {
    if (maxConnections === 0) return true; 
    const stats = getUserStat(username); 
    if (stats.sockets.size < maxConnections) {
        return true;
    }
    return false;
}


// --- Client Handler ---

function handleClient(clientSocket, isTls) {
    let clientIp = clientSocket.remoteAddress;
    let clientPort = clientSocket.remotePort;
    let localPort = clientSocket.localPort;

    let fullRequest = Buffer.alloc(0);
    
    let state = 'handshake';
    let remoteSocket = null;
    let username = null; 
    let limits = null; // [AXIOM V2.0] 注意: 'limits' 仅用于连接时检查
    let requireAuthHeader = 1; // 默认需要认证头

    clientSocket.setTimeout(TIMEOUT);
    // [AXIOM V1.7.1] 启用 TCP Keep-Alive (60秒探测一次)
    clientSocket.setKeepAlive(true, 60000);

    clientSocket.on('error', (err) => {
        if (err.code !== 'ECONNRESET' && err.code !== 'EPIPE' && err.code !== 'ETIMEDOUT') {
            // console.error(`[WSS V8.0] Client error from ${clientIp}: ${err.message}`);
        }
        if (remoteSocket) remoteSocket.destroy();
        clientSocket.destroy();
    });

    clientSocket.on('timeout', () => {
        // console.log(`[WSS V8.0] Connection timeout for ${clientIp}:${clientPort}`);
        if (remoteSocket) remoteSocket.destroy();
        clientSocket.destroy();
    });
    
    clientSocket.on('close', () => {
        if (remoteSocket) remoteSocket.destroy();
        if (username) {
            try {
                const stats = getUserStat(username);
                stats.sockets.delete(clientSocket);
                stats.ip_map.delete(clientIp);
            } catch (e) {}
        }
    });

    // [AXIOM V1.2] 重构 data 处理器，以支持 TCP 流水线 (Pipelining)
    clientSocket.on('data', async (data) => {
        
        // --- [STATE: forwarding] ---
        if (state === 'forwarding') {
            const stats = getUserStat(username);
            // [AXIOM V2.0] 流量从实时更新的令牌桶中消耗
            const allowedBytes = stats.bucket_up.consume(data.length);
            if (allowedBytes === 0) return; 
            const dataToWrite = (allowedBytes < data.length) ? data.subarray(0, allowedBytes) : data;
            stats.traffic_delta.upload += dataToWrite.length;
            stats.traffic_live.upload += dataToWrite.length;
            if (remoteSocket && remoteSocket.writable) {
                remoteSocket.write(dataToWrite);
            }
            return;
        }

        // --- [STATE: handshake] ---
        // 将新数据附加到缓冲区
        fullRequest = Buffer.concat([fullRequest, data]);

        // [AXIOM V1.2] 循环处理缓冲区，因为一个 TCP 包可能包含多个 HTTP 请求
        while (state === 'handshake' && fullRequest.length > 0) {
            
            const headerEndIndex = fullRequest.indexOf('\r\n\r\n');

            if (headerEndIndex === -1) {
                // 缓冲区中没有完整的 HTTP 请求，等待更多数据
                if (fullRequest.length > BUFFER_SIZE * 2) {
                    clientSocket.end(FORBIDDEN_RESPONSE); 
                }
                return; // 退出 on('data') 处理器，等待下一次 data 事件
            }

            // --- 头部解析 ---
            const headersRaw = fullRequest.subarray(0, headerEndIndex);
            // [AXIOM V1.2] 将此请求之后的数据保留在缓冲区中
            let dataAfterHeaders = fullRequest.subarray(headerEndIndex + 4);
            const headers = headersRaw.toString('utf8', 0, headersRaw.length);
            
            // [AXIOM V1.2] 从缓冲区中消耗掉这个已处理的请求
            fullRequest = dataAfterHeaders;
            
            // 1. Host 白名单检查
            if (!checkHost(headers)) {
                logConnection(clientIp, clientPort, localPort, 'N/A', 'REJECTED_HOST');
                clientSocket.end(FORBIDDEN_RESPONSE);
                return; // 终止连接，退出
            }
            
            // 2. 提取认证信息
            const auth = parseAuth(headers);
            
            // 检查 WebSocket/GET-RAY 升级请求
            const isWebsocketRequest = headers.includes('Upgrade: websocket') || 
                                       headers.includes('Connection: Upgrade') || 
                                       headers.includes('GET-RAY');

            if (!isWebsocketRequest) {
                 // 普通 HTTP 请求 (Payload 吞噬)
                 if (auth) {
                    // 如果普通 HTTP 请求带了认证，可能是客户端错误，拒绝
                    logConnection(clientIp, clientPort, localPort, 'N/A', 'REJECTED_AUTH_NOT_WEBSOCKET');
                    clientSocket.end(FORBIDDEN_RESPONSE);
                    return; // 终止连接，退出
                 }
                 // [目标 5c 逻辑] 如果没有认证，发送 200 OK，等待下一个请求 (Payload 吞噬)
                 logConnection(clientIp, clientPort, localPort, 'N/A', 'DUMMY_HTTP_REQUEST');
                 clientSocket.write(FIRST_RESPONSE);
                 
                 // [AXIOM V1.2] 不退出函数，而是继续循环 (continue) 来处理缓冲区中的下一个请求
                 continue; 
            }
            
            // --- 3. WebSocket 请求认证流程 ---
            // (如果代码执行到这里，isWebsocketRequest 必定为 true)
            
            if (auth) {
                // 情况 1: 客户端提供了 Proxy-Authorization 头 (标准流程)
                username = auth.username; 
                const authResult = await authenticateUser(auth.username, auth.password);
                
                if (!authResult.success) {
                    logConnection(clientIp, clientPort, localPort, username, `AUTH_FAILED (${authResult.message})`);
                    clientSocket.end(UNAUTHORIZED_RESPONSE);
                    return; // 终止连接，退出
                }
                
                limits = authResult.limits; 
                requireAuthHeader = authResult.requireAuthHeader;
                
            } else {
                // 情况 2: 客户端未提供 Proxy-Authorization 头 (可能为免认证用户)
                
                // 尝试从 URI 中解析用户名 (格式 /?user=xxx)
                const uriMatch = headers.match(/GET\s+\/\?user=([a-z0-9_]{3,16})/i);
                
                if (!uriMatch) {
                    // 没有认证头，URI 中也没有用户名，拒绝
                    logConnection(clientIp, clientPort, localPort, 'N/A', 'AUTH_MISSING');
                    clientSocket.end(UNAUTHORIZED_RESPONSE);
                    return; // 终止连接，退出
                }
                
                // 提取 URI 中的用户名并进行轻量级免认证状态查询 [目标 5c]
                const tempUsername = uriMatch[1];
                const liteAuth = await getLiteAuthStatus(tempUsername);
                
                if (liteAuth.exists && liteAuth.requireAuthHeader === 0) {
                    // 免认证用户已配置
                    username = tempUsername;
                    
                    // [AXIOM V2.0] 
                    // 我们不再需要在这里获取 limits。
                    // `getLiteAuthStatus` 已经触发了 `updateUserLimits`，
                    // `limits` 已经通过 IPC 或 API 被缓存。
                    // 我们在 `connectToTarget` 中将从 `getUserStat(username).limits` 获取。
                    limits = getUserStat(username).limits; // 从内存中获取
                    requireAuthHeader = 0;
                    logConnection(clientIp, clientPort, localPort, username, 'AUTH_LITE_SUCCESS');
                    
                } else {
                    // 用户不存在或要求认证头，拒绝
                    logConnection(clientIp, clientPort, localPort, tempUsername, 'AUTH_LITE_FAILED');
                    clientSocket.end(UNAUTHORIZED_RESPONSE);
                    return; // 终止连接，退出
                }
            }
            
            // --- 4. 认证/免认证通过后的最终检查和连接 ---
            
            // 5. 并发检查
            if (!checkConcurrency(username, limits.max_connections)) {
                logConnection(clientIp, clientPort, localPort, username, `REJECTED_CONCURRENCY`);
                clientSocket.end(TOO_MANY_REQUESTS_RESPONSE);
                return; // 终止连接，退出
            }
            
            // 6. 认证通过, 准备连接
            clientSocket.write(SWITCH_RESPONSE); 
            
            // [AXIOM V1.2] 检查缓冲区中是否还有数据
            // (这是在 `\r\n\r\n` 之后的数据，即真正的 SSH 流量的开头)
            const initialSshData = fullRequest;
            fullRequest = Buffer.alloc(0); // 清空缓冲区，因为我们即将进入 forwarding 状态

            const payloadSample = initialSshData.length > 256 ? initialSshData.subarray(0, 256).toString('utf8') : initialSshData.toString('utf8');
            const trimmedSample = payloadSample.trimLeft();
            
            const isHttpPayload = trimmedSample.startsWith('CONNECT ') || 
                                  trimmedSample.startsWith('GET ') || 
                                  trimmedSample.startsWith('POST ');

            if (isHttpPayload) {
                // 这是一个常见的客户端错误，它在 Upgrade 之后又发送了一个 HTTP 请求
                // 我们需要找到这个错误请求的结尾
                const httpPayloadEndIndex = initialSshData.indexOf('\r\n\r\n');
                if (httpPayloadEndIndex !== -1) {
                    const sshData = initialSshData.subarray(httpPayloadEndIndex + 4);
                    connectToTarget(sshData); // 只转发 SSH 数据
                } else {
                    logConnection(clientIp, clientPort, localPort, username, `REJECTED_SPLIT_PAYLOAD`);
                    clientSocket.end(FORBIDDEN_RESPONSE);
                }
            } else {
                // 正常情况：initialSshData 是 SSH 流量的开头
                connectToTarget(initialSshData); 
            }
            
            // [AXIOM V1.2] 退出 while 循环，因为状态已改变
            return;

        } // end while
    }); // end on('data')

    /**
     * 连接到目标 (SSHD)
     */
    async function connectToTarget(initialData) {
        if (remoteSocket) return; 
        try {
            remoteSocket = net.connect(DEFAULT_TARGET.port, DEFAULT_TARGET.host, () => {
                logConnection(clientIp, clientPort, localPort, username, 'CONN_START'); 
                const stats = getUserStat(username);
                
                // [目标 3] 记录 IP
                stats.ip_map.set(clientIp, clientSocket);

                stats.sockets.add(clientSocket);
                
                // [AXIOM V2.0] 移除: 令牌桶的创建已移至 updateUserLimits
                // const rateUp = limits.rate_kbps || 0;
                // stats.bucket_up = new TokenBucket(rateUp * 2, rateUp);
                // const rateDown = limits.rate_kbps || 0; 
                // stats.bucket_down = new TokenBucket(rateDown * 2, rateDown);

                // [AXIOM V1.2] 关键：在转发数据之前设置状态
                state = 'forwarding';
                
                if (initialData.length > 0) {
                    // [AXIOM V1.2] 现在我们可以安全地转发之前缓冲的数据
                    clientSocket.emit('data', initialData);
                }
                
                remoteSocket.on('data', (data) => {
                    // [AXIOM V2.0] 流量从实时更新的令牌桶中消耗
                    const allowedBytes = stats.bucket_down.consume(data.length);
                    if (allowedBytes === 0) return; 
                    const dataToWrite = (allowedBytes < data.length) ? data.subarray(0, allowedBytes) : data;
                    stats.traffic_delta.download += dataToWrite.length;
                    stats.traffic_live.download += dataToWrite.length;
                    if (clientSocket.writable) {
                        clientSocket.write(dataToWrite);
                    }
                });

                // [AXIOM V1.7.1] 为到 SSHD 的内部连接也启用 Keep-Alive
                remoteSocket.setKeepAlive(true, 60000);
            });

            remoteSocket.on('error', (err) => {
                // [AXIOM V1.2] 增加日志
                if (err.code === 'ECONNREFUSED') {
                    console.error(`[WSS] CRITICAL: Connection refused by target ${DEFAULT_TARGET.host}:${DEFAULT_TARGET.port}. (Is SSHD running on port ${INTERNAL_FORWARD_PORT}?)`);
                    // 发送 502 Bad Gateway
                    clientSocket.end(INTERNAL_ERROR_RESPONSE); 
                }
                clientSocket.destroy();
            });

            remoteSocket.on('close', () => {
                clientSocket.end();
            });
        } catch (e) {
            console.error(`[WSS] Failed to connect to target: ${e.message}`);
            clientSocket.destroy();
        }
    }
}


// --- Internal API Server ---
// [AXIOM V2.3.2] 修复: 完整的 `startInternalApiServer` 逻辑 (仅在主进程中运行)
function startInternalApiServer() {
    
    const internalApiSecretMiddleware = (req, res, next) => {
        if (req.headers['x-internal-secret'] === INTERNAL_API_SECRET) {
            next();
        } else {
            console.warn(`[WSS API Master] Denied internal API request (Bad Secret).`);
            res.writeHead(403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, message: 'Forbidden: Invalid API Secret' }));
        }
    };
    
    const server = http.createServer((req, res) => {
        if (req.socket.remoteAddress !== '127.0.0.1' && req.socket.remoteAddress !== '::1' && req.socket.remoteAddress !== '::ffff:127.0.0.1') {
             console.warn(`[WSS API Master] Denied external access attempt to Internal API from ${req.socket.remoteAddress}`);
             res.writeHead(403, { 'Content-Type': 'application/json' });
             res.end(JSON.stringify({ success: false, message: 'Forbidden' }));
             return;
        }
        let body = '';
        req.on('data', chunk => { body += chunk.toString(); });
        req.on('end', async () => {
            try {
                // GET /stats
                if (req.method === 'GET' && req.url === '/stats') {
                    // [AXIOM V2.3.2] 这是主进程的聚合逻辑
                    internalApiSecretMiddleware(req, res, () => {
                        
                        // 1. 清除上一次的统计数据
                        allWorkerStats.clear();
                        
                        // 2. 向所有工作进程广播 'GET_STATS'
                        for (const id in cluster.workers) {
                            cluster.workers[id].send({ type: 'GET_STATS' });
                        }
                        
                        // 3. 等待 250 毫秒以收集所有回复
                        setTimeout(() => {
                            const aggregatedStats = {};
                            const aggregatedLiveIps = {};

                            for (const [workerId, workerData] of allWorkerStats.entries()) {
                                // 聚合用户统计 (traffic, speed, conns)
                                for (const username in workerData.stats) {
                                    if (!aggregatedStats[username]) {
                                        // 如果是第一个，直接复制
                                        aggregatedStats[username] = { ...workerData.stats[username] };
                                    } else {
                                        // 如果已存在，累加
                                        const existing = aggregatedStats[username];
                                        const current = workerData.stats[username];
                                        existing.traffic_delta += current.traffic_delta;
                                        existing.connections += current.connections;
                                        existing.speed_kbps.upload += current.speed_kbps.upload;
                                        existing.speed_kbps.download += current.speed_kbps.download;
                                    }
                                }
                                
                                // 聚合 live_ips (简单合并)
                                Object.assign(aggregatedLiveIps, workerData.live_ips);
                            }
                            
                            const finalResponse = { ...aggregatedStats, live_ips: aggregatedLiveIps };
                            
                            res.writeHead(200, { 'Content-Type': 'application/json' });
                            res.end(JSON.stringify(finalResponse));
                            
                        }, 250); // 250ms 超时等待工作进程响应
                    });
                } else {
                    res.writeHead(404, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, message: 'Not Found' }));
                }
            } catch (e) {
                console.error(`[WSS API Master] Internal API Error: ${e.message}`);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, message: 'Internal Server Error' }));
            }
        });
    });

    server.listen(INTERNAL_API_PORT, '127.0.0.1', () => {
        // [AXIOM V2.3.1] 确认这是主进程
        const workerId = cluster.isWorker ? `Worker ${cluster.worker.id}` : 'Master';
        console.log(`[WSS ${workerId}] Internal API server (/stats) listening on 127.0.0.1:${INTERNAL_API_PORT}`);
    }).on('error', (err) => {
        const workerId = cluster.isWorker ? `Worker ${cluster.worker.id}` : 'Master';
        console.error(`[CRITICAL ${workerId}] WSS Internal API failed to start on port ${INTERNAL_API_PORT}: ${err.message}`);
        process.exit(1);
    });
}


// --- Server Initialization ---
function startServers() {
    loadHostWhitelist();
    setupLogStream();
    // [AXIOM V2.3.1] 移除: Internal API Server 由主进程启动
    // startInternalApiServer();
    
    // [AXIOM V2.0] 启动 IPC 客户端
    connectToIpcServer();

    const httpServer = net.createServer((socket) => {
        handleClient(socket, false);
    });
    httpServer.listen(HTTP_PORT, LISTEN_ADDR, () => {
        // [AXIOM V2.3.0] 增加 Worker ID 日志
        console.log(`[WSS Worker ${cluster.worker.id}] Listening on ${LISTEN_ADDR}:${HTTP_PORT} (HTTP)`);
    }).on('error', (err) => {
        console.error(`[CRITICAL Worker ${cluster.worker.id}] HTTP Server failed to start on port ${HTTP_PORT}: ${err.message}`);
        process.exit(1); // 工作进程退出，主进程将重启它
    });

    try {
        if (!fs.existsSync(CERT_FILE) || !fs.existsSync(KEY_FILE)) {
            console.warn(`[WSS Worker ${cluster.worker.id}] WARNING: TLS certificate not found at ${CERT_FILE}. TLS server disabled.`);
            return;
        }
        const tlsOptions = {
            key: fs.readFileSync(KEY_FILE),
            cert: fs.readFileSync(CERT_FILE),
            rejectUnauthorized: false
        };
        const tlsServer = tls.createServer(tlsOptions, (socket) => {
            handleClient(socket, true);
        });
        tlsServer.listen(TLS_PORT, LISTEN_ADDR, () => {
            // [AXIOM V2.3.0] 增加 Worker ID 日志
            console.log(`[WSS Worker ${cluster.worker.id}] Listening on ${LISTEN_ADDR}:${TLS_PORT} (TLS)`);
        }).on('error', (err) => {
            console.error(`[CRITICAL Worker ${cluster.worker.id}] TLS Server failed to start on port ${TLS_PORT}: ${err.message}`);
            process.exit(1); // 工作进程退出，主进程将重启它
        });
    } catch (e) {
        console.error(`[WSS Worker ${cluster.worker.id}] WARNING: TLS server setup failed: ${e.message}. Disabled.`);
    }

    // [AXIOM V2.0] 移除 fs.watch
    // fs.watch(HOSTS_DB_PATH, (eventType, filename) => {
    //     if (eventType === 'change' || eventType === 'rename') {
    //         console.log(`[WSS] Host list changed, reloading...`);
    //         loadHostWhitelist();
    //     }
    // });
}

process.on('SIGINT', () => {
    // [AXIOM V2.3.0] Add worker check
    const workerId = cluster.isWorker ? `Worker ${cluster.worker.id}` : 'Master';
    console.log(`\n[${workerId}] WSS Proxy Stopped.`);
    if (logStream) logStream.end();
    process.exit(0);
});


// --- [AXIOM V2.3.2] 修复: 完整的集群启动逻辑 ---

if (cluster.isPrimary) {
    const numCPUs = os.cpus().length;
    console.log(`[AXIOM Cluster Master] Master process ${process.pid} is running.`);
    console.log(`[AXIOM Cluster Master] Forking ${numCPUs} worker processes...`);

    // Fork workers.
    for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }
    
    // [AXIOM V2.3.1] 只有主进程启动 Internal API Server
    startInternalApiServer();
    
    // [AXIOM V2.3.2] 修复: 监听来自工作进程的 `STATS_RESPONSE` 消息
    cluster.on('message', (worker, message) => {
        if (message && message.type === 'STATS_RESPONSE' && message.data) {
            // console.log(`[AXIOM Cluster Master] Received stats from worker ${worker.id}`);
            allWorkerStats.set(worker.id, message.data);
        }
    });

    cluster.on('exit', (worker, code, signal) => {
        console.error(`[AXIOM Cluster Master] Worker ${worker.process.pid} (ID: ${worker.id}) died with code ${code}, signal ${signal}.`);
        // [AXIOM V2.3.1] 清理已退出进程的统计数据
        allWorkerStats.delete(worker.id);
        console.log('[AXIOM Cluster Master] Forking a new replacement worker...');
        cluster.fork();
    });

} else {
    // This is a worker process
    console.log(`[AXIOM Cluster Worker] Worker ${process.pid} (ID: ${cluster.worker.id}) starting...`);
    
    // 工作进程将启动所有服务器 (HTTP, TLS)
    startServers();
    
    // [AXIOM V2.3.1] 工作进程现在需要监听 'GET_STATS' 消息
    process.on('message', (msg) => {
        if (msg && msg.type === 'GET_STATS') {
            // console.log(`[AXIOM Cluster Worker ${cluster.worker.id}] Received GET_STATS request from master.`);
            
            // --- 这是从旧的 /stats API 复制并移到这里的逻辑 ---
            const statsReport = {};
            const liveIps = {}; // [目标 3] IP -> Username 映射
            
            for (const [username, stats] of userStats.entries()) {
                if (stats.sockets.size > 0 || stats.traffic_delta.upload > 0 || stats.traffic_delta.download > 0) {
                    
                    statsReport[username] = {
                        traffic_delta: stats.traffic_delta.upload + stats.traffic_delta.download,
                        speed_kbps: stats.speed_kbps,
                        connections: stats.sockets.size
                    };
                    
                    // 关键: 重置 delta 计数器
                    stats.traffic_delta.upload = 0;
                    stats.traffic_delta.download = 0;
                    
                    for (const ip of stats.ip_map.keys()) {
                        liveIps[ip] = username;
                    }
                }
            }
            // --- 逻辑结束 ---
            
            // 将本地统计数据发送回主进程
            process.send({ 
                type: 'STATS_RESPONSE', 
                data: { stats: statsReport, live_ips: liveIps } 
            });
        }
    });
    
    // [AXIOM V2.3.0] 为工作进程添加未捕获的异常处理器
    process.on('uncaughtException', (err, origin) => {
        console.error(`[AXIOM Cluster Worker ${cluster.worker.id}] Uncaught Exception: ${err.message}`, `Origin: ${origin}`, err.stack);
        // 让主进程处理崩溃和重启
        // 强制退出以确保清理状态
        process.exit(1); 
    });
}
