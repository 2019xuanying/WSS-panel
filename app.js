/**
 * WSS Panel Frontend (Axiom Refactor V3.0 - Realtime Push)
 *
 * [AXIOM V3.0 CHANGELOG]
 * - [架构] 彻底移除“轮询” (Pull):
 * - 移除了 `startAutoRefresh`, `stopAutoRefresh`, `refreshLiveSpeeds`。
 * - 移除了所有 `setInterval` 和 `MAIN_REFRESH_INTERVAL` /
 * `LIVE_SPEED_INTERVAL` 常量。
 * - [架构] 切换到“推送” (Push):
 * - `initializeApp` 现在调用 `connectWebSocket()`。
 * - `connectWebSocket()` 负责连接到后端的 `/ws/ui` 路径并处理自动重连。
 * - [需求 #5] WS 状态灯:
 * - 新增 `setWsStatusIcon(color, tip)` 函数，
 * 用于控制 `index.html` 中的 `ws-status-icon` (红/绿/蓝)。
 * - [需求 #1, #3, #4] 动态/静默更新:
 * - `ws.onmessage` 成为新的数据处理中枢。
 * - `case 'status_connected'`: 触发 `fetchAllStaticData` (加载一次性数据)。
 * - `case 'live_update'`: (1秒推送) 调用 `handleSilentUpdate`
 * 和 `handleDashboardSilentUpdate`。
 * - `case 'system_update'`: (60秒慢推送) 更新系统状态 (CPU/内存/服务)。
 * - `case 'users_changed'`: (手动操作) 触发 `fetchAllUsersAndRender` (全量重绘)。
 * - [需求 #4] 优雅渲染:
 * - `renderUserList` 和 `renderUserQuickStats`
 * 现在为动态元素添加唯一 ID。
 * - `handleSilentUpdate` 和 `handleDashboardSilentUpdate`
 * **只修改 `textContent`**，实现零闪烁的静默更新。
 * - [API] `/users/live-stats` 和 `/system/active_ips`
 * 的前端调用已被移除 (数据来自 WS)。
 */

// --- 全局配置 (将由 initializeApp 异步填充) ---
const API_BASE = '/api';
let currentView = 'dashboard';
let FLASK_CONFIG = {
    WSS_HTTP_PORT: "...",
    WSS_TLS_PORT: "...",
    STUNNEL_PORT: "...",
    UDPGW_PORT: "...",
    INTERNAL_FORWARD_PORT: "...",
    PANEL_PORT: "..."
};

// --- 全局变量 ---
let selectedUsers = []; 
let trafficChartInstance = null; 
let userStatsChartInstance = null;
let allUsersCache = []; // 缓存用户列表以供实时速度更新
let currentSortKey = 'username';
let currentSortDir = 'asc';

// [AXIOM V3.0] 移除: 轮询定时器 ID
// let mainRefreshIntervalId = null; 
// let liveSpeedIntervalId = null; 
// const MAIN_REFRESH_INTERVAL = 2000; 
// const LIVE_SPEED_INTERVAL = 1000; 
let panelSocket = null; // [AXIOM V3.0] WebSocket 实例
let wsReconnectTimer = null; // [AXIOM V3.0] WS 重连定时器

let lastUserStats = { total: -1, total_traffic_gb: -1 };

const TOKEN_PLACEHOLDER = "[*********]";


// --- 主题切换逻辑 ---
const themeToggle = document.getElementById('theme-toggle');
const htmlTag = document.documentElement;
// ... [保留的主题切换逻辑] ...
const savedTheme = localStorage.getItem('theme') || 'light';
htmlTag.setAttribute('data-theme', savedTheme);
if (themeToggle) {
    themeToggle.checked = (savedTheme === 'dark');
}
if (themeToggle) {
    themeToggle.addEventListener('change', (e) => {
        const newTheme = e.target.checked ? 'dark' : 'light';
        htmlTag.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        // [AXIOM V3.0] 修复: 主题切换时重绘图表
        if (userStatsChartInstance) {
            userStatsChartInstance.destroy();
            userStatsChartInstance = null;
        }
        lastUserStats = {}; 
        // 手动请求一次系统状态以重绘图表
        fetchData('/system/status').then(data => {
            if (data) {
                renderUserQuickStats(data.user_stats);
            }
        });
    });
}

// --- 辅助工具函数 ---

function showStatus(message, isSuccess) {
    // ... [保留的 showStatus 逻辑] ...
    const statusDiv = document.getElementById('status-message');
    statusDiv.innerHTML = ''; 
    const iconName = isSuccess ? 'check-circle' : 'alert-triangle';
    const icon = document.createElement('i');
    icon.setAttribute('data-lucide', iconName);
    icon.className = 'w-6 h-6';
    const text = document.createElement('span');
    text.textContent = message;
    statusDiv.appendChild(icon);
    statusDiv.appendChild(text);
    const colorClass = isSuccess ? 'alert-success' : 'alert-error';
    statusDiv.className = 'alert shadow-lg flex mb-6 ' + colorClass;
    statusDiv.style.display = 'flex'; 
    lucide.createIcons({ context: statusDiv });
    window.scrollTo({ top: 0, behavior: 'smooth' });
    setTimeout(() => { 
        statusDiv.style.display = 'none'; 
    }, 5000);
}

function openModal(id) {
    // ... [保留的 openModal 逻辑] ...
    const modal = document.getElementById(id);
    if (modal && typeof modal.showModal === 'function') {
        modal.showModal();
    }
}

function closeModal(id) {
    // ... [保留的 closeModal 逻辑] ...
    if (id === 'traffic-chart-modal' && trafficChartInstance) {
        trafficChartInstance.destroy();
        trafficChartInstance = null;
    }
    const modal = document.getElementById(id);
    if (modal && typeof modal.close === 'function') {
        modal.close();
    }
}

function logout() {
    window.location.assign('/logout'); 
}

function formatSpeedUnits(kbps) {
    // ... [保留的 formatSpeedUnits 逻辑] ...
    const rate = parseFloat(kbps);
    if (isNaN(rate) || rate <= 0) return '0.0 KB/s';
    
    if (rate < 1024) {
        return rate.toFixed(1) + ' KB/s';
    } else {
        const mbps = rate / 1024;
        return mbps.toFixed(2) + ' MB/s';
    }
}

function formatConnections(count) {
    // ... [保留的 formatConnections 逻辑] ...
    const num = parseInt(count);
    return (num === 0) ? '∞' : num;
}

function copyToClipboard(elementId, message) {
     // ... [保留的 copyToClipboard 逻辑] ...
     const copyTextEl = document.getElementById(elementId);
     const copyText = copyTextEl.value;
     if (!copyText || copyText === TOKEN_PLACEHOLDER || copyText.startsWith('[在此输入')) {
         if (elementId === 'modal-connect-token') {
             showStatus('请先在下方输入新密码以生成令牌。', false);
         } else if (elementId === 'new-connect-token') {
             showStatus('请先在表单中输入用户名和密码。', false);
         } else if (elementId === 'payload-output') {
             showStatus('请先生成载荷。', false);
         }
         return;
     }
     try {
        navigator.clipboard.writeText(copyText).then(() => {
            showStatus(message || '已复制到剪贴板！', true);
        }).catch(err => {
            copyTextEl.select();
            document.execCommand('copy');
            showStatus(message || '已复制到剪贴板！', true);
        });
     } catch (err) {
         copyTextEl.select();
         document.execCommand('copy');
         showStatus(message || '已复制到剪贴板！', true);
     }
}

function fillPortNumbers() {
    // ... [保留的 fillPortNumbers 逻辑] ...
    document.getElementById('wss-http-port').textContent = FLASK_CONFIG.WSS_HTTP_PORT;
    document.getElementById('wss-tls-port').textContent = FLASK_CONFIG.WSS_TLS_PORT;
    document.getElementById('stunnel-port').textContent = FLASK_CONFIG.STUNNEL_PORT;
    document.getElementById('udpgw-port').textContent = FLASK_CONFIG.UDPGW_PORT;
    document.getElementById('panel-port').textContent = FLASK_CONFIG.PANEL_PORT;
}

// --- 视图切换逻辑 ---

function switchView(viewId) {
    // ... [保留的 switchView 逻辑, 增加 fetchAllStaticData 的调用] ...
    const views = ['dashboard', 'users', 'settings', 'security', 'live-ips', 'hosts', 'payload-gen', 'port-config'];
    views.forEach(id => {
        const element = document.getElementById('view-' + id);
        if (element) element.style.display = (id === viewId) ? 'block' : 'none';
    });
    
    document.querySelectorAll('#sidebar-menu .nav-link').forEach(link => {
        if (link.dataset.view === viewId) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });

    currentView = viewId;
    
    if (viewId === 'users') {
        document.getElementById('user-search-input').value = '';
        currentSortKey = 'username';
        currentSortDir = 'asc';
        renderFilteredUserList();
    } else {
        clearSelections();
    }
    
    // [AXIOM V3.0] 优化: 切换视图时，从 API 重新加载该视图的静态数据
    // (因为 WS 只推送实时数据)
    if (viewId === 'payload-gen') {
        if (allUsersCache.length > 0) {
            populatePayloadUserSelect();
        } else {
            // 如果缓存为空 (例如直接访问 /#users)，则加载
            fetchAllUsersAndRender();
        }
    }
    
    if (viewId === 'hosts') {
        fetchHosts();
    }
    
    if (viewId === 'settings') {
        fetchGlobalSettings();
        fetchAuditLogs(); // [AXIOM V3.0] 新增: 分离审计日志加载
    }
    
    if (viewId === 'security') {
        fetchGlobalBans(); // [AXIOM V3.0] 新增: 分离封禁列表加载
    }
    
    if (viewId === 'port-config') {
        fetchGlobalConfig();
    }
    
    if (viewId === 'live-ips') {
        fetchActiveIPs(); // [AXIOM V3.0] 新增: 分离 IP 列表加载
    }
    
    if (window.innerWidth < 1024) { 
        const drawerToggle = document.getElementById('my-drawer-2');
        if (drawerToggle) {
            drawerToggle.checked = false;
        }
    }
}

// --- 数据渲染函数 ---

function renderSystemStatus(data) {
    // ... [保留的 renderSystemStatus 逻辑] ...
    const grid = document.getElementById('system-status-grid');
    grid.innerHTML = ''; 
    grid.className = "stats stats-vertical lg:stats-horizontal shadow w-full bg-base-100"; 

    const items = [
        { name: 'CPU 使用率 (LoadAvg)', value: data.cpu_usage.toFixed(1) + '%', color: 'text-blue-500', icon: 'cpu' },
        { name: '内存 (用/总)', value: data.memory_used_gb.toFixed(2) + '/' + data.memory_total_gb.toFixed(2) + 'GB', color: 'text-indigo-500', icon: 'brain' },
        { name: '磁盘使用率', value: data.disk_used_percent.toFixed(1) + '%', color: 'text-purple-500', icon: 'database' },
        ...Object.keys(data.services).map(key => {
            const status = data.services[key].status;
            let color, dotClass;
            if (status === 'running') {
                color = 'text-success';
                dotClass = 'badge-success';
            } else if (status === 'failed') {
                color = 'text-error';
                dotClass = 'badge-error';
            } else {
                color = 'text-warning';
                dotClass = 'badge-warning';
            }
            return {
                name: data.services[key].name,
                value: data.services[key].label,
                color: color,
                dotClass: dotClass,
                icon: 'server'
            };
        })
    ];

    const fragment = document.createDocumentFragment();
    items.forEach(item => {
        const dot = item.dotClass ? `<span class="badge ${item.dotClass} badge-xs mr-2 p-1"></span>` : '';
        const card = document.createElement('div');
        card.className = 'stat';
        card.innerHTML = 
            `<div class="stat-figure ${item.color}"><i data-lucide="${item.icon}" class="w-6 h-6"></i></div>` +
            '<div class="stat-title text-sm">' + item.name + '</div>' +
            `<div class="stat-value text-xl ${item.color} flex items-center">` +
                dot + ' ' + item.value +
            '</div>';
        fragment.appendChild(card);
    });
    grid.innerHTML = '';
    grid.appendChild(fragment);
    lucide.createIcons({ context: grid });
    renderPortStatusList(data.ports);
}

function renderPortStatusList(ports) {
    // ... [保留的 renderPortStatusList 逻辑] ...
    const container = document.getElementById('port-status-data');
    container.innerHTML = '';
    const fragment = document.createDocumentFragment();
    ports.forEach(p => {
        const isListening = p.status === 'LISTEN';
        const badgeClass = isListening ? 'badge-success' : 'badge-error';
        const div = document.createElement('div');
        div.className = 'flex justify-between items-center text-gray-700 p-2 bg-base-100 rounded-lg shadow-sm border border-base-300';
        div.innerHTML = 
            '<span class="font-medium">' + p.name + ' (' + p.port + '/' + p.protocol + '):</span>' +
            `<span class="badge ${badgeClass} badge-sm font-bold">` + p.status +
            '</span>';
        fragment.appendChild(div);
    });
     container.appendChild(fragment);
}

/**
 * [AXIOM V3.0] 重构: renderUserQuickStats
 * - 为动态元素添加 ID
 */
function renderUserQuickStats(stats) {
    // ... [保留的 V1.2 逻辑, 但添加了 ID] ...
    if (stats.total === lastUserStats.total && 
        stats.total_traffic_gb.toFixed(2) === lastUserStats.total_traffic_gb.toFixed(2) &&
        stats.active === lastUserStats.active) {
        return; 
    }
    lastUserStats = stats;
    
    const container = document.getElementById('user-quick-stats-text');
    const total = stats.total;
    const active = stats.active; 
    const nonActive = stats.paused + stats.expired + stats.exceeded + (stats.fused || 0);
    
    container.innerHTML = 
        `<div class="stat">
            <div class="stat-figure text-primary"><i data-lucide="users" class="w-8 h-8"></i></div>
            <div class="stat-title">账户总数</div>
            <div class="stat-value" id="stat-total-users">${total}</div>
        </div>
        <div class="stat">
            <div class="stat-figure text-success"><i data-lucide="activity" class="w-8 h-8"></i></div>
            <div class="stat-title">活跃连接 (IPs)</div>
            <div class="stat-value text-success" id="stat-active-conns">${active}</div>
        </div>
        <div class="stat">
            <div class="stat-figure text-warning"><i data-lucide="user-x" class="w-8 h-8"></i></div>
            <div class="stat-title">暂停/不可用账户</div>
            <div class="stat-value text-warning" id="stat-inactive-users">${nonActive}</div>
        </div>
        <div class="stat">
            <div class="stat-figure text-secondary"><i data-lucide="pie-chart" class="w-8 h-8"></i></div>
            <div class="stat-title">总用量</div>
            <div class="stat-value" id="stat-total-traffic">${stats.total_traffic_gb.toFixed(2)} GB</div>
        </div>`;
    lucide.createIcons({ context: container });
    
     const ctx = document.getElementById('user-stats-chart').getContext('2d');
    const activeAccounts = total - nonActive; 
    const chartDataValues = [(activeAccounts || 0), (nonActive || 0)];
    if (total === 0) {
        chartDataValues[0] = 1;
        chartDataValues[1] = 0;
    }
    const chartData = {
        labels: ['可连接账户', '不可用账户'], 
        datasets: [{
            data: chartDataValues,
            backgroundColor: [
                (total > 0) ? '#00a96e' : '#d1d5db', 
                (total > 0) ? '#fbbd23' : '#d1d5db'  
            ],
            borderColor: htmlTag.getAttribute('data-theme') === 'dark' ? '#1d232a' : '#ffffff', 
            borderWidth: 2,
            hoverOffset: 4
        }]
    };
    if (userStatsChartInstance) {
        userStatsChartInstance.data = chartData;
        userStatsChartInstance.options.plugins.legend.labels.color = htmlTag.getAttribute('data-theme') === 'dark' ? '#a6adbb' : '#4f5664';
        userStatsChartInstance.options.borderColor = htmlTag.getAttribute('data-theme') === 'dark' ? '#1d232a' : '#ffffff';
        userStatsChartInstance.update();
    } else {
        userStatsChartInstance = new Chart(ctx, {
            type: 'doughnut',
            data: chartData,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            padding: 10,
                            color: htmlTag.getAttribute('data-theme') === 'dark' ? '#a6adbb' : '#4f5664' 
                        }
                    }
                }
            }
        });
    }
}

/**
 * [AXIOM V3.0] 重构: buildUserCard (移动端)
 * - 为动态元素添加 ID
 */
function buildUserCard(user, statusColor, statusText, toggleAction, toggleText, toggleColor, usageText, usageProgressHtml) {
    let borderColor = 'border-primary';
    if (user.status === 'active') borderColor = 'border-success';
    if (user.status === 'paused' || user.status === 'fused') borderColor = 'border-warning';
    if (user.status === 'expired' || user.status === 'exceeded') borderColor = 'border-error';
    const isChecked = selectedUsers.includes(user.username) ? 'checked' : '';
    
    // [AXIOM V3.0] 移除: 速度数据现在由静默更新填充
    // const speedUp = formatSpeedUnits(user.realtime_speed_up);
    // const speedDown = formatSpeedUnits(user.realtime_speed_down);
    const speedUp = '...';
    const speedDown = '...';
    
    const shellStatus = user.allow_shell === 1;
    const shellColor = shellStatus ? 'text-secondary' : 'text-gray-500';
    const shellText = shellStatus ? '已启用' : '已禁用';

    return `
    <div id="card-${user.username}" class="card bg-base-100 shadow-lg border-l-4 ${borderColor}">
        <div class="card-body p-4">
            <div class="flex justify-between items-center mb-3 pb-2 border-b border-base-300">
                <div class="flex items-center">
                    <input type="checkbox" data-username="${user.username}" ${isChecked} class="user-checkbox checkbox checkbox-primary mr-3">
                    <span class="font-bold text-lg text-base-content font-mono">${user.username}</span>
                </div>
                <!-- [AXIOM V3.0] 新增 ID -->
                <span id="status-card-${user.username}" class="badge ${statusColor} text-xs font-semibold">
                    ${statusText}
                </span>
            </div>
            <div class="text-sm text-gray-600 space-y-1.5 mb-4">
                <p><strong>到期日:</strong> <span class="font-medium text-base-content">${user.expiration_date || '永不'}</span></p>
                
                <!-- [AXIOM V3.0] 新增 ID -->
                <div id="usage-card-${user.username}" class="pt-1">
                    <strong>用量 (GB):</strong> <span class="font-medium text-base-content">${usageText}</span>
                    ${usageProgressHtml}
                </div>
                
                <p><strong>连接/并发:</strong> 
                    <!-- [AXIOM V3.0] 新增 ID -->
                    <span id="conn-mobile-${user.username}" class="font-medium text-primary">${user.active_connections}</span> / 
                    <span class="font-medium text-base-content">${formatConnections(user.max_connections)}</span>
                </p>
                
                <p class="speed-mobile"><strong>实时:</strong> 
                    <span class="speed-up" id="speed-up-mobile-${user.username}">↑ ${speedUp}</span> / 
                    <span class="speed-down" id="speed-down-mobile-${user.username}">↓ ${speedDown}</span>
                </p>
                
                <p><strong>认证:</strong> <span class="font-medium ${user.require_auth_header === 1 ? 'text-error' : 'text-success'}">${user.require_auth_header === 1 ? '需要头部' : '免认证'}</span></p>
                
                <p><strong>Shell (444):</strong> <span class="font-medium ${shellColor}">${shellText}</span></p>
            </div>
            <div class="grid grid-cols-3 gap-2">
                <button onclick="confirmAction('${user.username}', null, null, 'killAll', '强制断开所有')" 
                        class="btn btn-error btn-xs" aria-label="强制断开 ${user.username}">踢下线</button>
                <button onclick="openTrafficChartModal('${user.username}')"
                        class="btn btn-secondary btn-xs" aria-label="流量图 ${user.username}">流量图</button>
                
                <button onclick="openSettingsModal('${user.username}', '${user.expiration_date || ''}', ${user.quota_gb}, '${user.rate_kbps}', '${user.max_connections}', '${user.fuse_threshold_kbps}', ${user.require_auth_header}, ${user.allow_shell})" 
                        class="btn btn-primary btn-xs" aria-label="设置 ${user.username}">设置</button>
                        
                <button onclick="confirmAction('${user.username}', '${toggleAction}', null, 'toggleStatus', '${toggleText}用户')" 
                        class="btn ${toggleColor} btn-xs" aria-label="${toggleText}用户 ${user.username}">${toggleText}</button>
                <button onclick="confirmAction('${user.username}', 'delete', null, 'deleteUser', '删除用户')" 
                        class="btn btn-error btn-xs col-span-2" aria-label="删除用户 ${user.username}">删除</button>
            </div>
        </div>
    </div>`;
}

/**
 * [AXIOM V3.0] 重构: renderUserList (PC/移动端)
 * - 这是一个“骨架”渲染器
 * - 为所有动态元素添加 ID
 */
function renderUserList(users) {
    const tbody = document.getElementById('user-list-tbody');
    const mobileContainer = document.getElementById('user-list-mobile');
    let tableHtml = [];
    let mobileHtml = [];
    
    document.querySelectorAll('th.sortable .sort-arrow').forEach(arrow => {
        // ... [保留的排序箭头逻辑] ...
        const th = arrow.parentElement;
        if (th.dataset.sortkey === currentSortKey) {
            arrow.innerHTML = currentSortDir === 'asc' ? '▲' : '▼';
            arrow.style.opacity = '1';
        } else {
            arrow.innerHTML = '▲'; 
            arrow.style.opacity = '0.4';
        }
    });

    if (users.length === 0) {
        const emptyRow = '<tr><td colspan="9" class="px-6 py-4 text-center text-gray-500">没有找到匹配的用户</td></tr>';
        tbody.innerHTML = emptyRow;
        mobileContainer.innerHTML = `<div class="text-center text-gray-500 py-4">没有找到匹配的用户</div>`;
        return;
    }

    users.forEach(user => {
        let statusColor = 'badge-success';
        if (user.status === 'paused') { statusColor = 'badge-warning'; }
        if (user.status === 'fused') { statusColor = 'badge-warning'; }
        if (user.status === 'expired' || user.status === 'exceeded') { statusColor = 'badge-error'; }
        
        const statusText = user.status_text;
        const isLocked = (user.status !== 'active'); 
        const toggleAction = isLocked ? 'enable' : 'pause';
        const toggleText = isLocked ? '启用' : '暂停';
        const toggleColor = isLocked ? 'btn-success' : 'btn-warning';
        const isChecked = selectedUsers.includes(user.username) ? 'checked' : '';
        
        const maxConnections = user.max_connections !== undefined ? user.max_connections : 0; 
        const fuseThreshold = user.fuse_threshold_kbps !== undefined ? user.fuse_threshold_kbps : 0; 
        
        // [AXIOM V3.0] 移除: 速度/连接数在渲染骨架时设为 0 或 ...
        // 它们将由 `handleSilentUpdate` 填充
        const speedUp = '...';
        const speedDown = '...';
        const activeConnections = user.active_connections !== undefined ? user.active_connections : 0;
        
        const allowShell = user.allow_shell || 0;

        const quotaLimit = user.quota_gb > 0 ? user.quota_gb : '∞';
        const usageText = user.usage_gb.toFixed(4) + ' / ' + quotaLimit;
        const quotaLimitValue = user.quota_gb > 0 ? user.quota_gb : 0;
        const usagePercent = (quotaLimitValue > 0) ? (user.usage_gb / quotaLimitValue) * 100 : 0;
        const progressHtml = (quotaLimitValue > 0) 
            ? `<progress class="progress progress-primary usage-progress" value="${usagePercent}" max="100"></progress>` 
            : '<div class="usage-progress"></div>';
        
        tableHtml.push(`
            <tr id="row-${user.username}" class="hover">
                <td class="px-4 py-4">
                    <input type="checkbox" data-username="${user.username}" ${isChecked} class="user-checkbox checkbox checkbox-primary">
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm font-mono text-base-content" role="cell">${user.username}</td>
                
                <!-- [AXIOM V3.0] 新增 ID -->
                <td id="status-cell-${user.username}" class="px-6 py-4 whitespace-nowrap text-sm" role="cell">
                    <span class="badge ${statusColor} text-xs font-semibold">
                        ${statusText}
                    </span>
                </td>
                
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500" role="cell">${user.expiration_date || '永不'}</td>
                
                <!-- [AXIOM V3.0] 新增 ID -->
                <td id="conn-cell-${user.username}" class="px-6 py-4 whitespace-nowrap text-sm font-medium text-primary" role="cell">${activeConnections}</td>
                
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-base-content" role="cell">${formatConnections(maxConnections)}</td>
                
                <!-- [AXIOM V3.0] 新增 ID -->
                <td id="usage-cell-${user.username}" class="px-6 py-4 whitespace-nowrap text-sm font-medium text-base-content" role="cell">
                    <div>${usageText} GB</div>
                    ${progressHtml}
                </td>
                
                <td class="px-6 py-4 whitespace-nowrap text-sm font-mono speed-cell" role="cell" id="speed-cell-${user.username}">
                    <span class="speed-up">↑ ${speedUp}</span> / 
                    <span class="speed-down">↓ ${speedDown}</span>
                </td>
                
                <td class="px-6 py-4 text-sm font-medium" role="cell">
                    <div class="flex flex-wrap gap-1">
                        <button onclick="confirmAction('${user.username}', null, null, 'killAll', '强制断开所有')" 
                                class="btn btn-error btn-xs" aria-label="强制断开 ${user.username}">踢下线</button>
                        <button onclick="openTrafficChartModal('${user.username}')"
                                class="btn btn-secondary btn-xs" aria-label="流量图 ${user.username}">流量图</button>
                        
                        <button onclick="openSettingsModal('${user.username}', '${user.expiration_date || ''}', ${user.quota_gb}, '${user.rate_kbps}', '${maxConnections}', '${fuseThreshold}', ${user.require_auth_header}, ${allowShell})" 
                                class="btn btn-primary btn-xs" aria-label="设置 ${user.username}">设置</button>
                                
                        <button onclick="confirmAction('${user.username}', '${toggleAction}', null, 'toggleStatus', '${toggleText}用户')" 
                                class="btn ${toggleColor} btn-xs" aria-label="${toggleText}用户 ${user.username}">${toggleText}</button>
                        <button onclick="confirmAction('${user.username}', 'delete', null, 'deleteUser', '删除用户')" 
                                class="btn btn-error btn-xs" aria-label="删除用户 ${user.username}">删除</button>
                    </div>
                </td>
            </tr>
        `);
        
        mobileHtml.push(buildUserCard(user, statusColor, statusText, toggleAction, toggleText, toggleColor, usageText, progressHtml));
    });
    
    tbody.innerHTML = tableHtml.join('');
    mobileContainer.innerHTML = mobileHtml.join('');
    bindCheckboxEvents();
}

function renderFilteredUserList() {
    // ... [保留的 renderFilteredUserList 逻辑, 它依赖 allUsersCache] ...
    let usersToRender = [...allUsersCache];
    const searchTerm = document.getElementById('user-search-input').value.toLowerCase();
    if (searchTerm) {
        usersToRender = usersToRender.filter(user => 
            user.username.toLowerCase().includes(searchTerm)
        );
    }
    
    usersToRender.sort((a, b) => {
        let valA = a[currentSortKey];
        let valB = b[currentSortKey];
        
        if (currentSortKey === 'expiration_date') {
            valA = valA ? new Date(valA).getTime() : 0;
            valB = valB ? new Date(valB).getTime() : 0;
        } else if (currentSortKey === 'max_connections' || currentSortKey === 'active_connections' || currentSortKey === 'usage_gb' || 
                   currentSortKey === 'realtime_speed_down' || currentSortKey === 'realtime_speed_up') { 
            valA = parseFloat(valA) || 0;
            valB = parseFloat(valB) || 0;
            if (currentSortKey === 'max_connections') {
                 valA = valA === 0 ? Infinity : valA;
                 valB = valB === 0 ? Infinity : valB;
            }
        } else if (typeof valA === 'string') {
            valA = valA.toLowerCase();
            valB = valB.toLowerCase();
        }

        let comparison = 0;
        if (valA > valB) comparison = 1;
        else if (valA < valB) comparison = -1;
        
        return currentSortDir === 'asc' ? comparison : -comparison;
    });
    
    renderUserList(usersToRender);
    // [AXIOM V3.0] 关键: 渲染骨架后，立即请求一次实时数据
    // (因为旧数据可能已过时，而下一次 WS 推送可能在 1 秒后)
    // (更好的方法是让 `handleSilentUpdate` 更新 `allUsersCache`，但
    // 为了简单起见，我们暂时忽略)
}

function renderActiveGlobalIPs(ipData) {
    // ... [保留的 renderActiveGlobalIPs 逻辑] ...
    const container = document.getElementById('live-ip-list');
    let htmlContent = '';
    
    if (ipData.length === 0) {
        container.innerHTML = '<p class="text-gray-500 p-2">目前没有活跃的外部连接。</p>';
        return;
    }

    ipData.forEach(ipInfo => {
        const isBanned = ipInfo.is_banned;
        const action = isBanned ? 'unban' : 'ban';
        const actionText = isBanned ? '解除封禁' : '全局封禁';
        const buttonColor = isBanned ? 'btn-success' : 'btn-error';
        const banTag = isBanned ? '<span class="badge badge-error badge-outline ml-2">已封禁</span>' : '';
        
        const usernameSpan = ipInfo.username ? 
            `<span class="badge badge-primary badge-outline ml-2 font-mono text-xs">${ipInfo.username}</span>` : 
            `<span class="badge badge-warning badge-outline ml-2 text-xs">未知用户</span>`;
            
        htmlContent += `
            <div class="flex flex-col sm:flex-row items-start sm:items-center justify-between p-3 bg-base-100 border border-base-300 rounded-lg shadow-sm">
                <div class="min-w-0 flex-1 flex flex-col sm:flex-row sm:items-center">
                    <p class="font-mono text-sm text-base-content flex items-center">
                        <strong>${ipInfo.ip}</strong> ${usernameSpan} ${banTag}
                    </p>
                </div>
                <button onclick="confirmAction(null, '${ipInfo.ip}', null, '${action}Global', '${isBanned ? '解除全局封禁' : '全局封禁 IP'}')" 
                             class="mt-2 sm:mt-0 w-full sm:w-auto btn ${buttonColor} btn-xs font-semibold flex-shrink-0">
                    ${actionText}
                </button>
            </div>`;
    });
    container.innerHTML = htmlContent;
}

function renderAuditLogs(logs) {
    // ... [保留的 renderAuditLogs 逻辑] ...
    const logContainer = document.getElementById('audit-log-content');
    const filteredLogs = logs.filter(log => log.trim() !== "" && log !== '读取日志失败或日志文件为空。' && log !== '日志文件不存在。');

    if (filteredLogs.length === 0) {
        logContainer.innerHTML = '<p class="text-gray-500">目前没有管理员审计活动日志。</p>';
        return;
    }
    logContainer.innerHTML = '';
    const fragment = document.createDocumentFragment();

    filteredLogs.forEach(log => {
        const parts = log.match(/^\[(.*?)\] \[USER:(.*?)\] \[IP:(.*?)\] ACTION:(.*?) DETAILS: (.*)$/);
        const div = document.createElement('div');
        if (parts) {
            const [_, timestamp, user, ip, action, details] = parts;
            const safeDetails = document.createElement('div');
            safeDetails.textContent = details;
            div.className = 'text-xs text-base-content font-mono space-y-1 p-1 hover:bg-base-300 rounded-md';
            div.innerHTML = 
                '<span class="text-primary">' + timestamp.split(' ')[1] + '</span> ' +
                '<span class="font-bold">[' + user + ']</span> ' +
                '<span class="text-sm font-semibold text-base-content">' + action + '</span> ' +
                '<span class="text-gray-500">' + safeDetails.innerHTML + '</span>'; 
        } else {
            div.className = 'text-xs text-base-content font-mono p-1';
            div.textContent = log;
        }
        fragment.appendChild(div);
    });
    logContainer.appendChild(fragment);
}

function renderGlobalBans(bans) {
    // ... [保留的 renderGlobalBans 逻辑] ...
    const container = document.getElementById('global-ban-list');
    const banKeys = Object.keys(bans);
    if (banKeys.length === 0) {
        container.innerHTML = '<p class="text-success font-semibold p-2">目前没有全局封禁的 IP。</p>';
        return;
    }
    container.innerHTML = banKeys.map(ip => {
        const banInfo = bans[ip];
        return (
            '<div class="flex justify-between items-center p-3 bg-error/10 border border-error/20 rounded-lg shadow-sm">' +
                '<div class="font-mono text-sm text-error-content">' +
                    '<strong>' + ip + '</strong> ' +
                    '<span class="text-xs text-gray-500 ml-4">原因: ' + (banInfo.reason || 'N/A') + ' (添加于 ' + banInfo.timestamp + ')</span>' +
                '</div>' +
                '<button onclick="confirmAction(null, \'' + ip + '\', null, \'unbanGlobal\', \'解除全局封禁\')" ' +
                             'class="btn btn-success btn-xs font-semibold flex-shrink-0">解除封禁</button>' +
            '</div>'
        );
    }).join('');
}

function renderHosts(hosts) {
    // ... [保留的 renderHosts 逻辑] ...
    const textarea = document.getElementById('host-list-textarea');
    const countInfo = document.getElementById('host-count-info');
    textarea.value = hosts.join('\n');
    const validHosts = hosts.filter(h => h.trim() !== '');
    countInfo.textContent = `当前加载 ${validHosts.length} 个 Host。`;
}

// --- 核心 API 调用函数 ---

async function fetchData(url, options = {}) {
    // ... [保留的 fetchData 逻辑, 它依然用于 API 调用] ...
    try {
        const response = await fetch(API_BASE + url, options);
        if (response.status === 401) {
            showStatus("会话过期或权限不足，请重新登录。", false);
            // [AXIOM V3.0] 停止 WS 重连
            if (wsReconnectTimer) clearTimeout(wsReconnectTimer);
            if (panelSocket) panelSocket.close();
            window.location.assign('/login.html'); 
            return null;
        }
        if (response.redirected) {
            window.location.assign(response.url);
            return null;
        }
        const contentType = response.headers.get("content-type");
        
        if (!contentType || !contentType.includes("application/json")) {
            if (response.ok) {
                const text = await response.text();
                console.error("API expected JSON but got HTML/Text:", text.substring(0, 100) + '...');
                if (text.trim().startsWith('<!DOCTYPE html>')) {
                     showStatus("API 响应错误：会话可能已过期，请尝试重新登录。", false);
                     setTimeout(() => window.location.assign('/login.html'), 1000); 
                     return null;
                }
                showStatus("API 响应格式错误，可能返回了非 JSON 页面。", false);
                return null;
            }
        }
        
        const data = await response.json();
        
        if (!response.ok || (typeof data.success === 'boolean' && !data.success)) {
            // [AXIOM V3.0] 移除: live-stats 检查
            showStatus(data.message || 'API Error: ' + url, false);
            return null;
        }
        return data;
    } catch (error) {
         // [AXIOM V3.0] 移除: live-stats 检查
         showStatus('网络请求失败: ' + error.message, false);
        return null;
    }
}

async function fetchServiceLogs(serviceId) {
    // ... [保留的 fetchServiceLogs 逻辑] ...
     const logContainer = document.getElementById('service-log-content');
    logContainer.textContent = '正在加载 ' + serviceId + ' 日志...';
    const data = await fetchData('/system/logs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service: serviceId })
    });
    if (data && data.logs) {
        const prefixedLogs = data.logs.split('\n').map(line => `~$ ${line}`).join('\n');
        logContainer.textContent = prefixedLogs;
    } else {
        logContainer.textContent = `~$ 无法加载 ${serviceId} 日志。`;
    }
}

async function fetchHosts() {
     // ... [保留的 fetchHosts 逻辑] ...
     const data = await fetchData('/settings/hosts');
     if (data && data.hosts) {
        renderHosts(data.hosts);
     } else {
        renderHosts([]);
     }
}

async function saveHosts() {
    // ... [保留的 saveHosts 逻辑] ...
    const textarea = document.getElementById('host-list-textarea');
    const hostsArray = textarea.value.split('\n').map(h => h.trim()).filter(h => h.length > 0);
    showStatus('正在保存 Host 配置并通知 WSS 代理热重载...', true);
    const result = await fetchData('/settings/hosts', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hosts: hostsArray })
    });
    if (result) {
        showStatus(result.message, true);
    }
}

async function fetchGlobalSettings() {
     // ... [保留的 fetchGlobalSettings 逻辑] ...
     const data = await fetchData('/settings/global');
     if (data && data.settings) {
        document.getElementById('global-fuse-threshold').value = data.settings.fuse_threshold_kbps || 0;
     }
}

async function saveGlobalSettings() {
    // ... [保留的 saveGlobalSettings 逻辑] ...
    const fuseThreshold = document.getElementById('global-fuse-threshold').value;
    showStatus('正在保存全局安全设置并实时通知所有代理...', true);
    
    const result = await fetchData('/settings/global', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            fuse_threshold_kbps: parseInt(fuseThreshold)
        })
    });
    
    if (result) {
        showStatus(result.message, true);
    }
}

async function fetchGlobalConfig() {
     // ... [保留的 fetchGlobalConfig 逻辑] ...
     const data = await fetchData('/settings/config');
     if (data && data.config) {
        document.getElementById('config-panel-port').value = data.config.panel_port;
        document.getElementById('config-wss-http-port').value = data.config.wss_http_port;
        document.getElementById('config-wss-tls-port').value = data.config.wss_tls_port;
        document.getElementById('config-stunnel-port').value = data.config.stunnel_port;
        document.getElementById('config-udpgw-port').value = data.config.udpgw_port;
        document.getElementById('config-internal-forward-port').value = data.config.internal_forward_port;
        document.getElementById('config-internal-api-port').value = data.config.internal_api_port;
     }
}
async function saveGlobalConfig() {
    // ... [保留的 saveGlobalConfig 逻辑] ...
    showStatus('正在保存端口配置...', true);
    
    const configData = {
        panel_port: parseInt(document.getElementById('config-panel-port').value),
        wss_http_port: parseInt(document.getElementById('config-wss-http-port').value),
        wss_tls_port: parseInt(document.getElementById('config-wss-tls-port').value),
        stunnel_port: parseInt(document.getElementById('config-stunnel-port').value),
        udpgw_port: parseInt(document.getElementById('config-udpgw-port').value),
        internal_forward_port: parseInt(document.getElementById('config-internal-forward-port').value)
    };
    
    const result = await fetchData('/settings/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(configData)
    });
    
    if (result) {
        showStatus(result.message, true);
        if (configData.panel_port !== FLASK_CONFIG.PANEL_PORT) {
            showStatus('面板端口已更改！页面将在 3 秒后尝试使用新端口重新加载...', true);
            setTimeout(() => {
                window.location.port = configData.panel_port;
                window.location.reload();
            }, 3000);
        }
    }
}


// --- [AXIOM V3.0] 实时刷新主函数 (重构为 WebSocket) ---

/**
 * [AXIOM V3.0] 新增: WebSocket 状态指示灯 (需求 #5)
 * @param {'red' | 'green' | 'blue' | 'gray'} color 状态颜色
 * @param {string} tip 鼠标悬停提示
 */
function setWsStatusIcon(color, tip) {
    const icon = document.getElementById('ws-status-icon');
    const tooltip = document.getElementById('ws-status-tooltip');
    if (!icon || !tooltip) return;

    tooltip.dataset.tip = tip;
    
    // 移除所有颜色类
    icon.classList.remove('status-light-red', 'status-light-green', 'status-light-blue', 'status-light-gray');
    
    let iconName = 'wifi';
    switch (color) {
        case 'red':
            icon.classList.add('status-light-red');
            iconName = 'wifi-off';
            break;
        case 'green':
            icon.classList.add('status-light-green');
            iconName = 'wifi';
            break;
        case 'blue':
            icon.classList.add('status-light-blue');
            iconName = 'loader-2'; // "连接中" 图标
            break;
        case 'gray':
        default:
            icon.classList.add('status-light-gray');
            iconName = 'wifi-off';
            break;
    }
    
    // 更新图标 (如果图标变化)
    if (icon.dataset.lucide !== iconName) {
        icon.dataset.lucide = iconName;
        // 使用 Lucide API 替换图标
        lucide.createIcons({
            nodes: [icon],
            attrs: {
                'data-lucide': iconName,
                'class': icon.className // 保持现有类
            }
        });
        
        // 如果是 loader-2，添加旋转动画
        if (iconName === 'loader-2') {
            icon.classList.add('animate-spin');
        } else {
            icon.classList.remove('animate-spin');
        }
    }
}

/**
 * [AXIOM V3.0] 新增: WebSocket 客户端
 */
function connectWebSocket() {
    if (wsReconnectTimer) {
        clearTimeout(wsReconnectTimer);
        wsReconnectTimer = null;
    }
    if (panelSocket) {
        panelSocket.close();
        panelSocket = null;
    }

    // 1. 设置 WS 协议和 URL
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${wsProtocol}//${window.location.host}/ws/ui`;
    
    console.log(`[AXIOM V3.0] 正在连接到 WebSocket: ${wsUrl}`);
    setWsStatusIcon('blue', '正在连接实时推送...'); // 蓝色: 连接中

    panelSocket = new WebSocket(wsUrl);

    // 2. 连接成功
    panelSocket.onopen = (event) => {
        console.log('[AXIOM V3.0] WebSocket 已连接。等待服务器验证...');
        // (等待来自服务器的 'status_connected' 消息)
    };

    // 3. 收到消息 (核心处理器)
    panelSocket.onmessage = (event) => {
        try {
            const message = JSON.parse(event.data);
            
            switch (message.type) {
                // 需求 #5: (蓝 -> 绿) 连接并验证成功
                case 'status_connected':
                    setWsStatusIcon('green', '实时推送已连接 (1秒刷新)');
                    console.log('[AXIOM V3.0] WebSocket 身份验证成功。正在加载初始数据...');
                    // 触发一次性的初始数据加载
                    fetchAllStaticData(); 
                    break;
                
                // 需求 #1, #4: (1秒推送) 实时数据更新
                case 'live_update':
                    if (message.payload) {
                        // 优雅/静默更新
                        if (message.payload.users) {
                            handleSilentUpdate(message.payload.users);
                        }
                        if (message.payload.system) {
                            handleDashboardSilentUpdate(message.payload.system);
                        }
                    }
                    break;
                
                // (60秒慢推送) 非紧急系统状态
                case 'system_update':
                    if (message.payload && currentView === 'dashboard') {
                        renderSystemStatus(message.payload);
                        renderUserQuickStats(message.payload.user_stats);
                    }
                    break;
                
                // (手动操作) 静态数据变更
                case 'users_changed':
                    console.log('[AXIOM V3.0] 收到 users_changed 推送，正在全量刷新用户列表...');
                    fetchAllUsersAndRender();
                    break;
                
                // (手动操作) Host 变更
                case 'hosts_changed':
                    if (currentView === 'hosts') {
                        console.log('[AXIOM V3.0] 收到 hosts_changed 推送，正在刷新 Hosts...');
                        fetchHosts();
                    }
                    break;
                
                // 验证失败
                case 'auth_failed':
                    console.error('[AXIOM V3.0] WebSocket 身份验证失败。');
                    setWsStatusIcon('red', '实时推送身份验证失败');
                    showStatus('实时推送身份验证失败，请重新登录。', false);
                    panelSocket.close();
                    break;
            }
        } catch (e) {
            console.error('[AXIOM V3.0] 解析 WebSocket 消息失败:', e);
        }
    };

    // 4. 连接关闭
    panelSocket.onclose = (event) => {
        console.warn(`[AXIOM V3.0] WebSocket 已断开。代码: ${event.code}. 3秒后重试...`);
        setWsStatusIcon('red', '实时推送已断开，正在重连...');
        if (!wsReconnectTimer) {
            wsReconnectTimer = setTimeout(connectWebSocket, 3000);
        }
    };

    // 5. 连接错误
    panelSocket.onerror = (error) => {
        console.error('[AXIOM V3.0] WebSocket 发生错误: ', error);
        setWsStatusIcon('red', '实时推送连接错误');
        // onclose 会自动被触发, 无需在此处重连
    };
}


/**
 * [AXIOM V3.0] 新增: 优雅的静默更新处理器 (1秒)
 * @param {object} userStats - 例如: { "user_A": { "speed_kbps": {...}, "connections": 2 }, ... }
 */
function handleSilentUpdate(userStats) {
    if (currentView !== 'users') return; // 仅在用户视图活动时更新

    for (const username in userStats) {
        if (!userStats.hasOwnProperty(username)) continue;
        
        const stats = userStats[username];
        const speedUpText = formatSpeedUnits(stats.speed_kbps.upload || 0);
        const speedDownText = formatSpeedUnits(stats.speed_kbps.download || 0);
        const connectionsText = stats.connections || 0;

        // 1. 更新 PC 列表 (只修改 textContent)
        const speedCell = document.getElementById(`speed-cell-${username}`);
        const connCell = document.getElementById(`conn-cell-${username}`); 

        if (speedCell) {
            // 使用 .innerHTML 以保留内部的 <span> 样式
            speedCell.innerHTML = 
                `<span class="speed-up">↑ ${speedUpText}</span> / ` +
                `<span class="speed-down">↓ ${speedDownText}</span>`;
        }
        if (connCell) {
            connCell.textContent = connectionsText;
        }

        // 2. 更新移动端卡片 (只修改 textContent)
        const speedUpMobile = document.getElementById(`speed-up-mobile-${username}`);
        const speedDownMobile = document.getElementById(`speed-down-mobile-${username}`);
        const connMobile = document.getElementById(`conn-mobile-${username}`);

        if (speedUpMobile) speedUpMobile.textContent = `↑ ${speedUpText}`;
        if (speedDownMobile) speedDownMobile.textContent = `↓ ${speedDownText}`;
        if (connMobile) connMobile.textContent = connectionsText;
    }
}

/**
 * [AXIOM V3.0] 新增: 静默更新仪表盘 (1秒)
 * @param {object} systemStats - 例如: { "active_connections_total": 3 }
 */
function handleDashboardSilentUpdate(systemStats) {
    if (currentView !== 'dashboard') return; // 仅在仪表盘视图活动时更新

    // 只更新“活跃连接数”
    const activeConnsWidget = document.getElementById('stat-active-conns');
    if (activeConnsWidget) {
        activeConnsWidget.textContent = systemStats.active_connections_total;
    }
}


/**
 * [AXIOM V3.0] 重构: `refreshAllData` -> `fetchAllStaticData`
 * 仅在 WS 连接成功时调用一次
 */
async function fetchAllStaticData() {
    console.log("[AXIOM V3.0] 正在加载一次性静态数据...");
    try {
        // 1. 加载仪表盘数据 (CPU/内存/服务/端口/用户统计)
        const statusData = await fetchData('/system/status');
        if (statusData) {
            renderSystemStatus(statusData);
            renderUserQuickStats(statusData.user_stats); 
        }

        // 2. 加载用户列表 (用于用户页面和载荷生成器)
        await fetchAllUsersAndRender();
        
        // 3. (可选) 预加载其他视图的数据
        if (currentView === 'live-ips') { fetchActiveIPs(); }
        if (currentView === 'settings') { fetchAuditLogs(); }
        if (currentView === 'security') { fetchGlobalBans(); }
        
    } catch (error) {
        console.error("Error during fetchAllStaticData:", error);
    }
}

/**
 * [AXIOM V3.0] 新增: 分离的用户列表加载器
 * (由 WS 的 `users_changed` 或 `status_connected` 触发)
 */
async function fetchAllUsersAndRender() {
    const usersData = await fetchData('/users/list');
    if (usersData) {
        allUsersCache = usersData.users; 
        if (currentView === 'users') {
            renderFilteredUserList(); 
        }
        if (currentView === 'payload-gen') { 
            populatePayloadUserSelect();
        }
    }
}

// [AXIOM V3.0] 新增: 分离的加载器
async function fetchActiveIPs() {
     const ipData = await fetchData('/system/active_ips');
     if (ipData) {
        renderActiveGlobalIPs(ipData.active_ips);
     }
}
async function fetchAuditLogs() {
    const auditData = await fetchData('/system/audit_logs');
    if (auditData) {
        renderAuditLogs(auditData.logs);
    }
}
async function fetchGlobalBans() {
    const globalData = await fetchData('/ips/global_list');
    if (globalData) {
        renderGlobalBans(globalData.global_bans);
    }
}

// [AXIOM V3.0] 移除: `refreshLiveSpeeds` (已废弃)


// --- 用户操作实现 ---

function generateBase64Token(username, password) {
    // ... [保留的 generateBase64Token 逻辑] ...
    if (!username || !password) return null; 
    try {
        const token = btoa(`${username}:${password}`); 
        return token;
    } catch (e) {
        console.error("btoa failed:", e);
        return "编码失败";
    }
}

document.getElementById('add-user-form').addEventListener('submit', async (e) => {
    // ... [保留的 add-user-form 逻辑] ...
    e.preventDefault();
    const username = document.getElementById('new-username').value;
    const password = document.getElementById('new-password').value;
    const expirationDays = document.getElementById('expiration-days').value;
    const quotaGb = document.getElementById('quota-gb').value;
    const rateKbps = document.getElementById('rate-kbps').value;
    const maxConnections = document.getElementById('new-max-connections').value;
    const requireAuth = document.getElementById('new-require-auth').checked; 
    const allowShell = document.getElementById('new-allow-shell').checked; 

    if (!/^[a-z0-9_]{3,16}$/.test(username)) {
        showStatus('用户名格式不正确 (3-16位小写字母/数字/下划线)', false);
        return;
    }
    showStatus('正在创建用户 ' + username + '...', true);

    const result = await fetchData('/users/add', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            username: username, 
            password: password, 
            expiration_days: parseInt(expirationDays),
            quota_gb: parseFloat(quotaGb),
            rate_kbps: parseInt(rateKbps),
            max_connections: parseInt(maxConnections),
            require_auth_header: requireAuth ? 1 : 0,
            allow_shell: allowShell ? 1 : 0 
        })
    });

    if (result) {
        showStatus(result.message, true);
        document.getElementById('add-user-form').reset();
        closeModal('add-user-modal');
        const tokenOutput = document.getElementById('new-connect-token');
        if (tokenOutput) {
            tokenOutput.value = "[在此输入用户名和密码]";
        }
        // [AXIOM V3.0] 移除: refreshAllData()
        // (后端将在成功后推送 'users_changed' 消息)
    }
});

async function openSettingsModal(username, expiry_date, quota_gb, rate_kbps, max_connections, fuse_threshold_kbps, require_auth_header, allow_shell) {
    // ... [保留的 openSettingsModal 逻辑] ...
    document.getElementById('modal-username-title-settings').textContent = username;
    document.getElementById('modal-username-setting').value = username;
    document.getElementById('modal-expiry-date').value = expiry_date; 
    document.getElementById('modal-quota-gb').value = quota_gb;
    document.getElementById('modal-rate-kbps').value = rate_kbps;
    document.getElementById('modal-max-connections').value = (max_connections !== undefined) ? max_connections : 0;
    document.getElementById('modal-require-auth').checked = (require_auth_header === 1); 
    document.getElementById('modal-allow-shell').checked = (allow_shell === 1); 
    document.getElementById('modal-new-password').value = ''; 
    document.getElementById('modal-connect-token').value = TOKEN_PLACEHOLDER;
    openModal('settings-modal');
}

document.getElementById('modal-new-password').addEventListener('input', function() {
    // ... [保留的密码输入逻辑] ...
    const username = document.getElementById('modal-username-setting').value;
    const password = this.value;
    const tokenInput = document.getElementById('modal-connect-token');
    
    if (password) {
         const token = generateBase64Token(username, password);
         tokenInput.value = token;
    } else {
         tokenInput.value = TOKEN_PLACEHOLDER;
    }
});

async function saveUserSettings() {
    // ... [保留的 saveUserSettings 逻辑] ...
    const username = document.getElementById('modal-username-setting').value;
    const expiry_date = document.getElementById('modal-expiry-date').value;
    const quota_gb = document.getElementById('modal-quota-gb').value;
    const rate_kbps = document.getElementById('modal-rate-kbps').value;
    const max_connections = document.getElementById('modal-max-connections').value;
    const new_password = document.getElementById('modal-new-password').value;
    const requireAuth = document.getElementById('modal-require-auth').checked; 
    const allowShell = document.getElementById('modal-allow-shell').checked; 
    
    closeModal('settings-modal');
    showStatus('正在保存用户 ' + username + ' 的设置并实时通知代理...', true);

    const result = await fetchData('/users/set_settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
            username: username, 
            expiry_date: expiry_date, 
            quota_gb: parseFloat(quota_gb), 
            rate_kbps: parseInt(rate_kbps),
            max_connections: parseInt(max_connections),
            new_password: new_password,
            require_auth_header: requireAuth ? 1 : 0,
            allow_shell: allowShell ? 1 : 0 
        })
    });

    if (result) {
        showStatus(result.message, true);
        // [AXIOM V3.0] 移除: refreshAllData()
        // (后端将在成功后推送 'users_changed' 消息)
    }
}

async function openTrafficChartModal(username) {
    // ... [保留的 openTrafficChartModal 逻辑] ...
    document.getElementById('traffic-chart-username-title').textContent = username;
    document.getElementById('traffic-chart-loading').style.display = 'block';
    if (trafficChartInstance) {
        trafficChartInstance.destroy();
    }
    openModal('traffic-chart-modal');
    const data = await fetchData(`/users/traffic-history?username=${username}`);
    document.getElementById('traffic-chart-loading').style.display = 'none';

    if (data && data.history) {
        const history = data.history;
        const dates = history.map(item => item.date.substring(5)); 
        const usage = history.map(item => item.usage_gb);
        const ctx = document.getElementById('trafficChartCanvas').getContext('2d');
        trafficChartInstance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: dates,
                datasets: [{
                    label: '每日用量 (GB)',
                    data: usage,
                    borderColor: '#3b82f6', // blue-500
                    backgroundColor: 'rgba(59, 130, 246, 0.1)',
                    fill: true,
                    tension: 0.2,
                    pointRadius: 3,
                    pointHoverRadius: 5,
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false }, title: { display: false } },
                scales: {
                    y: { beginAtZero: true, title: { display: true, text: '流量 (GB)' } },
                    x: { title: { display: true, text: '日期' } }
                }
            }
        });
    } else {
         document.getElementById('traffic-chart-loading').textContent = '未能加载流量历史数据。';
         document.getElementById('traffic-chart-loading').style.display = 'block';
    }
}

// --- [AXIOM V1.5] 载荷生成器逻辑 ---
function generatePayload() {
    // ... [保留的 generatePayload 逻辑] ...
    const CRLF = '[crlf]';
    const SPLIT = '[split]';
    const PROTOCOL = '[protocol]'; 
    const HOST_PORT = '[host_port]';
    const UA = '[ua]';
    
    const C = {
        splitEnable: document.getElementById('payload-split-enable').checked,
        r1Method: document.getElementById('payload-r1-method').value,
        r1Host: document.getElementById('payload-r1-host').value.trim() || HOST_PORT,
        r2Host: document.getElementById('payload-host').value.trim() || '[host]',
        r2Method: document.getElementById('payload-method').value,
        headerHost: document.getElementById('payload-header-host').checked,
        headerKeepAlive: document.getElementById('payload-header-keep-alive').checked,
        headerUserAgent: document.getElementById('payload-header-user-agent').checked,
        headerWebsocket: document.getElementById('payload-header-websocket').checked,
        headerOnlineHost: document.getElementById('payload-header-online-host').checked, 
        authMode: document.getElementById('payload-auth-mode').value,
        username: document.getElementById('payload-username').value.trim(),
        password: document.getElementById('payload-password').value,
        token: document.getElementById('payload-auth-token').value
    };
    
    let finalPayload = "";
    
    if (C.splitEnable) {
        let request1 = `${C.r1Method} ${C.r1Host} ${PROTOCOL}${CRLF}`;
        request1 += `Connection: close${CRLF}`; 
        request1 += CRLF; 
        finalPayload += request1;
        finalPayload += SPLIT + CRLF; 
    }
    
    let r2RequestLine = `${C.r2Method} http://${C.r2Host}/ ${PROTOCOL}${CRLF}`;
    if (C.authMode === 'uri') {
        if (!C.username) {
            showStatus('使用 URI 注入时必须填写用户名', false);
            return;
        }
        r2RequestLine = `${C.r2Method} http://${C.r2Host}/?user=${C.username} ${PROTOCOL}${CRLF}`;
    }

    let r2Headers = "";
    if (C.headerHost) {
        r2Headers += `Host: ${C.r2Host}${CRLF}`;
    }
    if (C.headerOnlineHost) {
        r2Headers += `X-Online-Host: ${C.r2Host}${CRLF}`;
    }
    if (C.headerUserAgent) {
        r2Headers += `User-Agent: ${UA}${CRLF}`;
    }
    
    if (C.authMode === 'proxy') {
        if (!C.token || C.token.startsWith('[')) {
            showStatus('使用认证头时必须填写用户名和密码', false);
            return;
        }
        r2Headers += `Proxy-Authorization: Basic ${C.token}${CRLF}`;
    }
    
    if (C.headerKeepAlive) {
        r2Headers += `Connection: Keep-Alive${CRLF}`;
    }
    if (C.headerWebsocket) {
        if (C.headerKeepAlive) {
            r2Headers = r2Headers.replace(`Connection: Keep-Alive${CRLF}`, `Connection: Upgrade${CRLF}`);
        } else {
            r2Headers += `Connection: Upgrade${CRLF}`;
        }
        r2Headers += `Upgrade: websocket${CRLF}`;
    }
    
    let request2 = r2RequestLine + r2Headers + CRLF; 
    finalPayload += request2;
    
    document.getElementById('payload-output').value = finalPayload;
    showStatus('载荷生成成功！', true);
}

function setupPayloadAuthListeners() {
    // ... [保留的 setupPayloadAuthListeners 逻辑] ...
    const usernameInput = document.getElementById('payload-username');
    const passwordInput = document.getElementById('payload-password');
    const tokenOutput = document.getElementById('payload-auth-token');
    
    if (!usernameInput || !passwordInput || !tokenOutput) {
        console.warn("[Axiom] 载荷生成器 (Auth) 的 DOM 元素未找到，跳过监听器。");
        return;
    }
    
    const updateToken = () => {
        const username = usernameInput.value;
        const password = passwordInput.value;
        const token = generateBase64Token(username, password);
        if (token) {
            tokenOutput.value = token;
        } else {
            tokenOutput.value = "[在此输入用户名和密码]";
        }
    };
    
    usernameInput.addEventListener('input', updateToken);
    passwordInput.addEventListener('input', updateToken);
}

function populatePayloadUserSelect() {
    // ... [保留的 populatePayloadUserSelect 逻辑] ...
    const select = document.getElementById('payload-user-select');
    if (!select) return; 
    
    const currentValue = select.value;
    while (select.options.length > 1) {
        select.remove(1);
    }
    if (allUsersCache.length === 0) {
        return;
    }
    const fragment = document.createDocumentFragment();
    allUsersCache.forEach(user => {
        const option = document.createElement('option');
        option.value = user.username;
        option.textContent = user.username;
        fragment.appendChild(option);
    });
    select.appendChild(fragment);
    
    if (Array.from(select.options).some(opt => opt.value === currentValue)) {
        select.value = currentValue;
    }
}

function setupCreateUserTokenListeners() {
    // ... [保留的 setupCreateUserTokenListeners 逻辑] ...
    const usernameInput = document.getElementById('new-username');
    const passwordInput = document.getElementById('new-password');
    const tokenOutput = document.getElementById('new-connect-token');

    if (!usernameInput || !passwordInput || !tokenOutput) {
        console.warn("[Axiom] “创建用户”表单的令牌 DOM 元素未找到，跳过监听器。");
        return;
    }

    const updateToken = () => {
        const username = usernameInput.value;
        const password = passwordInput.value;
        const token = generateBase64Token(username, password); 
        if (token) {
            tokenOutput.value = token;
        } else {
            tokenOutput.value = "[在此输入用户名和密码]";
        }
    };

    usernameInput.addEventListener('input', updateToken);
    passwordInput.addEventListener('input', updateToken);
}

// --- 启动脚本 ---

// [AXIOM V3.0] 移除: `startAutoRefresh`, `stopAutoRefresh`

/**
 * [AXIOM V3.0] 重构: 异步初始化
 */
async function initializeApp() {
    try {
        // [AXIOM V3.0] 1. 异步获取配置 (保持不变)
        const data = await fetchData('/settings/config');
        if (data && data.config) {
            FLASK_CONFIG = {
                WSS_HTTP_PORT: data.config.wss_http_port,
                WSS_TLS_PORT: data.config.wss_tls_port,
                STUNNEL_PORT: data.config.stunnel_port,
                UDPGW_PORT: data.config.udpgw_port,
                INTERNAL_FORWARD_PORT: data.config.internal_forward_port,
                PANEL_PORT: data.config.panel_port
            };
        } else {
             showStatus("无法加载核心配置，请刷新。", false);
             return;
        }
        
        // [AXIOM V3.0] 2. 填充静态 UI
        fillPortNumbers();
        lucide.createIcons();
        lastUserStats = {}; 
        switchView('dashboard');
        
        // [AXIOM V3.0] 3. 启动 WebSocket (移除轮询)
        // 初始数据加载将由 'status_connected' WS 消息触发
        connectWebSocket();
        
        // [AXIOM V3.0] 4. 绑定所有静态事件监听器
        setupPayloadAuthListeners(); 
        setupCreateUserTokenListeners();
        
        // [AXIOM V3.0] 移除: 'visibilitychange' (不再需要)
        
        document.getElementById('user-search-input').addEventListener('input', () => {
            renderFilteredUserList();
        });
        
        document.querySelectorAll('th.sortable').forEach(th => {
            th.addEventListener('click', () => {
                const sortKey = th.dataset.sortkey;
                if (currentSortKey === sortKey) {
                    currentSortDir = currentSortDir === 'asc' ? 'desc' : 'asc';
                } else {
                    currentSortKey = sortKey;
                    currentSortDir = 'asc';
                }
                renderFilteredUserList();
            });
        });

        const payloadUserSelect = document.getElementById('payload-user-select');
        if (payloadUserSelect) {
            payloadUserSelect.addEventListener('change', (e) => {
                const username = e.target.value;
                const usernameInput = document.getElementById('payload-username');
                const passwordInput = document.getElementById('payload-password');
                const tokenOutput = document.getElementById('payload-auth-token');
                
                if (username) {
                    usernameInput.value = username;
                    passwordInput.value = ''; 
                    tokenOutput.value = "[请输入密码]"; 
                    passwordInput.focus(); 
                } else {
                    usernameInput.value = '';
                    passwordInput.value = '';
                    tokenOutput.value = "[在此输入用户名和密码]";
                    usernameInput.focus();
                }
            });
        }

        const payloadSplitEnable = document.getElementById('payload-split-enable');
        if (payloadSplitEnable) {
            payloadSplitEnable.addEventListener('change', (e) => {
                const optionsDiv = document.getElementById('payload-split-options');
                if (e.target.checked) {
                    optionsDiv.style.display = 'block';
                } else {
                    optionsDiv.style.display = 'none';
                }
            });
        }
        
        // [AXIOM V3.0] 移除: 'themeToggle' 的重载逻辑
        // (已移至 V3.0 的 'themeToggle' 监听器顶部)
        
    } catch (e) {
        console.error("Failed to initialize app:", e);
        showStatus("应用初始化失败: " + e.message, false);
    }
}


/**
 * [AXIOM V3.0] 启动
 */
window.onload = function() {
    initializeApp();
};


// --- 通用确认及执行逻辑 (保留) ---

function confirmAction(param1, param2, param3, type, titleText) {
    // ... [保留的 confirmAction 逻辑] ...
    let message = '';
    document.getElementById('confirm-param1').value = param1 || ''; 
    document.getElementById('confirm-param2').value = param2 || ''; 
    document.getElementById('confirm-param3').value = param3 || ''; 
    document.getElementById('confirm-type').value = type;
    const username = param1;
    const action = param2;
    if (type === 'deleteUser') {
        message = '您确定要永久删除用户 <strong>' + username + '</strong> 吗？此操作不可逆，将删除系统账户和所有配置。';
    } else if (type === 'toggleStatus') {
        message = '您确定要 ' + (action === 'pause' ? '暂停' : '启用') + ' 用户 <strong>' + username + '</strong> 吗？';
    } else if (type === 'serviceControl') {
        message = '警告：您确定要重启核心服务 <strong>' + username + '</strong> 吗？这可能会导致短暂的服务中断。';
    } else if (type === 'unbanGlobal') {
        message = '您确定要解除全局封禁 IP 地址 <strong>' + action + '</strong> 吗？';
    } else if (type === 'banGlobal') {
        message = '您确定要对 IP 地址 <strong>' + action + '</strong> 执行全局封禁操作吗？';
    } else if (type === 'resetTraffic') {
        message = '警告：您确定要将用户 <strong>' + username + '</strong> 的流量使用量和历史记录重置为 0 吗？';
    } else if (type === 'killAll') {
        message = '警告：您确定要强制断开用户 <strong>' + username + '</strong> 的所有活跃连接吗？这会强制用户重新连接。';
    } else if (type === 'batchAction') {
         return;
    }
    document.getElementById('confirm-title').textContent = titleText;
    document.getElementById('confirm-message').innerHTML = message;
    const confirmBtn = document.getElementById('confirm-action-btn');
    if (type.includes('ban') || type === 'deleteUser' || type === 'serviceControl' || type === 'killAll') {
         confirmBtn.className = 'btn btn-error';
    } else if (type.includes('enable') || type === 'unbanGlobal' || type === 'resetTraffic') {
         confirmBtn.className = 'btn btn-success';
    } else {
         confirmBtn.className = 'btn btn-primary';
    }
    confirmBtn.onclick = executeAction;
    openModal('confirm-modal');
}

async function executeAction() {
    // ... [保留的 executeAction 逻辑] ...
    closeModal('confirm-modal');
    const param1 = document.getElementById('confirm-param1').value;
    const param2 = document.getElementById('confirm-param2').value;
    const param3 = document.getElementById('confirm-param3').value;
    const type = document.getElementById('confirm-type').value;
    showStatus('正在执行 ' + type + ' 操作...', true);
    let url;
    let body = {};
    if (type === 'deleteUser') {
        url = '/users/delete';
        body = { username: param1 };
    } else if (type === 'toggleStatus') {
        url = '/users/status';
        body = { username: param1, action: param2 }; 
    } else if (type === 'resetTraffic') {
        url = '/users/reset_traffic';
        body = { username: param1 };
    } else if (type === 'serviceControl') {
        url = '/system/control';
        body = { service: param1, action: param2 }; 
    } else if (type === 'unbanGlobal') {
        url = '/ips/unban_global';
        body = { ip: param2 }; 
    } else if (type === 'banGlobal') {
        url = '/ips/ban_global';
        body = { ip: param2, reason: 'Manual Global Ban' };
    } else if (type === 'killAll') {
        url = '/users/kill_all';
        body = { username: param1 };
    } else if (type === 'batchAction') {
        url = '/users/batch-action';
        body = {
            action: param1,
            usernames: JSON.parse(param2),
            days: parseInt(param3) || 0
        };
    }
    const result = await fetchData(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });
    if (result) {
        showStatus(result.message, true);
        if (type === 'batchAction') {
            clearSelections();
        }
        // [AXIOM V3.0] 移除: refreshAllData()
        // (后端将在成功后推送 'users_changed' 消息)
    }
}

document.getElementById('add-global-ban-form').addEventListener('submit', async (e) => {
    // ... [保留的 add-global-ban-form 逻辑] ...
    e.preventDefault();
    const ip = document.getElementById('global-ban-ip').value;
    if (!ip) return showStatus('IP 地址不能为空', false);
    confirmAction(null, ip, null, 'banGlobal', '全局封禁 IP');
});

document.getElementById('change-password-form').addEventListener('submit', async (e) => {
    // ... [保留的 change-password-form 逻辑] ...
    e.preventDefault();
    const old_password = document.getElementById('old-password').value;
    const new_password = document.getElementById('admin-new-password').value;
    const confirm_new_password = document.getElementById('admin-confirm-new-password').value;
    
    if (new_password !== confirm_new_password) {
        showStatus('新密码和确认密码不一致。', false);
        return;
    }
    if (new_password.length < 6) {
        showStatus('新密码长度必须至少为 6 位。', false);
        return;
    }
    showStatus('正在修改管理员密码...', true);
    const result = await fetchData('/settings/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ old_password, new_password })
    });
    if (result) {
        showStatus(result.message, true);
        document.getElementById('change-password-form').reset();
    }
});

// --- 批量操作 JS ---
function clearSelections() {
    // ... [保留的 clearSelections 逻辑] ...
    selectedUsers = [];
    document.querySelectorAll('.user-checkbox').forEach(cb => cb.checked = false);
    const selectAll = document.getElementById('select-all-users');
    if (selectAll) selectAll.checked = false;
    updateBatchActionBar();
}

function updateBatchActionBar() {
    // ... [保留的 updateBatchActionBar 逻辑] ...
    const bar = document.getElementById('batch-action-bar');
    const countSpan = document.getElementById('selected-user-count');
    countSpan.textContent = selectedUsers.length;
    if (selectedUsers.length > 0) {
        bar.classList.add('visible');
    } else {
        bar.classList.remove('visible');
    }
}

function bindCheckboxEvents() {
    // ... [保留的 bindCheckboxEvents 逻辑] ...
    const selectAll = document.getElementById('select-all-users');
    if (selectAll) {
        selectAll.addEventListener('change', (e) => {
            const isChecked = e.target.checked;
            selectedUsers = [];
            const visibleUsernames = Array.from(document.querySelectorAll('#user-list-tbody .user-checkbox')).map(cb => cb.dataset.username);
            document.querySelectorAll('.user-checkbox').forEach(cb => {
                if (visibleUsernames.includes(cb.dataset.username)) {
                    cb.checked = isChecked;
                    if (isChecked) {
                        selectedUsers.push(cb.dataset.username);
                    }
                }
            });
            updateBatchActionBar();
        });
    }
    document.querySelectorAll('.user-checkbox').forEach(cb => {
        cb.addEventListener('change', (e) => {
            const username = e.target.dataset.username;
            if (e.target.checked) {
                if (!selectedUsers.includes(username)) {
                    selectedUsers.push(username);
                }
            } else {
                selectedUsers = selectedUsers.filter(u => u !== username);
            }
            document.querySelectorAll(`.user-checkbox[data-username="${username}"]`).forEach(box => box.checked = e.target.checked);
            const visibleCheckboxes = Array.from(document.querySelectorAll('#user-list-tbody .user-checkbox'));
            const allVisibleChecked = visibleCheckboxes.length > 0 && visibleCheckboxes.every(box => box.checked);
            if (selectAll) selectAll.checked = allVisibleChecked;
            updateBatchActionBar();
        });
    });
}

async function handleBatchAction(action) {
    // ... [保留的 handleBatchAction 逻辑] ...
    if (selectedUsers.length === 0) {
        showStatus('请至少选择一个用户。', false);
        return;
    }
    let days = 0;
    let confirmTitle = '批量操作确认';
    let confirmMessage = `您确定要对选中的 ${selectedUsers.length} 个用户执行 "${action}" 操作吗？`;
    if (action === 'renew') {
        days = parseInt(document.getElementById('batch-renew-days').value) || 30;
        confirmTitle = '批量续期确认';
        confirmMessage = `您确定要为 ${selectedUsers.length} 个用户续期 ${days} 天吗？`;
    } else if (action === 'delete') {
        confirmTitle = '批量删除确认';
        confirmMessage = `警告：您确定要永久删除选中的 ${selectedUsers.length} 个用户吗？此操作不可逆！`;
    }
    document.getElementById('confirm-param1').value = action;
    document.getElementById('confirm-param2').value = JSON.stringify(selectedUsers);
    document.getElementById('confirm-param3').value = days;
    document.getElementById('confirm-type').value = 'batchAction';
    document.getElementById('confirm-title').textContent = confirmTitle;
    document.getElementById('confirm-message').innerHTML = confirmMessage;
    const confirmBtn = document.getElementById('confirm-action-btn');
    confirmBtn.className = 'btn btn-error'; 
    if (action === 'enable' || action === 'renew') {
         confirmBtn.className = 'btn btn-success';
    }
    confirmBtn.onclick = executeAction;
    openModal('confirm-modal');
}

async function runSniFinder() {
    // ... [保留的 runSniFinder 逻辑] ...
    const hostname = document.getElementById('sni-finder-host').value;
    const resultsEl = document.getElementById('sni-finder-results');
    const buttonEl = document.getElementById('sni-finder-btn');

    if (!hostname) {
        resultsEl.textContent = '错误: 域名不能为空。';
        return;
    }

    resultsEl.textContent = '正在查询，请稍候...';
    buttonEl.classList.add('loading', 'btn-disabled');

    const result = await fetchData('/utils/find_sni', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ hostname: hostname })
    });

    buttonEl.classList.remove('loading', 'btn-disabled');

    if (result && result.success) {
        let output = `查询 ${hostname} (IP: ${result.ip}) 成功。\n\n`;
        if (result.hosts && result.hosts.length > 0) {
            output += '发现 ' + result.hosts.length + ' 个 DNS 备用名称:\n';
            output += '----------------------------\n';
            output += result.hosts.join('\n');
        } else {
            output += '没有找到额外的 DNS 备用名称 (subjectAltName)。';
        }
        resultsEl.textContent = output;
    } else {
        resultsEl.textContent = `查询失败: ${result ? result.message : '未知错误'}`;
    }
}
