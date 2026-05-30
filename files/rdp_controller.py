#!/usr/bin/env python3

import subprocess
import json
import time
import os
import sys
import shutil
import logging
from datetime import datetime
import threading
import hashlib
import socket
import socketserver
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    """多线程 HTTP 服务器：单个慢请求（如 firewall reload）不会阻塞其他请求。"""
    daemon_threads = True

# ── 日志 ────────────────────────────────────────────────────────────────────
LOG_FILE = '/var/log/rdp_controller.log'
_fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s', '%Y-%m-%d %H:%M:%S')
logger = logging.getLogger('rdp_controller')
logger.setLevel(logging.INFO)
try:
    _fh = logging.FileHandler(LOG_FILE)
    _fh.setFormatter(_fmt)
    logger.addHandler(_fh)
except OSError:
    pass
_sh = logging.StreamHandler(sys.stdout)
_sh.setFormatter(_fmt)
logger.addHandler(_sh)

CONFIG_PATH = '/etc/config/rdp_controller'
FIREWALL_CONFIG = '/etc/config/firewall'
TIMER_STATE_FILE = '/tmp/rdp_timers.json'

active_timers = {}
timer_lock = threading.Lock()

def uci_get(config, section, option, default=''):
    try:
        result = subprocess.check_output(
            ['uci', 'get', f'{config}.{section}.{option}'],
            stderr=subprocess.STDOUT
        ).decode('utf-8').strip()
        return result
    except:
        return default

def uci_set(config, section, option, value):
    subprocess.run(['uci', 'set', f'{config}.{section}.{option}={value}'], check=False)
    subprocess.run(['uci', 'commit', config], check=False)

def uci_show(config):
    try:
        result = subprocess.check_output(['uci', 'show', config], stderr=subprocess.STDOUT)
        return result.decode('utf-8')
    except:
        return ''

def get_all_redirects():
    """解析 uci show firewall，返回所有 redirect 段。

    兼容两种段标识写法（新旧 OpenWrt 都覆盖）：
      firewall.cfg0392c5=redirect          ← 新版匿名段用 cfg-id
      firewall.@redirect[0]=redirect        ← 旧版 @type[index]
    'index' 存段标识（cfg-id 或 @redirect[N]），可直接用于 uci set。
    """
    sections = {}
    order = []
    for line in uci_show('firewall').split('\n'):
        line = line.strip()
        if '=' not in line:
            continue
        left, value = line.split('=', 1)
        value = value.strip().strip('\'"')
        parts = left.split('.')
        if len(parts) == 2:
            # 段声明：firewall.<secid>=<type>
            if value == 'redirect':
                secid = parts[1]
                sections[secid] = {'index': secid}
                order.append(secid)
        elif len(parts) == 3:
            # 段选项：firewall.<secid>.<key>=<value>
            secid, key = parts[1], parts[2]
            if secid in sections:
                sections[secid][key] = value
    return [sections[s] for s in order]

def get_controllable_redirects():
    """读取被勾选的可控端口转发名称。

    直接解析 /etc/config/rdp_controller，兼容两种存储形式：
      list controlled_redirects 'RDP Forward'   ← UCI list，每项一行，空格安全
      option controlled_redirects 'a b c'        ← 旧的空格分隔字符串
    """
    names = []
    in_main = False
    try:
        with open(CONFIG_PATH) as f:
            for line in f:
                s = line.strip()
                if s.startswith('config '):
                    in_main = s.endswith("'main'") or s.endswith('"main"') or s.endswith(' main')
                    continue
                if not in_main:
                    continue
                if s.startswith('list controlled_redirects'):
                    val = s.split(None, 2)[2].strip().strip('\'"')
                    if val:
                        names.append(val)
                elif s.startswith('option controlled_redirects'):
                    val = s.split(None, 2)[2].strip().strip('\'"')
                    names = val.split()
    except OSError as e:
        logger.error("读取配置失败: %s", e)
    logger.info("controlled_redirects = %r", names)
    return names

def get_redirect_by_secid(secid):
    for r in get_all_redirects():
        if r.get('index') == secid:
            return r
    return None

def cut_connections(redirect):
    """删除流经该端口转发的已建立连接（conntrack 表项），强制断开现有会话。

    仅禁用防火墙 redirect 只能阻止新连接；已建立的 RDP 等长连接因 conntrack
    中仍有 DNAT 映射会继续保持，必须删除对应 conntrack 表项才能断开。
    """
    if not shutil.which('conntrack'):
        logger.warning("未检测到 conntrack 命令，无法断开已建立连接。"
                       "请执行: opkg update && opkg install conntrack-tools")
        return

    proto_raw = (redirect.get('proto') or 'tcp').lower()
    protos = [p for p in ('tcp', 'udp') if p in proto_raw] or ['tcp']
    src_dport = redirect.get('src_dport')
    dest_ip = redirect.get('dest_ip')
    dest_port = redirect.get('dest_port')

    for p in protos:
        # 删除进入该转发端口（DNAT 前的目的端口）的连接
        if src_dport:
            subprocess.run(['conntrack', '-D', '-p', p, '--orig-port-dst', str(src_dport)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # 删除指向内部目标（DNAT 后）的连接，覆盖回复方向
        if dest_ip and dest_port:
            subprocess.run(['conntrack', '-D', '-p', p, '-d', str(dest_ip), '--dport', str(dest_port)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logger.info("已清除 conntrack 连接: proto=%s src_dport=%s dest=%s:%s",
                protos, src_dport, dest_ip, dest_port)

def toggle_redirect_enabled(secid, enabled):
    state = '1' if enabled else '0'
    subprocess.run(['uci', 'set', f'firewall.{secid}.enabled={state}'], check=False)
    subprocess.run(['uci', 'commit', 'firewall'], check=False)
    subprocess.run(['/etc/init.d/firewall', 'reload'], check=False)
    logger.info("redirect %s -> enabled=%s", secid, state)
    # 关闭时同时断开已建立的连接
    if not enabled:
        redirect = get_redirect_by_secid(secid)
        if redirect:
            cut_connections(redirect)

def build_redirects_payload():
    """构造 /api/redirects 响应：受控的端口转发 + 当前计时器。"""
    all_redirects = get_all_redirects()
    controlled = get_controllable_redirects()
    result = []
    for r in all_redirects:
        name = r.get('name')
        if name and name in controlled:
            # 防火墙 redirect 缺省即启用，只有显式 enabled='0' 才算关闭
            enabled = '0' if r.get('enabled') == '0' else '1'
            result.append({
                'name': name,
                'index': r.get('index'),
                'enabled': enabled,
            })
    with timer_lock:
        timers_copy = {k: v.copy() for k, v in active_timers.items()}
    wol_mac = uci_get('rdp_controller', 'main', 'wol_mac', '')
    logger.info("payload redirects=%r controlled=%r timers=%r",
                [x['name'] for x in result], controlled, list(timers_copy.keys()))
    return {'redirects': result, 'timers': timers_copy, 'wol_mac': wol_mac}

def send_wol(mac):
    """向指定 MAC 发送网络唤醒魔术包（UDP 广播到 9 端口）。"""
    clean = mac.replace(':', '').replace('-', '').replace(' ', '').strip()
    if len(clean) != 12 or not all(c in '0123456789abcdefABCDEF' for c in clean):
        return False, 'MAC 地址格式错误'
    try:
        mac_bytes = bytes.fromhex(clean)
        packet = b'\xff' * 6 + mac_bytes * 16
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # 同时发往全局广播与 9 端口，提升不同网络环境下的成功率
        s.sendto(packet, ('255.255.255.255', 9))
        s.sendto(packet, ('255.255.255.255', 7))
        s.close()
        logger.info("已发送网络唤醒魔术包: %s", mac)
        return True, '已发送唤醒魔术包'
    except Exception as e:
        logger.error("网络唤醒失败: %s", e)
        return False, str(e)

def send_feishu_webhook(message):
    webhook_enabled = uci_get('rdp_controller', 'webhook', 'enabled', '0') == '1'
    webhook_url = uci_get('rdp_controller', 'webhook', 'url', '')
    
    if not webhook_enabled or not webhook_url:
        return False
    
    try:
        import urllib.request
        payload = json.dumps({
            'msg_type': 'text',
            'content': {'text': message}
        }).encode('utf-8')
        
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={'Content-Type': 'application/json'}
        )
        
        with urllib.request.urlopen(req, timeout=5) as response:
            ok = response.status == 200
            if ok:
                logger.info("Webhook sent ok")
            else:
                logger.warning("Webhook returned status %d", response.status)
            return ok
    except Exception as e:
        logger.error("Webhook failed: %s", e)
        return False

def save_timer_state(snapshot):
    """把计时器快照写入磁盘。snapshot 由调用方在锁内复制好，
    本函数不再获取 timer_lock —— 之前在持锁上下文里再次抢锁会死锁。"""
    persist = uci_get('rdp_controller', 'settings', 'persist_on_restart', '1') == '1'
    if not persist:
        return
    try:
        with open(TIMER_STATE_FILE, 'w') as f:
            json.dump(snapshot, f)
    except OSError as e:
        logger.error("保存计时器状态失败: %s", e)

def load_timer_state():
    if os.path.exists(TIMER_STATE_FILE):
        try:
            with open(TIMER_STATE_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {}

def timer_thread():
    global active_timers
    active_timers = load_timer_state()
    
    while True:
        now = time.time()
        expired = []

        # 锁内：只做到期判断、移除、快照（全是快速内存操作）
        with timer_lock:
            for redirect_name, timer_info in list(active_timers.items()):
                if now >= timer_info.get('end_time', 0):
                    expired.append((redirect_name, timer_info.get('index')))
                    del active_timers[redirect_name]
            snapshot = {k: v.copy() for k, v in active_timers.items()}

        # 锁外：执行慢操作（firewall reload、webhook、写文件），避免阻塞 /api/redirects
        if expired:
            save_timer_state(snapshot)
            for redirect_name, redirect_index in expired:
                if redirect_index:
                    logger.info("计时器到期: '%s' (index=%s)，关闭端口", redirect_name, redirect_index)
                    toggle_redirect_enabled(redirect_index, False)
                    closed_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    send_feishu_webhook(f"""🔒 端口转发已关闭
━━━━━━━━━━━━━━━
📋 名称: {redirect_name}
🕐 关闭时间: {closed_time}
━━━━━━━━━━━━━━━""")

        time.sleep(1)

def login_page():
    return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>登录 - RDP控制器</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
        .login-box { background: #f5f5f5; padding: 30px; border-radius: 8px; }
        h2 { text-align: center; margin-top: 0; }
        input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
        button { width: 100%; padding: 10px; background: #2196F3; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #1976D2; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>RDP控制器登录</h2>
        <form method="post" action="/login">
            <input type="password" name="password" placeholder="请输入密码" required>
            <button type="submit">登录</button>
        </form>
    </div>
</body>
</html>
"""

def main_page():
    return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>RDP端口转发控制器</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 20px auto; padding: 0 20px; }
        h1 { text-align: center; color: #333; }
        .container { background: #f9f9f9; padding: 20px; border-radius: 8px; }
        .redirect-item { 
            display: flex; 
            align-items: center; 
            padding: 15px; 
            margin: 10px 0; 
            background: white; 
            border-radius: 6px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .redirect-name { 
            flex: 0 0 200px; 
            font-weight: bold; 
            font-size: 16px;
        }
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 10px;
            flex-shrink: 0;
        }
        .status-on { background-color: #4CAF50; }
        .status-off { background-color: #9E9E9E; }
        .countdown-wrapper { 
            flex: 1; 
            margin: 0 15px; 
            min-width: 200px;
        }
        .countdown-track {
            width: 100%;
            height: 20px;
            background: #e0e0e0;
            border-radius: 10px;
            overflow: hidden;
        }
        .countdown-fill {
            height: 100%;
            background: #4CAF50;
            border-radius: 10px;
            transition: width 0.3s, background 0.3s;
        }
        .countdown-time {
            text-align: center;
            margin-top: 5px;
            font-size: 14px;
            color: #666;
        }
        .btn-group { display: flex; gap: 8px; }
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            color: white;
        }
        .btn-start { background-color: #2196F3; }
        .btn-start:hover { background-color: #1976D2; }
        .btn-stop { background-color: #F44336; }
        .btn-stop:hover { background-color: #D32F2F; }
        .btn:disabled { background-color: #ccc; cursor: not-allowed; }
        .timer-input {
            width: 80px;
            padding: 6px;
            margin-right: 5px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .timer-label {
            font-size: 14px;
            color: #666;
            margin-right: 5px;
        }
        @media (max-width: 800px) {
            .redirect-item { flex-wrap: wrap; }
            .redirect-name { width: 100%; margin-bottom: 10px; flex: none; }
            .countdown-wrapper { width: 100%; margin: 10px 0; flex: none; }
            .btn-group { width: 100%; }
        }
    </style>
</head>
<body>
    <h1>端口转发控制器 <span style="font-size:14px;color:#999;">v__PKG_VERSION__</span></h1>
    <div id="wol-bar" style="text-align:center;margin:10px 0;display:none;">
        <button id="wol-btn" class="btn" style="background:#673AB7;padding:10px 22px;font-size:15px;" onclick="wakeHost()">🖥 唤醒主机</button>
        <span id="wol-mac" style="margin-left:10px;color:#888;font-size:13px;"></span>
    </div>
    <div class="container" id="redirect-list">
        加载中...
    </div>

    <script>
        let state = { redirects: [], timers: {} };
        let lastSig = '';
        let ticking = null;

        function formatTime(ms) {
            const s = Math.floor(ms / 1000);
            const m = Math.floor(s / 60);
            return m.toString().padStart(2, '0') + ':' + (s % 60).toString().padStart(2, '0');
        }
        function getColorClass(p) {
            if (p > 50) return '#4CAF50';
            if (p > 20) return '#FFC107';
            return '#F44336';
        }

        async function loadRedirects() {
            try {
                const resp = await fetch('/api/redirects', {cache: 'no-store'});
                const data = await resp.json();
                state.redirects = data.redirects || [];
                state.timers = data.timers || {};
                updateWolBar(data.wol_mac || '');
                render(false);
            } catch (e) {
                document.getElementById('redirect-list').innerHTML = '加载失败，请刷新页面';
            }
        }

        // 仅在配置了 MAC 时显示唤醒按钮
        function updateWolBar(mac) {
            const bar = document.getElementById('wol-bar');
            if (mac) {
                document.getElementById('wol-mac').textContent = '目标: ' + mac;
                bar.style.display = 'block';
            } else {
                bar.style.display = 'none';
            }
        }

        async function wakeHost() {
            const btn = document.getElementById('wol-btn');
            btn.disabled = true;
            const old = btn.textContent;
            btn.textContent = '发送中...';
            try {
                const resp = await fetch('/api/wol', {method: 'POST'});
                const data = await resp.json();
                alert(data.success ? ('✅ ' + data.message) : ('❌ ' + data.message));
            } catch (e) {
                alert('请求失败: ' + e);
            }
            btn.textContent = old;
            btn.disabled = false;
        }

        // 仅当结构（端口集合 / 是否有计时器 / 启用状态）变化时才重建 DOM，
        // 否则只更新倒计时文本 —— 避免每 5 秒轮询清空用户正在输入的分钟数
        function render(force) {
            const container = document.getElementById('redirect-list');
            if (state.redirects.length === 0) {
                container.innerHTML = '<p>没有可控制的端口转发，请先在 LuCI「端口控制 → 服务设置」中勾选并保存。</p>';
                lastSig = '';
                return;
            }
            const now = Date.now();
            const sig = state.redirects.map(r => {
                const t = state.timers[r.name];
                const live = t && (t.end_time * 1000 > now);
                return r.name + '|' + r.index + '|' + (live ? 'T' : '_') + '|' + r.enabled;
            }).join(';');

            if (force || sig !== lastSig) {
                lastSig = sig;
                let html = '';
                for (const r of state.redirects) {
                    const t = state.timers[r.name];
                    const hasTimer = t && (t.end_time * 1000 > now);
                    const on = (r.enabled === '1') || hasTimer;
                    const nm = encodeURIComponent(r.name);
                    let mid;
                    if (hasTimer) {
                        mid = `<div class="countdown-wrapper" style="display:flex;flex-direction:column;">
                                 <div class="countdown-track"><div class="countdown-fill" id="fill-${nm}"></div></div>
                                 <div class="countdown-time" id="time-${nm}"></div>
                               </div>`;
                    } else {
                        mid = `<div class="countdown-wrapper">
                                 <span class="timer-label">倒计时</span>
                                 <input type="number" class="timer-input" id="minutes-${nm}" min="1" value="30">
                                 <span class="timer-label">分钟</span>
                               </div>`;
                    }
                    html += `<div class="redirect-item">
                        <span class="status-indicator ${on ? 'status-on' : 'status-off'}"></span>
                        <div class="redirect-name">${r.name}</div>
                        ${mid}
                        <div class="btn-group">
                            <button class="btn btn-start" ${hasTimer ? 'disabled' : ''} onclick="startTimer('${nm}','${r.index}')">倒计时开启</button>
                            <button class="btn btn-stop" ${hasTimer ? '' : 'disabled'} onclick="stopTimer('${nm}','${r.index}')">立刻结束</button>
                        </div>
                    </div>`;
                }
                container.innerHTML = html;
            }
            tick();
        }

        // 仅刷新倒计时显示。到点后只触发一次同步（_synced 去重），
        // 不在此处递归 render/删除，避免轮询风暴导致页面卡死。
        function tick() {
            const now = Date.now();
            let needSync = false;
            for (const name of Object.keys(state.timers)) {
                const t = state.timers[name];
                const nm = encodeURIComponent(name);
                const fill = document.getElementById('fill-' + nm);
                const time = document.getElementById('time-' + nm);
                const total = t.end_time * 1000 - t.start_time * 1000;
                const remaining = Math.max(0, t.end_time * 1000 - now);
                if (fill && time) {
                    const percent = total > 0 ? (remaining / total) * 100 : 0;
                    fill.style.width = percent + '%';
                    fill.style.background = getColorClass(percent);
                    time.textContent = formatTime(remaining);
                }
                if (remaining <= 0 && !t._synced) {
                    t._synced = true;       // 仅同步一次，等服务器确认关闭后移除
                    needSync = true;
                }
            }
            if (needSync) loadRedirects();
        }
        function ensureTicking() {
            if (!ticking) ticking = setInterval(tick, 1000);
        }

        async function startTimer(encodedName, index) {
            const name = decodeURIComponent(encodedName);
            const input = document.getElementById('minutes-' + encodedName);
            const minutes = (input && parseInt(input.value)) || 30;
            // 乐观更新：立即本地显示倒计时，无需等待服务器
            const now = Date.now() / 1000;
            state.timers[name] = { index: index, start_time: now, end_time: now + minutes * 60 };
            render(true);
            try {
                const resp = await fetch('/api/timer/start', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ name: name, index: index, minutes: minutes })
                });
                const data = await resp.json();
                if (data.success) {
                    loadRedirects();      // 用服务器真实时间校准
                } else {
                    delete state.timers[name];
                    render(true);
                    alert('开启失败: ' + (data.message || '未知错误'));
                }
            } catch (e) {
                delete state.timers[name];
                render(true);
                alert('请求失败: ' + e);
            }
        }

        async function stopTimer(encodedName, index) {
            const name = decodeURIComponent(encodedName);
            delete state.timers[name];   // 乐观移除
            render(true);
            try {
                const resp = await fetch('/api/timer/stop', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ name: name, index: index })
                });
                const data = await resp.json();
                if (!data.success) alert('结束失败: ' + (data.message || ''));
            } catch (e) {
                alert('请求失败: ' + e);
            }
            loadRedirects();
        }

        loadRedirects();
        ensureTicking();
        setInterval(loadRedirects, 5000);
    </script>
</body>
</html>
"""

class RequestHandler(BaseHTTPRequestHandler):
    session_cookies = {}
    
    def check_auth(self):
        auth_enabled = uci_get('rdp_controller', 'main', 'auth_enabled', '0') == '1'
        if not auth_enabled:
            return True
        
        cookie_header = self.headers.get('Cookie', '')
        cookies = {}
        if cookie_header:
            for cookie in cookie_header.split(';'):
                name, value = cookie.strip().split('=', 1)
                cookies[name] = value
        
        expected = hashlib.sha256(uci_get('rdp_controller', 'main', 'password', '').encode()).hexdigest()
        return cookies.get('rdp_auth') == expected
    
    def do_GET(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        
        if path == '/':
            if not self.check_auth():
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write(login_page().encode('utf-8'))
                return
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(main_page().encode('utf-8'))
        
        elif path == '/api/redirects':
            payload = build_redirects_payload()
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode('utf-8'))

        elif path == '/api/webhook/test':
            # LuCI 测试按钮用 wget(GET) 触发，这里也要受理
            test_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ok = send_feishu_webhook(f"🔔 Port-Control 测试通知: {test_time}")
            msg = '测试消息已发送' if ok else '发送失败：请确认已勾选启用、填写正确的 Webhook 地址并已保存'
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'success': ok, 'message': msg}).encode('utf-8'))

        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Not Found')

    def do_POST(self):
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        if path == '/login':
            params = parse_qs(post_data.decode('utf-8'))
            password = params.get('password', [''])[0]
            correct = uci_get('rdp_controller', 'main', 'password', '')
            
            if password == correct:
                hash_val = hashlib.sha256(correct.encode()).hexdigest()
                self.send_response(302)
                self.send_header('Location', '/')
                self.send_header('Set-Cookie', f'rdp_auth={hash_val}; Max-Age=86400; Path=/')
                self.end_headers()
            else:
                self.send_response(200)
                self.send_header('Content-type', 'text/html; charset=utf-8')
                self.end_headers()
                self.wfile.write((login_page() + '<p style="color:red;text-align:center;">密码错误</p>').encode('utf-8'))
        
        elif path == '/api/timer/start':
            if not self.check_auth():
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': False, 'message': '未授权'}).encode('utf-8'))
                return
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                name = data.get('name')
                index = data.get('index')
                minutes = data.get('minutes', 30)
                logger.info("timer/start name=%r index=%r minutes=%r", name, index, minutes)

                if not name or index is None:
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'success': False, 'message': '参数错误'}).encode('utf-8'))
                    return
                
                now = time.time()
                end_time = now + (minutes * 60)
                
                with timer_lock:
                    active_timers[name] = {
                        'index': index,
                        'start_time': now,
                        'end_time': end_time
                    }
                    snapshot = {k: v.copy() for k, v in active_timers.items()}
                save_timer_state(snapshot)

                toggle_redirect_enabled(index, True)
                
                start_time_str = datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S')
                end_time_str = datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S')
                
                send_feishu_webhook(f"""🔓 端口转发已开启
━━━━━━━━━━━━━━━
📋 名称: {name}
⏰ 开始时间: {start_time_str}
⏰ 结束时间: {end_time_str}
━━━━━━━━━━━━━━━""")
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': True}).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': False, 'message': str(e)}).encode('utf-8'))
        
        elif path == '/api/timer/stop':
            if not self.check_auth():
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': False, 'message': '未授权'}).encode('utf-8'))
                return
            
            try:
                data = json.loads(post_data.decode('utf-8'))
                name = data.get('name')
                index = data.get('index')
                
                if not name or index is None:
                    self.send_response(400)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'success': False, 'message': '参数错误'}).encode('utf-8'))
                    return
                
                with timer_lock:
                    active_timers.pop(name, None)
                    snapshot = {k: v.copy() for k, v in active_timers.items()}
                save_timer_state(snapshot)

                # 立刻结束：同时关闭该端口转发
                toggle_redirect_enabled(index, False)
                
                closed_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                send_feishu_webhook(f"""🔒 端口转发已关闭
━━━━━━━━━━━━━━━
📋 名称: {name}
🕐 关闭时间: {closed_time}
━━━━━━━━━━━━━━━""")
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': True}).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': False, 'message': str(e)}).encode('utf-8'))
        
        elif path == '/api/webhook/test':
            test_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            success = send_feishu_webhook(f"🔔 测试消息: {test_time}")

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            if success:
                self.wfile.write(json.dumps({'success': True, 'message': '测试消息发送成功'}).encode('utf-8'))
            else:
                self.wfile.write(json.dumps({'success': False, 'message': '测试消息发送失败，请检查配置'}).encode('utf-8'))

        elif path == '/api/wol':
            if not self.check_auth():
                self.send_response(401)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'success': False, 'message': '未授权'}).encode('utf-8'))
                return
            mac = uci_get('rdp_controller', 'main', 'wol_mac', '')
            if not mac:
                ok, message = False, '未配置唤醒 MAC 地址，请先在 LuCI 中填写'
            else:
                ok, message = send_wol(mac)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'success': ok, 'message': message}).encode('utf-8'))

        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Not Found')
    
    def log_message(self, format, *args):
        logger.info("[%s] %s", self.address_string(), format % args)

def main():
    # 日志开关：settings.log_enabled 为 0 时关闭记录
    if uci_get('rdp_controller', 'settings', 'log_enabled', '1') != '1':
        logger.setLevel(logging.CRITICAL)

    port = int(uci_get('rdp_controller', 'main', 'port', '8080'))
    logger.info("=== rdp_controller starting on 0.0.0.0:%d ===", port)

    threading.Thread(target=timer_thread, daemon=True).start()

    server = ThreadedHTTPServer(('0.0.0.0', port), RequestHandler)
    logger.info("Server ready, log: %s", LOG_FILE)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopping")
        server.shutdown()

if __name__ == '__main__':
    main()
