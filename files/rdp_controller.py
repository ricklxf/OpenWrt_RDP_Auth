#!/usr/bin/env python3

import subprocess
import json
import time
import os
import sys
import logging
from datetime import datetime
import threading
import hashlib
import socket
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote

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
    redirects = []
    uci_output = uci_show('firewall')
    
    current_redirect = None
    for line in uci_output.split('\n'):
        line = line.strip()
        if line.startswith('firewall.@redirect['):
            if current_redirect:
                redirects.append(current_redirect)
            current_redirect = {'index': line.split('[')[1].split(']')[0]}
        elif '=' in line and current_redirect is not None:
            key, value = line.split('=', 1)
            key = key.split('.')[-1]
            value = value.strip('\'')
            current_redirect[key] = value
    
    if current_redirect:
        redirects.append(current_redirect)
    
    return redirects

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

def toggle_redirect_enabled(index, enabled):
    state = '1' if enabled else '0'
    subprocess.run(['uci', 'set', f'firewall.@redirect[{index}].enabled={state}'], check=False)
    subprocess.run(['uci', 'commit', 'firewall'], check=False)
    subprocess.run(['/etc/init.d/firewall', 'reload'], check=False)

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

def save_timer_state():
    persist = uci_get('rdp_controller', 'settings', 'persist_on_restart', '1') == '1'
    if persist:
        with timer_lock:
            with open(TIMER_STATE_FILE, 'w') as f:
                json.dump(active_timers, f)

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
        to_remove = []
        
        with timer_lock:
            for redirect_name, timer_info in list(active_timers.items()):
                end_time = timer_info.get('end_time', 0)
                if now >= end_time:
                    redirect_index = timer_info.get('index')
                    if redirect_index:
                        logger.info("Timer expired: '%s' (index=%s), disabling", redirect_name, redirect_index)
                        toggle_redirect_enabled(redirect_index, False)

                        closed_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        send_feishu_webhook(f"""🔒 端口转发已关闭
━━━━━━━━━━━━━━━
📋 名称: {redirect_name}
🕐 关闭时间: {closed_time}
━━━━━━━━━━━━━━━""")
                    
                    to_remove.append(redirect_name)
            
            for name in to_remove:
                del active_timers[name]
            
            if to_remove:
                save_timer_state()
        
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
    <h1>端口转发控制器</h1>
    <div class="container" id="redirect-list">
        加载中...
    </div>
    
    <script>
        function formatTime(ms) {
            const seconds = Math.floor(ms / 1000);
            const mins = Math.floor(seconds / 60);
            const secs = seconds % 60;
            return mins.toString().padStart(2, '0') + ':' + secs.toString().padStart(2, '0');
        }
        
        function getColorClass(percent) {
            if (percent > 50) return '#4CAF50';
            if (percent > 20) return '#FFC107';
            return '#F44336';
        }
        
        async function loadRedirects() {
            try {
                const resp = await fetch('/api/redirects');
                const data = await resp.json();
                renderRedirects(data);
            } catch (e) {
                document.getElementById('redirect-list').innerHTML = '加载失败';
            }
        }
        
        function renderRedirects(data) {
            const container = document.getElementById('redirect-list');
            
            if (data.redirects.length === 0) {
                container.innerHTML = '<p>没有可控制的端口转发，请先在LuCI配置中选择。</p>';
                return;
            }
            
            let html = '';
            for (const r of data.redirects) {
                const statusClass = r.enabled === '1' ? 'status-on' : 'status-off';
                const hasTimer = data.timers[r.name] !== undefined;
                let timerHtml = '';
                
                if (hasTimer) {
                    const timer = data.timers[r.name];
                    const now = Date.now();
                    const total = timer.end_time * 1000 - timer.start_time * 1000;
                    const remaining = Math.max(0, timer.end_time * 1000 - now);
                    const percent = (remaining / total) * 100;
                    
                    timerHtml = `
                        <div class="countdown-wrapper">
                            <div class="countdown-track">
                                <div class="countdown-fill" id="fill-${encodeURIComponent(r.name)}" 
                                    style="width: ${percent}%; background: ${getColorClass(percent)};"></div>
                            </div>
                            <div class="countdown-time" id="time-${encodeURIComponent(r.name)}">${formatTime(remaining)}</div>
                        </div>
                    `;
                } else {
                    timerHtml = `
                        <div class="countdown-wrapper">
                            <span class="timer-label">倒计时</span>
                            <input type="number" class="timer-input" id="minutes-${encodeURIComponent(r.name)}" min="1" value="30" placeholder="分钟">
                        </div>
                    `;
                }
                
                html += `
                    <div class="redirect-item">
                        <span class="status-indicator ${statusClass}"></span>
                        <div class="redirect-name">${r.name}</div>
                        ${timerHtml}
                        <div class="btn-group">
                            <button class="btn btn-start" onclick="startTimer('${encodeURIComponent(r.name)}', '${r.index}')" 
                                    ${hasTimer ? 'disabled' : ''}>
                                倒计时开启
                            </button>
                            <button class="btn btn-stop" onclick="stopTimer('${encodeURIComponent(r.name)}', '${r.index}')" 
                                    ${!hasTimer ? 'disabled' : ''}>
                                立刻结束
                            </button>
                        </div>
                    </div>
                `;
            }
            
            container.innerHTML = html;
            
            if (Object.keys(data.timers).length > 0) {
                updateTimers(data.timers);
            }
        }
        
        function updateTimers(timers) {
            const interval = setInterval(() => {
                const now = Date.now();
                let allExpired = true;
                
                for (const [name, timer] of Object.entries(timers)) {
                    const fillEl = document.getElementById(`fill-${encodeURIComponent(name)}`);
                    const timeEl = document.getElementById(`time-${encodeURIComponent(name)}`);
                    
                    if (fillEl && timeEl) {
                        const total = timer.end_time * 1000 - timer.start_time * 1000;
                        const remaining = Math.max(0, timer.end_time * 1000 - now);
                        const percent = (remaining / total) * 100;
                        
                        fillEl.style.width = percent + '%';
                        fillEl.style.background = getColorClass(percent);
                        timeEl.textContent = formatTime(remaining);
                        
                        if (remaining > 0) allExpired = false;
                    }
                }
                
                if (allExpired) {
                    clearInterval(interval);
                    loadRedirects();
                }
            }, 1000);
        }
        
        async function startTimer(encodedName, index) {
            const name = decodeURIComponent(encodedName);
            const minutes = parseInt(document.getElementById(`minutes-${encodedName}`).value) || 30;
            
            try {
                const resp = await fetch('/api/timer/start', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({name: name, index: index, minutes: minutes})
                });
                const data = await resp.json();
                
                if (data.success) {
                    loadRedirects();
                } else {
                    alert('操作失败: ' + data.message);
                }
            } catch (e) {
                alert('请求失败');
            }
        }
        
        async function stopTimer(encodedName, index) {
            const name = decodeURIComponent(encodedName);
            
            try {
                const resp = await fetch('/api/timer/stop', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({name: name, index: index})
                });
                const data = await resp.json();
                
                if (data.success) {
                    loadRedirects();
                } else {
                    alert('操作失败: ' + data.message);
                }
            } catch (e) {
                alert('请求失败');
            }
        }
        
        loadRedirects();
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
            all_redirects = get_all_redirects()
            controlled_names = get_controllable_redirects()
            logger.info("防火墙规则名: %r / 受控名: %r",
                        [r.get('name') for r in all_redirects], controlled_names)

            result = []
            for r in all_redirects:
                name = r.get('name', '未命名')
                if name in controlled_names:
                    result.append({
                        'name': name,
                        'index': r.get('index'),
                        'enabled': r.get('enabled', '0')
                    })
            
            with timer_lock:
                timers_copy = {k: v.copy() for k, v in active_timers.items()}
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'redirects': result, 'timers': timers_copy}).encode('utf-8'))
        
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
                    save_timer_state()
                
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
                    if name in active_timers:
                        del active_timers[name]
                        save_timer_state()
                
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
        
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Not Found')
    
    def log_message(self, format, *args):
        logger.info("[%s] %s", self.address_string(), format % args)

def main():
    port = int(uci_get('rdp_controller', 'main', 'port', '8080'))
    logger.info("=== rdp_controller starting on 0.0.0.0:%d ===", port)

    threading.Thread(target=timer_thread, daemon=True).start()

    server = HTTPServer(('0.0.0.0', port), RequestHandler)
    logger.info("Server ready, log: %s", LOG_FILE)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopping")
        server.shutdown()

if __name__ == '__main__':
    main()
