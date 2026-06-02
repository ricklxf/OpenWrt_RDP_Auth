#!/usr/bin/env python3

import subprocess
import json
import re
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
import logging.handlers
LOG_FILE = '/var/log/rdp_controller.log'
_fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s', '%Y-%m-%d %H:%M:%S')
logger = logging.getLogger('rdp_controller')
logger.setLevel(logging.INFO)
try:
    # WatchedFileHandler：当日志文件被删除时，下次写入自动重建，
    # 这样 LuCI 上「删除日志」后服务仍能继续记录。
    _fh = logging.handlers.WatchedFileHandler(LOG_FILE)
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
DOC_CONFIG = '/etc/rdp_controller.conf'   # 带注释的配置说明文件（自动生成）

active_timers = {}
timer_lock = threading.Lock()
# 串行化所有防火墙操作：避免多线程并发 `firewall reload` 撑爆内存导致路由器卡死/重启
firewall_lock = threading.Lock()

def run_cmd(cmd, timeout=30):
    """执行外部命令，带超时与异常保护，绝不让线程无限挂起。"""
    try:
        subprocess.run(cmd, check=False, timeout=timeout,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        logger.error("命令超时(%ss): %s", timeout, ' '.join(cmd))
    except Exception as e:
        logger.error("命令执行失败 %s: %s", ' '.join(cmd), e)

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
            run_cmd(['conntrack', '-D', '-p', p, '--orig-port-dst', str(src_dport)], 10)
        # 删除指向内部目标（DNAT 后）的连接，覆盖回复方向
        if dest_ip and dest_port:
            run_cmd(['conntrack', '-D', '-p', p, '-d', str(dest_ip), '--dport', str(dest_port)], 10)
    logger.info("已清除 conntrack 连接: proto=%s src_dport=%s dest=%s:%s",
                protos, src_dport, dest_ip, dest_port)

def apply_redirect_states(changes):
    """批量设置多个 redirect 的 enabled 状态，全程持锁且只 reload 一次。

    changes: [(secid, enabled_bool), ...]
    防火墙操作必须串行：并发 `firewall reload` 会瞬间占用大量内存，
    低内存设备上可能 OOM 直接重启。
    """
    if not changes:
        return
    with firewall_lock:
        for secid, en in changes:
            run_cmd(['uci', 'set', f'firewall.{secid}.enabled={"1" if en else "0"}'], 10)
        run_cmd(['uci', 'commit', 'firewall'], 15)
        run_cmd(['/etc/init.d/firewall', 'reload'], 60)
    for secid, en in changes:
        logger.info("redirect %s -> enabled=%s", secid, '1' if en else '0')

def toggle_redirect_enabled(secid, enabled):
    # 关闭前先取规则详情（此时字段仍可读），用于断开已建立连接
    redirect = None if enabled else get_redirect_by_secid(secid)
    apply_redirect_states([(secid, enabled)])
    if not enabled and redirect:
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
    wol_ip  = uci_get('rdp_controller', 'main', 'wol_ip',  '')
    logger.info("payload redirects=%r controlled=%r timers=%r",
                [x['name'] for x in result], controlled, list(timers_copy.keys()))
    return {'redirects': result, 'timers': timers_copy, 'wol_mac': wol_mac, 'wol_ip': wol_ip}

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
    """发送飞书通知。返回 (是否成功, 说明文本)。

    飞书自定义机器人即使逻辑失败也返回 HTTP 200，需解析 body 里的
    code/StatusCode 才能判断是否真的成功（如开启签名校验会返回错误码）。
    """
    enabled = uci_get('rdp_controller', 'webhook', 'enabled', '0')
    url = uci_get('rdp_controller', 'webhook', 'url', '')
    keyword = uci_get('rdp_controller', 'webhook', 'keyword', '')

    if enabled != '1':
        logger.warning("飞书通知未启用 (enabled=%r)，跳过发送", enabled)
        return False, '飞书通知未启用'
    if not url:
        logger.warning("飞书 Webhook 地址为空，跳过发送")
        return False, 'Webhook 地址为空'

    # 机器人开启「自定义关键词」校验时，消息必须包含该关键词，否则飞书报 19024
    if keyword and keyword not in message:
        message = f"【{keyword}】\n{message}"

    try:
        import urllib.request
        payload = json.dumps({'msg_type': 'text', 'content': {'text': message}}).encode('utf-8')
        req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=8) as response:
            body = response.read().decode('utf-8', 'ignore')
            logger.info("飞书响应 status=%s body=%s", response.status, body[:300])
            try:
                j = json.loads(body)
            except Exception:
                # 无法解析则以 HTTP 状态码为准
                return (response.status == 200), f'HTTP {response.status}'
            # 成功：StatusCode==0（旧接口）或 code==0（新接口）
            if j.get('StatusCode') == 0 or j.get('code') == 0:
                return True, '发送成功'
            err = j.get('msg') or j.get('StatusMessage') or body[:120]
            logger.warning("飞书返回错误: %s", err)
            return False, f'飞书拒绝: {err}'
    except Exception as e:
        logger.error("飞书 Webhook 请求失败: %s", e)
        return False, f'请求失败: {e}'

def save_timer_state(snapshot):
    """把计时器快照写入磁盘。snapshot 由调用方在锁内复制好，
    本函数不再获取 timer_lock —— 之前在持锁上下文里再次抢锁会死锁。"""
    persist = uci_get('rdp_controller', 'main', 'persist_on_restart', '1') == '1'
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
        # 整个循环体用 try 兜底：任何异常都不应让计时线程退出
        try:
            now = time.time()
            expired = []

            # 锁内：只做到期判断、移除、快照（全是快速内存操作）
            with timer_lock:
                for redirect_name, timer_info in list(active_timers.items()):
                    if now >= timer_info.get('end_time', 0):
                        expired.append((redirect_name, timer_info.get('index')))
                        del active_timers[redirect_name]
                snapshot = {k: v.copy() for k, v in active_timers.items()}

            # 锁外执行慢操作；多个到期的端口合并为一次 firewall reload
            if expired:
                save_timer_state(snapshot)
                changes = [(idx, False) for _, idx in expired if idx]
                redirects = {idx: get_redirect_by_secid(idx) for _, idx in expired if idx}
                apply_redirect_states(changes)
                for redirect_name, redirect_index in expired:
                    if redirect_index:
                        logger.info("计时器到期: '%s' (index=%s)，关闭端口", redirect_name, redirect_index)
                        r = redirects.get(redirect_index)
                        if r:
                            cut_connections(r)
                        closed_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        send_feishu_webhook(f"""🔒 端口转发已关闭
━━━━━━━━━━━━━━━
📋 名称: {redirect_name}
🕐 关闭时间: {closed_time}
━━━━━━━━━━━━━━━""")
        except Exception as e:
            logger.error("计时线程异常(已忽略继续运行): %s", e)

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
    <div id="err-bar" style="display:none;background:#ffebee;color:#c62828;padding:8px 16px;border-radius:4px;margin:8px 0;text-align:center;font-size:14px;"></div>
    <div id="wol-bar" style="text-align:center;margin:10px 0;display:none;">
        <button id="wol-btn" class="btn" style="background:#673AB7;padding:10px 22px;font-size:15px;display:none;" onclick="wakeHost()">🖥 唤醒主机</button>
        <span id="wol-mac" style="margin-left:10px;color:#888;font-size:13px;"></span>
        <span id="ping-wrap" style="display:none;">
            <button id="ping-btn" class="btn" style="background:#0288D1;padding:10px 16px;font-size:14px;margin-left:10px;" onclick="pingHost()">🔍 检查在线状态</button>
            <span id="ping-status" style="margin-left:8px;font-size:13px;color:#888;"></span>
        </span>
    </div>
    <div class="container" id="redirect-list">
        加载中...
    </div>

    <script>
        let state = { redirects: [], timers: {}, wol_mac: '', wol_ip: '' };
        let lastSig = '';
        let ticking = null;
        // busySet：请求飞行中时禁止同一项目重复点击，防止连环 alert 弹窗
        const busySet = new Set();
        let _errTimer = null;
        function showError(msg) {
            const el = document.getElementById('err-bar');
            if (!el) return;
            el.textContent = msg;
            el.style.display = 'block';
            clearTimeout(_errTimer);
            _errTimer = setTimeout(() => { el.style.display = 'none'; }, 5000);
        }

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
                state.wol_mac = data.wol_mac || '';
                state.wol_ip  = data.wol_ip  || '';
                updateWolBar(state.wol_mac, state.wol_ip);
                render(false);
            } catch (e) {
                // firewall reload 期间可能短暂断连，轮询静默失败，保留当前显示
            }
        }

        function updateWolBar(mac, ip) {
            const bar     = document.getElementById('wol-bar');
            const wolBtn  = document.getElementById('wol-btn');
            const pingWrap= document.getElementById('ping-wrap');
            wolBtn.style.display = mac ? '' : 'none';
            document.getElementById('wol-mac').textContent = mac ? '目标: ' + mac : '';
            pingWrap.style.display = ip ? '' : 'none';
            bar.style.display = (mac || ip) ? 'block' : 'none';
        }

        async function pingHost() {
            const btn    = document.getElementById('ping-btn');
            const status = document.getElementById('ping-status');
            btn.disabled = true;
            status.textContent  = '检测中...';
            status.style.color  = '#888';
            try {
                const resp = await fetch('/api/ping', {cache: 'no-store'});
                const data = await resp.json();
                status.textContent = data.message;
                status.style.color = data.online ? '#4CAF50' : '#F44336';
            } catch (e) {
                status.textContent = '请求失败';
                status.style.color = '#F44336';
            }
            btn.disabled = false;
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
                    const busy = busySet.has(r.name);
                    html += `<div class="redirect-item">
                        <span class="status-indicator ${on ? 'status-on' : 'status-off'}"></span>
                        <div class="redirect-name">${r.name}</div>
                        ${mid}
                        <div class="btn-group">
                            <button class="btn btn-start" ${(hasTimer || busy) ? 'disabled' : ''} onclick="startTimer('${nm}','${r.index}')">倒计时开启</button>
                            <button class="btn btn-stop" ${(!hasTimer || busy) ? 'disabled' : ''} onclick="stopTimer('${nm}','${r.index}')">立刻结束</button>
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
            if (busySet.has(name)) return;   // 防重复点击
            busySet.add(name);
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
                    showError('开启失败: ' + (data.message || '未知错误'));
                }
            } catch (e) {
                // firewall reload 期间连接可能短暂中断，2s 后自动重试同步
                delete state.timers[name];
                showError('请求失败，服务可能正忙，稍后自动同步');
                setTimeout(loadRedirects, 2000);
            } finally {
                busySet.delete(name);
                render(true);
            }
        }

        async function stopTimer(encodedName, index) {
            const name = decodeURIComponent(encodedName);
            if (busySet.has(name)) return;   // 防重复点击
            busySet.add(name);
            const prevTimer = state.timers[name];
            delete state.timers[name];   // 乐观移除
            render(true);
            try {
                const resp = await fetch('/api/timer/stop', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ name: name, index: index })
                });
                const data = await resp.json();
                if (!data.success) showError('结束失败: ' + (data.message || ''));
            } catch (e) {
                state.timers[name] = prevTimer;   // 请求失败时还原乐观更新
                showError('请求失败，服务可能正忙，稍后自动同步');
            } finally {
                busySet.delete(name);
                render(true);
                setTimeout(loadRedirects, 500);
            }
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
            ok, msg = send_feishu_webhook(f"🔔 Port-Control 测试通知: {test_time}")
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'success': ok, 'message': msg}).encode('utf-8'))

        elif path == '/api/ping':
            ip = uci_get('rdp_controller', 'main', 'wol_ip', '')
            if not ip:
                result = {'success': False, 'online': False, 'message': '未配置目标 IP，请在 LuCI 中填写唤醒主机 IP 地址'}
            else:
                try:
                    r = subprocess.run(
                        ['ping', '-c', '1', '-W', '1', ip],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        text=True, timeout=5
                    )
                    if r.returncode == 0:
                        m = re.search(r'time[=<](\d+\.?\d*)\s*ms', r.stdout)
                        rtt = m.group(1) if m else '?'
                        result = {'success': True, 'online': True, 'message': f'在线  延迟 {rtt} ms', 'ip': ip}
                    else:
                        result = {'success': True, 'online': False, 'message': '不在线（ping 超时或无法到达）', 'ip': ip}
                except Exception as e:
                    result = {'success': False, 'online': False, 'message': f'ping 失败: {e}', 'ip': ip}
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))

        elif path == '/api/stop_all':
            # 清空所有计时器
            with timer_lock:
                cleared_count = len(active_timers)
                active_timers.clear()
            save_timer_state({})
            # 关闭所有受控端口转发
            controlled_names = set(get_controllable_redirects())
            all_r = get_all_redirects()
            changes = [(r['index'], False) for r in all_r if r.get('name') in controlled_names]
            to_cut  = [r for r in all_r if r.get('name') in controlled_names]
            if changes:
                apply_redirect_states(changes)
                for r in to_cut:
                    cut_connections(r)
            logger.info("stop_all: 清除 %d 个计时器，关闭 %d 个端口转发", cleared_count, len(changes))
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(
                {'success': True, 'message': f'已清除 {cleared_count} 个计时器，关闭 {len(changes)} 个端口转发'}
            ).encode('utf-8'))

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
            success, message = send_feishu_webhook(f"🔔 测试消息: {test_time}")
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'success': success, 'message': message}).encode('utf-8'))

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

def write_config_doc():
    """生成带详细注释的配置说明文件。

    实际生效配置由 LuCI/UCI 管理（/etc/config/rdp_controller，UCI 提交时会丢注释），
    本文件在每次保存导致服务重启时自动重新生成，供查阅当前配置。
    """
    def g(opt, d=''):
        return uci_get('rdp_controller', 'main', opt, d)
    def w(opt, d=''):
        return uci_get('rdp_controller', 'webhook', opt, d)
    try:
        content = f"""# =====================================================================
# Port-Control 配置说明（本文件自动生成，手动修改无效）
# 实际生效配置: /etc/config/rdp_controller  （请在 LuCI「服务 → 端口控制」修改）
# 每次在 LuCI 保存并应用后，本文件会自动重新生成
# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
# =====================================================================

## 基本设置 ##
# 是否启用插件          1=启用  0=禁用
enabled            = {g('enabled', '1')}
# Web 管理界面端口
port               = {g('port', '8080')}
# 是否启用密码登录      1=启用  0=禁用
auth_enabled       = {g('auth_enabled', '0')}
# 访问密码（启用密码登录时生效）
password           = {'******（已设置）' if g('password') else '（未设置）'}

## 网络唤醒（Wake-on-LAN） ##
# 目标主机 MAC，填写后管理页出现「唤醒主机」按钮，格式 AA:BB:CC:DD:EE:FF
wol_mac            = {g('wol_mac') or '（未设置）'}
# 目标主机 IP，填写后管理页出现「检查在线状态」按钮（ping 一次）
wol_ip             = {g('wol_ip') or '（未设置）'}

## 飞书通知 ##
# 是否启用飞书通知      1=启用  0=禁用
webhook_enabled    = {w('enabled', '0')}
# 飞书自定义机器人 Webhook 地址
webhook_url        = {w('url') or '（未设置）'}
# 安全关键词：若机器人开启「自定义关键词」校验，须填其中一个关键词，
#            否则飞书拒收并报错 19024 Key Words Not Found
webhook_keyword    = {w('keyword') or '（未设置）'}

## 日志与计时 ##
# 是否记录运行日志      1=启用  0=禁用
log_enabled        = {g('log_enabled', '1')}
# OpenWrt 重启后是否保持倒计时   1=是  0=否
persist_on_restart = {g('persist_on_restart', '1')}

## 相关文件 ##
# 受控端口转发规则: /etc/config/firewall （仅修改其 enabled 状态）
# 运行日志:        /var/log/rdp_controller.log
# 倒计时持久化:     /tmp/rdp_timers.json
"""
        with open(DOC_CONFIG, 'w') as f:
            f.write(content)
        logger.info("已生成配置说明文件: %s", DOC_CONFIG)
    except OSError as e:
        logger.error("写配置说明文件失败: %s", e)

def main():
    # 日志开关：main.log_enabled 为 0 时关闭记录
    if uci_get('rdp_controller', 'main', 'log_enabled', '1') != '1':
        logger.setLevel(logging.CRITICAL)

    write_config_doc()

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
