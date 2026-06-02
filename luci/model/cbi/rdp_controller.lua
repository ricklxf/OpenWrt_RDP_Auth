local luci_sys = require "luci.sys"
local uci = require("luci.model.uci").cursor()

local STATUS_FILE = "/tmp/rdp_status.cache"

-- 获取 LAN IP
local function get_lan_ip()
    local ip = luci_sys.exec("uci get network.lan.ipaddr 2>/dev/null"):gsub("[%s\n]+", "")
    if ip == "" then
        ip = luci_sys.exec(
            "ip -4 addr show br-lan 2>/dev/null | grep -oE '([0-9]{1,3}\\.){3}[0-9]{1,3}' | head -1"
        ):gsub("[%s\n]+", "")
    end
    return (ip ~= "" and ip) or "192.168.1.1"
end

-- 后台完整地址
local function get_admin_url()
    local port = uci:get("rdp_controller", "main", "port") or "8080"
    return "http://" .. get_lan_ip() .. ":" .. port
end

-- 服务是否运行（用 pgrep，比 status 可靠）
local function svc_running()
    return luci_sys.call("pgrep -f /usr/bin/rdp_controller.py >/dev/null 2>&1") == 0
end

-- 刷新状态到缓存文件（只在按钮点击/保存时调用）
local function refresh_status()
    local running = svc_running()
    local t = os.date("%Y-%m-%d %H:%M:%S")
    local f = io.open(STATUS_FILE, "w")
    if f then
        f:write(running and "1\n" or "0\n")
        f:write(t .. "\n")
        f:close()
    end
end

-- 读取缓存状态，返回 running(bool 或 nil), 检测时间
local function read_status()
    local f = io.open(STATUS_FILE, "r")
    if not f then return nil, nil end
    local running = f:read("*l")
    local t = f:read("*l")
    f:close()
    return (running == "1"), t
end

-- ─────────────────────────────────────────────────────────────────────────────
m = Map("rdp_controller", translate("端口控制") .. " v__PKG_VERSION__",
    translate("管理端口转发规则与倒计时"))

-- 保存并应用后，刷新服务状态
function m.on_commit(self)
    luci_sys.call("sleep 2")
    refresh_status()
end

-- ══════════════════════════════════════════
-- 服务状态
-- ══════════════════════════════════════════
s0 = m:section(NamedSection, "main", "rdp_controller", translate("服务状态"))
s0.addremove = false
s0.anonymous = true

-- 运行状态（只读缓存，不自动检测）
local sv = s0:option(DummyValue, "_svc_status", translate("运行状态"))
sv.rawhtml = true
function sv.cfgvalue(self, section)
    local running, t = read_status()
    if running == nil then
        return "<span style='color:#9E9E9E'>● 未检测 —— 请点击下方「状态检测」</span>"
    end
    local badge = running
        and "<b style='color:#4CAF50'>● 运行中</b>"
        or  "<b style='color:#f44336'>● 已停止</b>"
    return badge .. "  <span style='color:#999'>(检测于 " .. (t or "") .. ")</span>"
end

-- 管理地址（可点击链接）
local lv = s0:option(DummyValue, "_svc_url", translate("管理地址"))
lv.rawhtml = true
function lv.cfgvalue(self, section)
    local url = get_admin_url()
    return string.format(
        "<a href='%s' target='_blank' style='color:#1976D2;font-weight:bold'>%s &#x2197;</a>",
        url, url
    )
end

-- 配置文件路径提示
local cf = s0:option(DummyValue, "_cfg_path", translate("配置文件"))
cf.rawhtml = true
function cf.cfgvalue(self, section)
    return "实际配置: <code>/etc/config/rdp_controller</code><br/>" ..
           "带注释说明: <code>/etc/rdp_controller.conf</code> " ..
           "<span style='color:#999'>（保存后自动生成，仅供查阅）</span>"
end

-- 端口转发规则列表
local pv = s0:option(DummyValue, "_fw_ports", translate("端口转发规则"))
pv.rawhtml = true
function pv.cfgvalue(self, section)
    local out = {}
    uci:foreach("firewall", "redirect", function(r)
        if r.name then
            local en   = (r.enabled ~= "0")
            local col  = en and "#4CAF50" or "#9E9E9E"
            local sym  = en and "✓" or "○"
            local port = r.src_dport and (":" .. r.src_dport) or ""
            table.insert(out, string.format(
                "<span style='color:%s;margin-right:14px'>%s %s%s</span>",
                col, sym, r.name, port
            ))
        end
    end)
    if #out == 0 then
        return "<span style='color:#9E9E9E'>" .. translate("（暂无端口转发规则）") .. "</span>"
    end
    return table.concat(out, "")
end

-- 状态检测按钮
local cb = s0:option(Button, "_check_btn", translate("&nbsp;"))
cb.inputtitle = translate("🔍 状态检测")
cb.inputstyle = "reload"
function cb.write(self, section)
    refresh_status()
end

-- 重启服务按钮
local rb = s0:option(Button, "_restart_btn", translate("&nbsp;"))
rb.inputtitle = translate("↺ 重启服务")
rb.inputstyle = "apply"
function rb.write(self, section)
    luci_sys.call("/etc/init.d/rdp_controller restart >/dev/null 2>&1")
    luci_sys.call("sleep 2")
    refresh_status()
end

-- 停止所有转发按钮：清计时器 + 关闭所有受控端口 + 停服务
local sa = s0:option(Button, "_stop_all_btn", translate("&nbsp;"))
sa.inputtitle = translate("⛔ 停止所有")
sa.inputstyle = "remove"
function sa.write(self, section)
    local port = uci:get("rdp_controller", "main", "port") or "8080"
    luci_sys.call(string.format(
        "wget -q -T 30 -O - 'http://127.0.0.1:%s/api/stop_all' >/dev/null 2>&1", port))
    luci_sys.call("sleep 1")
    luci_sys.call("/etc/init.d/rdp_controller stop >/dev/null 2>&1")
    luci_sys.call("sleep 1")
    refresh_status()
end

-- ══════════════════════════════════════════
-- 服务设置
-- ══════════════════════════════════════════
s = m:section(NamedSection, "main", "rdp_controller", translate("服务设置"))
s.addremove = false
s.anonymous = true

local e = s:option(Flag, "enabled", translate("启用插件"))
e.rmempty = false

local po = s:option(Value, "port", translate("访问端口"))
po.datatype = "port"
po.default = "8080"
po.rmempty = false

local ae = s:option(Flag, "auth_enabled", translate("启用密码登录"))
ae.rmempty = false

local pw = s:option(Value, "password", translate("访问密码"))
pw.password = true
pw:depends("auth_enabled", "1")
pw.rmempty = true

-- 网络唤醒目标 MAC
local wol = s:option(Value, "wol_mac", translate("网络唤醒 MAC 地址"))
wol.placeholder = "AA:BB:CC:DD:EE:FF"
wol.rmempty = true
wol.description = translate("填写后，管理页面会出现「唤醒主机」按钮（发送 WoL 魔术包）")

-- 网络唤醒目标 IP（用于 ping 检查在线状态）
local wolip = s:option(Value, "wol_ip", translate("唤醒主机 IP 地址"))
wolip.placeholder = "192.168.1.100"
wolip.rmempty = true
wolip.description = translate("填写后，管理页面会出现「检查在线状态」按钮（ping 一次，显示延迟或不在线）")

-- 重启后保持倒计时
local pr = s:option(Flag, "persist_on_restart", translate("重启后保持倒计时"))
pr.default = "1"
pr.rmempty = false

-- 可控制的端口转发（复选框多选，存为 UCI list，空格安全）
local rs = s:option(MultiValue, "controlled_redirects", translate("可控制的端口转发"))
rs:depends("enabled", "1")
rs.widget = "checkbox"
rs.rmempty = true
uci:foreach("firewall", "redirect", function(r)
    if r.name then
        local label = r.name
        if r.src_dport then
            label = label .. "  (:" .. r.src_dport .. ")"
        end
        rs:value(r.name, label)
    end
end)
-- 强制以空格分隔的字符串存储（uci:set 只可靠接受字符串，传 table 会静默失败）
function rs.write(self, section, value)
    if type(value) == "table" then
        value = table.concat(value, " ")
    end
    self.map:set(section, "controlled_redirects", value)
end

-- ══════════════════════════════════════════
-- 飞书通知
-- ══════════════════════════════════════════
w = m:section(NamedSection, "webhook", "webhook", translate("飞书通知"))
w.addremove = false
w.anonymous = true

local we = w:option(Flag, "enabled", translate("启用飞书通知"))
we.rmempty = false

local wu = w:option(Value, "url", translate("Webhook 地址"))
wu:depends("enabled", "1")
wu.rmempty = true
wu.placeholder = "https://open.feishu.cn/open-apis/bot/v2/hook/..."

local wk = w:option(Value, "keyword", translate("安全关键词"))
wk:depends("enabled", "1")
wk.rmempty = true
wk.description = translate("若机器人开启了「自定义关键词」校验，请填写其中一个关键词；" ..
    "否则飞书会拒收并报错 19024 Key Words Not Found。会自动加到每条消息前。")

local wt = w:option(Button, "_test_wh", translate("&nbsp;"))
wt.inputtitle = translate("发送测试通知")
wt.inputstyle = "reload"
wt:depends("enabled", "1")
-- 走服务真实发送路径（与倒计时通知同一代码），并把结果写入临时文件供显示
function wt.write(self, section)
    local port = uci:get("rdp_controller", "main", "port") or "8080"
    local out = luci_sys.exec(string.format(
        "wget -q -O - 'http://127.0.0.1:%s/api/webhook/test' 2>&1", port)) or ""
    local f = io.open("/tmp/rdp_wh_test", "w")
    if f then f:write(os.date("%H:%M:%S") .. " " .. out); f:close() end
end

-- 测试结果显示
local wr = w:option(DummyValue, "_wh_result", translate("测试结果"))
wr.rawhtml = true
wr:depends("enabled", "1")
function wr.cfgvalue(self, section)
    local out = luci_sys.exec("cat /tmp/rdp_wh_test 2>/dev/null") or ""
    out = out:gsub("%s+$", "")
    if out == "" then
        return "<span style='color:#9E9E9E'>" .. translate("点击上方「发送测试通知」，结果将显示在此（请先保存并应用）") .. "</span>"
    end
    out = out:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;")
    return "<code style='font-size:12px'>" .. out .. "</code>"
end

-- ══════════════════════════════════════════
-- 日志（挂到 main 具名段，始终存在且与 Python 读取一致）
-- ══════════════════════════════════════════
s2 = m:section(NamedSection, "main", "rdp_controller", translate("日志"))
s2.addremove = false
s2.anonymous = true

local le = s2:option(Flag, "log_enabled", translate("启用日志记录"))
le.default = "1"
le.rmempty = false
le.description = translate("关闭后服务不再写入日志（需保存后生效）")

-- 日志文件路径（静态）
local lp = s2:option(DummyValue, "_log_path", translate("日志文件路径"))
lp.rawhtml = true
function lp.cfgvalue(self, section)
    return "<code>/var/log/rdp_controller.log</code>"
end

-- 日志文件大小（仅在点击「读取日志」时更新）
local ls = s2:option(DummyValue, "_log_size", translate("日志文件大小"))
ls.rawhtml = true
function ls.cfgvalue(self, section)
    local meta = (luci_sys.exec("head -n1 /tmp/rdp_log_view 2>/dev/null") or ""):gsub("%s+$", "")
    if meta == "" then
        return "<span style='color:#9E9E9E'>" .. translate("未读取") .. "</span>"
    end
    if meta:match("^MISSING") then
        local t = meta:match("^MISSING%s+(.*)$") or ""
        return "<span style='color:#f44336'>" .. translate("日志文件不存在") ..
               "</span> <span style='color:#999'>(读取于 " .. t .. ")</span>"
    end
    local size, t = meta:match("^OK%s+(%S+)%s+(.*)$")
    if size then
        return string.format("<b>%s</b> 字节 <span style='color:#999'>(读取于 %s)</span>", size, t or "")
    end
    return meta
end

-- 读取日志按钮：把大小+内容快照写入临时文件（能处理文件被删的情况）
local lr = s2:option(Button, "_read_log", translate("&nbsp;"))
lr.inputtitle = translate("📖 读取日志")
lr.inputstyle = "reload"
function lr.write(self, section)
    luci_sys.call(
        "L=/var/log/rdp_controller.log; O=/tmp/rdp_log_view; " ..
        "if [ -f \"$L\" ]; then " ..
        "echo \"OK $(wc -c < \"$L\" | tr -d ' ') $(date '+%Y-%m-%d %H:%M:%S')\" > \"$O\"; " ..
        "tail -n 300 \"$L\" >> \"$O\"; " ..
        "else echo \"MISSING $(date '+%Y-%m-%d %H:%M:%S')\" > \"$O\"; fi"
    )
end

-- 日志内容（读取后才显示）
local lvw = s2:option(DummyValue, "_log_view", translate("日志内容"))
lvw.rawhtml = true
function lvw.cfgvalue(self, section)
    local meta = (luci_sys.exec("head -n1 /tmp/rdp_log_view 2>/dev/null") or ""):gsub("%s+$", "")
    if meta == "" then
        return "<span style='color:#9E9E9E'>" .. translate("点击「读取日志」查看内容") .. "</span>"
    end
    if meta:match("^MISSING") then
        return "<span style='color:#f44336'>" .. translate("日志文件不存在（可能已被删除）") .. "</span>"
    end
    local content = luci_sys.exec("tail -n +2 /tmp/rdp_log_view 2>/dev/null") or ""
    if content:gsub("%s+$", "") == "" then
        return "<span style='color:#9E9E9E'>" .. translate("（日志为空）") .. "</span>"
    end
    content = content:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;")
    return "<pre style='max-height:360px;overflow:auto;background:#1e1e1e;color:#d4d4d4;"
        .. "padding:10px;border-radius:4px;font-size:12px;line-height:1.5;margin:0'>"
        .. content .. "</pre>"
end

-- 删除日志文件按钮（同时清掉读取快照）
local ld = s2:option(Button, "_del_log", translate("&nbsp;"))
ld.inputtitle = translate("🗑 删除日志文件")
ld.inputstyle = "remove"
function ld.write(self, section)
    luci_sys.call("rm -f /var/log/rdp_controller.log /tmp/rdp_log_view 2>/dev/null")
end

return m
