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

local wt = w:option(Button, "_test_wh", translate("&nbsp;"))
wt.inputtitle = translate("发送测试通知")
wt.inputstyle = "reload"
wt:depends("enabled", "1")
function wt.write(self, section)
    local port = uci:get("rdp_controller", "main", "port") or "8080"
    luci_sys.call(string.format(
        "wget -q -O /tmp/.rdp_wh_test 'http://127.0.0.1:%s/api/webhook/test' 2>/dev/null",
        port
    ))
end

-- ══════════════════════════════════════════
-- 日志与其他设置（同一 settings 段，合并为单个 section 避免 DOM id 冲突）
-- ══════════════════════════════════════════
s2 = m:section(NamedSection, "settings", "settings", translate("日志"))
s2.addremove = false
s2.anonymous = true

local le = s2:option(Flag, "log_enabled", translate("启用日志记录"))
le.default = "1"
le.rmempty = false
le.description = translate("关闭后服务不再写入日志（需保存后生效）")

-- 日志内容（读取最后 200 行）
local lvw = s2:option(DummyValue, "_log_view", translate("日志内容"))
lvw.rawhtml = true
function lvw.cfgvalue(self, section)
    local content = luci_sys.exec("tail -n 200 /var/log/rdp_controller.log 2>/dev/null")
    if not content or content == "" then
        return "<span style='color:#9E9E9E'>" .. translate("（暂无日志）") .. "</span>"
    end
    content = content:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;")
    return "<pre style='max-height:360px;overflow:auto;background:#1e1e1e;color:#d4d4d4;"
        .. "padding:10px;border-radius:4px;font-size:12px;line-height:1.5;margin:0'>"
        .. content .. "</pre>"
end

-- 清除日志按钮
local lc = s2:option(Button, "_clear_log", translate("&nbsp;"))
lc.inputtitle = translate("🗑 清除日志")
lc.inputstyle = "remove"
function lc.write(self, section)
    luci_sys.call(": > /var/log/rdp_controller.log 2>/dev/null")
end

-- 倒计时持久化
local pr = s2:option(Flag, "persist_on_restart", translate("重启后保持倒计时"))
pr.default = "1"
pr.rmempty = false

return m
