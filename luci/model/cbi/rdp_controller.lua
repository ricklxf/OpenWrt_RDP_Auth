local luci_sys = require "luci.sys"
local uci = require("luci.model.uci").cursor()

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

-- 获取后台完整地址
local function get_admin_url()
    local port = uci:get("rdp_controller", "main", "port") or "8080"
    return "http://" .. get_lan_ip() .. ":" .. port
end

-- 判断服务是否在运行
local function is_running()
    return luci_sys.call("/etc/init.d/rdp_controller status >/dev/null 2>&1") == 0
end

-- ─────────────────────────────────────────────────────────────────────────────
m = Map("rdp_controller", translate("端口控制"),
    translate("管理端口转发规则与倒计时"))

-- ══════════════════════════════════════════
-- 服务状态
-- ══════════════════════════════════════════
s0 = m:section(NamedSection, "main", "rdp_controller", translate("服务状态"))
s0.addremove = false
s0.anonymous = true

-- 运行状态
local sv = s0:option(DummyValue, "_svc_status", translate("运行状态"))
sv.rawhtml = true
function sv.cfgvalue(self, section)
    if is_running() then
        return "<b style='color:#4CAF50'>● 运行中</b>"
    else
        return "<b style='color:#f44336'>● 已停止</b>"
    end
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

-- 端口转发列表（当前所有规则及状态）
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

-- 重启服务按钮
local rb = s0:option(Button, "_restart_btn", translate("&nbsp;"))
rb.inputtitle = translate("↺ 重启服务")
rb.inputstyle = "apply"
function rb.write(self, section)
    luci_sys.call("/etc/init.d/rdp_controller restart >/dev/null 2>&1")
    luci_sys.call("sleep 2")
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

-- 可控制的端口转发（复选框多选）
local rs = s:option(MultiValue, "controlled_redirects", translate("可控制的端口转发"))
rs:depends("enabled", "1")
rs.widget = "checkbox"
uci:foreach("firewall", "redirect", function(r)
    if r.name then
        local label = r.name
        if r.src_dport then
            label = label .. "  (:" .. r.src_dport .. ")"
        end
        rs:value(r.name, label)
    end
end)

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
-- 其他设置
-- ══════════════════════════════════════════
s2 = m:section(NamedSection, "settings", "settings", translate("其他设置"))
s2.addremove = false
s2.anonymous = true

local pr = s2:option(Flag, "persist_on_restart", translate("重启后保持倒计时"))
pr.default = "1"
pr.rmempty = false

return m
