m = Map("rdp_controller", translate("RDP端口转发控制器"),
    translate("控制OpenWrt端口转发的开启/关闭和倒计时管理"))

-- 主设置section
s = m:section(NamedSection, "main", "rdp_controller", translate("服务设置"))
s.addremove = false
s.anonymous = true

e = s:option(Flag, "enabled", translate("启用插件"))
e.rmempty = false

p = s:option(Value, "port", translate("访问端口"))
p.datatype = "port"
p.default = "8080"
p.rmempty = false

-- 密码设置
a = s:option(Flag, "auth_enabled", translate("启用密码登录"))
a.rmempty = false

pwd = s:option(Value, "password", translate("访问密码"))
pwd.password = true
pwd:depends("auth_enabled", "1")
pwd.rmempty = true

-- 端口转发选择
rs = s:option(DynamicList, "controlled_redirects", translate("可控制的端口转发"))
rs:depends("enabled", "1")
rs.description = translate("选择哪些端口转发可以在Web界面中控制")

-- 读取防火墙配置中的redirect名称
local uci = require "luci.model.uci".cursor()
local redirect_names = {}
uci:foreach("firewall", "redirect", function(s)
    if s.name then
        table.insert(redirect_names, s.name)
        rs:value(s.name)
    end
end)

-- Webhook设置
w = m:section(NamedSection, "webhook", "webhook", translate("飞书通知"))
w.addremove = false
w.anonymous = true

we = w:option(Flag, "enabled", translate("启用飞书通知"))
we.rmempty = false

wu = w:option(Value, "url", translate("Webhook地址"))
wu:depends("enabled", "1")
wu.rmempty = true
wu.description = translate("飞书自定义机器人的Webhook地址")

-- 测试按钮
testbtn = w:option(Button, "test_webhook", translate("发送测试通知"))
testbtn:depends("enabled", "1")
testbtn.inputtitle = translate("发送测试通知")
testbtn.inputstyle = "apply"
function testbtn.write(self, section)
    -- 使用一个简单的Python脚本来调用Webhook测试API
    luci.sys.call([[
python3 -c "
import requests
import json
from datetime import datetime

# 读取UCI配置
import subprocess
def uci_get(config, section, option):
    try:
        result = subprocess.check_output(
            ['uci', 'get', f'{config}.{section}.{option}'],
            stderr=subprocess.STDOUT
        ).decode('utf-8').strip()
        return result
    except:
        return ''

webhook_url = uci_get('rdp_controller', 'webhook', 'url')
test_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

if webhook_url:
    try:
        payload = {
            'msg_type': 'text',
            'content': {'text': f'🔔 测试消息: {test_time}'}
        }
        response = requests.post(webhook_url, json=payload, timeout=5)
        if response.status_code == 200:
            print('测试消息发送成功')
        else:
            print(f'发送失败: {response.text}')
    except Exception as e:
        print(f'请求异常: {str(e)}')
else:
    print('未配置Webhook地址')
" 2>&1 | logger -t rdp_controller_test &]])
    
    -- 通知用户
    luci.sys.call("logger -t rdp_controller '测试通知已发送，请检查飞书或系统日志'")
end

-- 其他设置
s2 = m:section(NamedSection, "settings", "settings", translate("其他设置"))
s2.addremove = false
s2.anonymous = true

p2 = s2:option(Flag, "persist_on_restart", translate("倒计时持久化"))
p2.default = "1"
p2.rmempty = false
p2.description = translate("OpenWrt重启后保持倒计时状态")

return m
