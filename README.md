# RDP端口转发控制器 (OpenWrt)

一个用于控制OpenWrt端口转发的插件，支持倒计时管理和飞书通知。

## 功能特性

- 独立Web界面（可配置端口）
- 可选密码登录
- 只控制已选端口转发的开启/关闭
- 倒计时模式（自动关闭）
- 实时血条显示倒计时进度（绿→黄→红渐变）
- 飞书Webhook通知（开启和关闭时发送消息）
- 倒计时持久化（OpenWrt重启后继续）
- LuCI集成配置界面

## 安装

### 1. 编译安装

将项目目录复制到OpenWrt SDK的package目录下：
```bash
# 在SDK根目录
make package/rdp_controller/compile
```

### 2. 直接安装

将所需文件复制到OpenWrt设备上：
```bash
# 复制配置文件
scp files/rdp_controller root@192.168.1.1:/etc/config/

# 复制主程序
scp files/rdp_controller.py root@192.168.1.1:/usr/bin/
chmod +x /usr/bin/rdp_controller.py

# 复制启动脚本
scp files/rdp_controller.init root@192.168.1.1:/etc/init.d/rdp_controller
chmod +x /etc/init.d/rdp_controller

# 复制LuCI文件
scp luci/controller/rdp_controller.lua root@192.168.1.1:/usr/lib/lua/luci/controller/
scp luci/model/cbi/rdp_controller.lua root@192.168.1.1:/usr/lib/lua/luci/model/cbi/
```

## 依赖

- python3
- luci

```bash
opkg install python3 luci
```

## 使用

### 1. 在LuCI中配置

访问 OpenWrt Luci → 服务 → RDP端口转发控制器

- 启用插件
- 设置访问端口（默认8080）
- 可选：启用密码并设置密码
- 选择需要控制的端口转发（从现有防火墙规则中选择）
- 可选：启用飞书通知并配置Webhook地址

### 2. 启动服务

```bash
/etc/init.d/rdp_controller enable
/etc/init.d/rdp_controller start
```

### 3. 访问Web界面

在浏览器中访问：`http://192.168.1.1:8080`

- 如果启用了密码，需要先登录
- 查看可控制的端口转发列表
- 设置倒计时并开启
- 点击"立刻结束"立即关闭

## Web界面特性

### 倒计时血条
- 绿色：剩余时间 > 50%
- 黄色：剩余时间 20%-50%
- 红色：剩余时间 < 20%
- 平滑动画效果

### 飞书通知格式

**开启通知：**
```
🔓 端口转发已开启
━━━━━━━━━━━━━━━
📋 名称: [转发名称]
⏰ 开始时间: [时间]
⏰ 结束时间: [时间]
━━━━━━━━━━━━━━━
```

**关闭通知：**
```
🔒 端口转发已关闭
━━━━━━━━━━━━━━━
📋 名称: [转发名称]
🕐 关闭时间: [时间]
━━━━━━━━━━━━━━━
```

## 配置文件位置

- 插件配置：`/etc/config/rdp_controller`
- 防火墙配置：`/etc/config/firewall`
- 倒计时状态：`/tmp/rdp_timers.json`

## 文件结构

```
OpenWrt_RDP_Auth/
├── Makefile
├── README.md
├── files/
│   ├── rdp_controller
│   ├── rdp_controller.init
│   └── rdp_controller.py
└── luci/
    ├── controller/
    │   └── rdp_controller.lua
    └── model/
        └── cbi/
            └── rdp_controller.lua
```

## 注意事项

1. 必须先在OpenWrt防火墙中添加端口转发规则，然后在插件配置中选择
2. 插件仅修改转发规则的`enabled`状态，不修改其他配置
3. 建议在局域网内使用，如需外网访问请做好安全措施
4. 飞书通知通过HTTPS发送，确保设备能访问外网
