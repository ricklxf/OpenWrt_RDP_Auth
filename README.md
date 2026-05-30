# Port-Control · OpenWrt 端口转发控制器

一个运行在 OpenWrt 上的端口转发管理插件：用独立 Web 界面 + LuCI 配置页，
对指定的防火墙端口转发做**倒计时开关**，到点自动关闭并**主动断开已建立的连接**，
适合临时开放 RDP / SSH 等端口的场景。

> LuCI 菜单：**服务 → 端口控制**

## 功能特性

- **独立 Web 管理界面**，端口可配置（默认 `8080`），标题实时显示版本号
- **复选框多选**要纳入管理的端口转发（从现有防火墙规则中勾选）
- **倒计时模式**：开启时启用转发，倒计时结束自动关闭
- **关闭即断连**：关闭端口时用 `conntrack` 删除已建立连接，强制断开正在使用的会话
  （仅禁用转发只能拦新连接，老连接不会断）
- **乐观更新 UI**：点击即时显示倒计时进度条（绿 → 黄 → 红），无需等待服务器
- **立刻结束**：手动提前关闭并断开连接
- **可选密码登录**
- **飞书 Webhook 通知**（开启 / 关闭时推送）
- **倒计时持久化**：OpenWrt 重启后继续计时
- **LuCI 集成**：服务状态（运行状态、管理地址直链、端口规则一览、状态检测、重启服务）、
  服务设置、飞书通知、日志管理（记录开关 / 在线查看 / 一键清除）

## 安装

### 方式一：直接安装 IPK（推荐）

从 [Releases](https://github.com/ricklxf/OpenWrt_RDP_Auth/releases) 下载最新的
`Port-Control_<版本>.ipk`，上传到路由器后：

```bash
# 断连功能需要 conntrack 工具（强烈建议先装）
opkg update && opkg install conntrack-tools

# 安装本插件
opkg install Port-Control_<版本>.ipk

# 启动服务
/etc/init.d/rdp_controller restart

# 清 LuCI 缓存后刷新浏览器即可看到菜单
rm -rf /tmp/luci-* /tmp/luci-modulecache
/etc/init.d/uhttpd restart
```

**升级**时先卸载旧版再安装：

```bash
opkg remove Port-Control
opkg install Port-Control_<新版本>.ipk
```

### 方式二：手动复制文件

```bash
scp files/rdp_controller        root@192.168.1.1:/etc/config/
scp files/rdp_controller.py     root@192.168.1.1:/usr/bin/
scp files/rdp_controller.init   root@192.168.1.1:/etc/init.d/rdp_controller
scp luci/controller/rdp_controller.lua    root@192.168.1.1:/usr/lib/lua/luci/controller/
scp luci/model/cbi/rdp_controller.lua     root@192.168.1.1:/usr/lib/lua/luci/model/cbi/
# 赋予可执行权限
chmod +x /usr/bin/rdp_controller.py /etc/init.d/rdp_controller
```

### 依赖

| 依赖 | 说明 |
| --- | --- |
| `python3` | 运行 Web 服务 |
| `luci` | LuCI 配置界面 |
| `conntrack-tools` | **可选但强烈推荐**，关闭端口时断开已建立连接 |

## 使用

1. **LuCI 配置**：进入 **服务 → 端口控制**
   - 启用插件、设置访问端口
   - 勾选要控制的端口转发（需先在「网络 → 防火墙 → 端口转发」中创建规则）
   - 可选：启用密码登录、配置飞书 Webhook
   - 保存并应用
2. **打开管理页**：点击配置页「管理地址」直链，或浏览器访问 `http://<路由器IP>:<端口>`
3. **倒计时控制**：为某个端口设置分钟数 → 点「倒计时开启」→ 进度条开始走，
   到点自动关闭并断开连接；也可随时点「立刻结束」

## 配置 / 文件位置

| 路径 | 用途 |
| --- | --- |
| `/etc/config/rdp_controller` | 插件配置（UCI） |
| `/etc/config/firewall` | 防火墙端口转发（只读改 `enabled`） |
| `/usr/bin/rdp_controller.py` | Web 服务主程序 |
| `/etc/init.d/rdp_controller` | procd 启动脚本 |
| `/var/log/rdp_controller.log` | 运行日志（可在 LuCI 查看/清除） |
| `/tmp/rdp_timers.json` | 倒计时持久化状态 |

### UCI 配置项

```
config rdp_controller 'main'
    option enabled '1'              # 启用插件
    option port '8080'             # Web 访问端口
    option auth_enabled '0'        # 是否启用密码登录
    option password ''             # 登录密码
    option controlled_redirects '' # 受控端口转发名称（空格分隔）

config webhook 'webhook'
    option enabled '0'             # 启用飞书通知
    option url ''                  # 飞书机器人 Webhook 地址

config settings 'settings'
    option persist_on_restart '1'  # 重启后保持倒计时
    option log_enabled '1'         # 启用日志记录
```

## 开发 / 构建发布

```bash
# 构建 IPK（纯 Python 打 AR 包，macOS / Linux 通用，无需 OpenWrt SDK）
python3 build.sh        # 产物：Port-Control_<版本>.ipk

# 发布（版本号 +1 → 构建 → 提交 → 打 tag → 上传 GitHub Release）
bash release.sh
```

> 仓库配置了 Claude Code 的提交钩子（`.claude/settings.json`）：每次 `git commit`
> 都会自动调用 `release.sh`，**自动递增版本号并发布**，无需手动操作。
> 版本号通过构建时占位符 `__PKG_VERSION__` 注入到 Web 标题与 LuCI 标题，自动同步。

### 目录结构

```
OpenWrt_RDP_Auth/
├── VERSION                 # 当前版本号（release.sh 自增）
├── build.sh                # 打包脚本（生成 .ipk）
├── release.sh              # 版本递增 + 构建 + 发布
├── files/
│   ├── rdp_controller      # UCI 默认配置
│   ├── rdp_controller.init # procd 启动脚本
│   └── rdp_controller.py   # Web 服务主程序
└── luci/
    ├── controller/rdp_controller.lua   # LuCI 菜单注册
    └── model/cbi/rdp_controller.lua    # LuCI 配置页
```

## 注意事项

1. 必须先在 OpenWrt 防火墙中创建端口转发规则，再在插件里勾选
2. 插件只修改转发规则的 `enabled` 状态，不改动其他防火墙配置
3. **断连功能依赖 `conntrack-tools`**；未安装时端口会关闭但已建立连接不会断开，
   日志会提示安装命令
4. 建议仅在局域网使用；如需公网访问请启用密码并做好安全防护
5. 升级后若 LuCI 菜单/界面未更新，清缓存：`rm -rf /tmp/luci-*` 并重启 `uhttpd`
