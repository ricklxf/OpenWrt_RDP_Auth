module("luci.controller.rdp_controller", package.seeall)

function index()
    if not nixio.fs.access("/etc/config/rdp_controller") then
        return
    end
    
    entry({"admin", "services", "rdp_controller"}, cbi("rdp_controller"), _("RDP端口转发控制器"), 60)
end
