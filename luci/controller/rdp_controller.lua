module("luci.controller.rdp_controller", package.seeall)

function index()
    entry({"admin", "services", "rdp_controller"}, cbi("rdp_controller"), _("端口控制"), 60)
end
