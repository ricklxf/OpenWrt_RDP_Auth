#!/usr/bin/env python3
"""
Build script for rdp-controller OpenWrt IPK package.
Run: python3 build.sh

OpenWrt IPK format: gzip-compressed tar containing
  ./debian-binary, ./data.tar.gz, ./control.tar.gz
"""

import tarfile, io, os, sys, gzip

PACKAGE_NAME = "Port-Control"
PACKAGE_ARCH = "all"

SOURCE_DIR = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(SOURCE_DIR, "VERSION")) as _f:
    PACKAGE_VERSION = _f.read().strip()
OUTPUT = os.path.join(SOURCE_DIR, f"{PACKAGE_NAME}_{PACKAGE_VERSION}.ipk")

def read(path):
    with open(path, 'rb') as f:
        return f.read()

def file_entry(name, data, mode=0o644):
    ti = tarfile.TarInfo(name=name)
    ti.type = tarfile.REGTYPE
    ti.mode = mode
    ti.size = len(data)
    ti.mtime = ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    return ti, io.BytesIO(data)

def dir_entry(name, mode=0o755):
    ti = tarfile.TarInfo(name=name)
    ti.type = tarfile.DIRTYPE
    ti.mode = mode
    ti.size = ti.mtime = ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    return ti

CONTROL = f"""\
Package: {PACKAGE_NAME}
Version: {PACKAGE_VERSION}
Architecture: {PACKAGE_ARCH}
Section: net
Priority: optional
Maintainer: ricklxf90@gmail.com
Depends: python3, luci
Replaces: rdp_controller
Conflicts: rdp_controller
Description: RDP Port Forwarding Controller with countdown timer and Feishu notifications
""".encode()

POSTINST = b"""\
#!/bin/sh
if [ -z "$IPKG_INSTROOT" ]; then
    chmod +x /usr/bin/rdp_controller.py 2>/dev/null || true
    chmod +x /etc/init.d/rdp_controller 2>/dev/null || true
    /etc/init.d/rdp_controller enable 2>/dev/null || true
fi
exit 0
"""

PRERM = b"""\
#!/bin/sh
if [ -z "$IPKG_INSTROOT" ]; then
    /etc/init.d/rdp_controller stop 2>/dev/null || true
    /etc/init.d/rdp_controller disable 2>/dev/null || true
fi
exit 0
"""

# control.tar.gz
ctrl_buf = io.BytesIO()
with tarfile.open(fileobj=ctrl_buf, mode='w:gz', format=tarfile.USTAR_FORMAT) as t:
    t.addfile(dir_entry("."))
    t.addfile(*file_entry("./control",  CONTROL,  0o644))
    t.addfile(*file_entry("./postinst", POSTINST, 0o755))
    t.addfile(*file_entry("./prerm",    PRERM,    0o755))

# data.tar.gz
data_buf = io.BytesIO()
with tarfile.open(fileobj=data_buf, mode='w:gz', format=tarfile.USTAR_FORMAT) as t:
    t.addfile(dir_entry("."))
    for d in ["./usr", "./usr/bin",
              "./usr/lib", "./usr/lib/lua", "./usr/lib/lua/luci",
              "./usr/lib/lua/luci/controller",
              "./usr/lib/lua/luci/model", "./usr/lib/lua/luci/model/cbi",
              "./etc", "./etc/config", "./etc/init.d"]:
        t.addfile(dir_entry(d))
    t.addfile(*file_entry("./usr/bin/rdp_controller.py",
        read(f"{SOURCE_DIR}/files/rdp_controller.py"), 0o755))
    t.addfile(*file_entry("./usr/lib/lua/luci/controller/rdp_controller.lua",
        read(f"{SOURCE_DIR}/luci/controller/rdp_controller.lua"), 0o644))
    t.addfile(*file_entry("./usr/lib/lua/luci/model/cbi/rdp_controller.lua",
        read(f"{SOURCE_DIR}/luci/model/cbi/rdp_controller.lua"), 0o644))
    t.addfile(*file_entry("./etc/config/rdp_controller",
        read(f"{SOURCE_DIR}/files/rdp_controller"), 0o644))
    t.addfile(*file_entry("./etc/init.d/rdp_controller",
        read(f"{SOURCE_DIR}/files/rdp_controller.init"), 0o755))

# Outer: gzip-compressed tar — the real OpenWrt IPK format
# (verified against official OpenWrt 23.05 packages)
outer_buf = io.BytesIO()
with tarfile.open(fileobj=outer_buf, mode='w:', format=tarfile.USTAR_FORMAT) as t:
    t.addfile(*file_entry("./debian-binary",  b"2.0\n",            0o644))
    t.addfile(*file_entry("./data.tar.gz",    data_buf.getvalue(), 0o644))
    t.addfile(*file_entry("./control.tar.gz", ctrl_buf.getvalue(), 0o644))

with gzip.GzipFile(OUTPUT, 'wb', compresslevel=9, mtime=0) as gz:
    gz.write(outer_buf.getvalue())

size = os.path.getsize(OUTPUT)
print(f"OK: {os.path.basename(OUTPUT)}  ({size} bytes)")
