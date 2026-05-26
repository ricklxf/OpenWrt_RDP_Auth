#!/bin/bash
# OpenWrt IPK Build Script - FINAL FIX

PACKAGE_NAME=rdp-controller
PACKAGE_VERSION=1.0.0
PACKAGE_ARCH=all
SOURCE_DIR=$(pwd)
BUILD_DIR=/tmp/ipk-build-$$

# Cleanup previous
rm -f "${SOURCE_DIR}"/*.ipk

# Create build dir in Linux FS (WSL tmp)
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR
cd $BUILD_DIR || exit 1

# Create directories
mkdir -p usr/bin etc/config etc/init.d
mkdir -p usr/lib/lua/luci/controller
mkdir -p usr/lib/lua/luci/model/cbi

# Copy files from source
cp "${SOURCE_DIR}/files/rdp_controller.py" usr/bin/
cp "${SOURCE_DIR}/files/rdp_controller" etc/config/
cp "${SOURCE_DIR}/files/rdp_controller.init" etc/init.d/rdp_controller
cp "${SOURCE_DIR}/luci/controller/rdp_controller.lua" usr/lib/lua/luci/controller/
cp "${SOURCE_DIR}/luci/model/cbi/rdp_controller.lua" usr/lib/lua/luci/model/cbi/

# Set permissions (WSL can do this on tmp)
chmod 755 usr/bin/rdp_controller.py
chmod 755 etc/init.d/rdp_controller

# Create control files in separate dir
mkdir -p CONTROL_FILES

cat > CONTROL_FILES/control << 'EOF'
Package: rdp-controller
Version: 1.0.0
Architecture: all
Section: net
Priority: optional
Maintainer: Your Name
Depends: python3, luci
Description: RDP Port Forwarding Controller
EOF

cat > CONTROL_FILES/postinst << 'EOF'
#!/bin/sh
if [ -z "$IPKG_INSTROOT" ]; then
    chmod +x /usr/bin/rdp_controller.py 2>/dev/null || true
    chmod +x /etc/init.d/rdp_controller 2>/dev/null || true
    /etc/init.d/rdp_controller enable 2>/dev/null || true
fi
exit 0
EOF

cat > CONTROL_FILES/prerm << 'EOF'
#!/bin/sh
if [ -z "$IPKG_INSTROOT" ]; then
    /etc/init.d/rdp_controller stop 2>/dev/null || true
    /etc/init.d/rdp_controller disable 2>/dev/null || true
fi
exit 0
EOF

chmod 755 CONTROL_FILES/postinst CONTROL_FILES/prerm

# Create tarballs (CRITICAL: create without ./ prefix)
echo "2.0" > debian-binary
cd CONTROL_FILES
tar czf ../control.tar.gz control postinst prerm
cd ..
tar czf data.tar.gz usr etc

# Final IPK
OUTPUT_FILE="${PACKAGE_NAME}_${PACKAGE_VERSION}_${PACKAGE_ARCH}.ipk"
ar r $OUTPUT_FILE debian-binary control.tar.gz data.tar.gz

# Copy to source dir and cleanup
cp $OUTPUT_FILE "${SOURCE_DIR}/"
cd "${SOURCE_DIR}"
rm -rf $BUILD_DIR

echo "OK: $OUTPUT_FILE"
ls -lh "$OUTPUT_FILE"
