#!/bin/bash
set -e

# Define directories
SRC_DIR="src"
PKG_DIR="pkg"
BUILD_DIR="build"
TEMP_DIR="${BUILD_DIR}/self"
INSTALL_DIR="${TEMP_DIR}/usr/lib/self"
SBIN_DIR="${TEMP_DIR}/usr/sbin"
DEBIAN_DIR="${TEMP_DIR}/DEBIAN"

# Clean previous build
echo "Cleaning previous build..."
rm -rf ${BUILD_DIR}
mkdir -p ${BUILD_DIR}

# Compile eBPF program
echo "Compiling eBPF program..."
clang -g -O2 -target bpf -c ${SRC_DIR}/ddos_protect.c -o ${BUILD_DIR}/ddos_protect.o

# Compile user-space program
echo "Compiling user-space program..."
gcc -Wall -O2 -I/usr/include -I/usr/local/include -I/usr/include/bpf ${SRC_DIR}/main.c -o ${BUILD_DIR}/main -lelf -lbpf -lpthread -lz -lrt

# Create package structure
echo "Creating package structure..."
mkdir -p ${INSTALL_DIR} ${SBIN_DIR} ${DEBIAN_DIR}

# Copy binaries to installation directory
cp ${BUILD_DIR}/ddos_protect.o ${INSTALL_DIR}/
cp ${BUILD_DIR}/main ${INSTALL_DIR}/
chmod +x ${INSTALL_DIR}/main

# Copy and make scripts executable
cp ${PKG_DIR}/self_start.sh ${SBIN_DIR}/self-start
cp ${PKG_DIR}/self_stop.sh ${SBIN_DIR}/self-stop
chmod 755 ${SBIN_DIR}/self-start ${SBIN_DIR}/self-stop

# Create a simplified control file for dpkg-deb
cat > ${DEBIAN_DIR}/control << EOF
Package: self
Version: 1.0.0-1
Section: net
Priority: optional
Architecture: amd64
Maintainer: Administrator <admin@example.com>
Depends: libbpf0
Recommends: linux-tools-common | linux-tools-generic
Description: Self-learning firewall based on eBPF
 A DDoS protection system that uses eBPF to monitor and block malicious traffic.
 This package provides a service that monitors network traffic and learns
 to detect and prevent DDoS attacks.
EOF

# Copy other debian files
cp debian/changelog ${DEBIAN_DIR}/
cp debian/compat ${DEBIAN_DIR}/
cp debian/postinst ${DEBIAN_DIR}/postinst
cp debian/postrm ${DEBIAN_DIR}/postrm
cp debian/preinst ${DEBIAN_DIR}/preinst
cp debian/prerm ${DEBIAN_DIR}/prerm
chmod 755 ${DEBIAN_DIR}/postinst ${DEBIAN_DIR}/postrm ${DEBIAN_DIR}/preinst ${DEBIAN_DIR}/prerm

# Create systemd directory and copy service file
mkdir -p ${TEMP_DIR}/etc/systemd/system
cp debian/self.service ${TEMP_DIR}/etc/systemd/system/

# Build the actual package
echo "Building Debian package..."
dpkg-deb --build ${TEMP_DIR} ${BUILD_DIR}/self_1.0.0-1_amd64.deb

echo "Package built: ${BUILD_DIR}/self_1.0.0-1_amd64.deb" 