#!/bin/bash

# OCI Manager - Quick Install & Systemd Service Setup
# Supports Ubuntu, CentOS, Debian, Oracle Linux (x86_64 & ARM64)

set -e

# Use localized messages
echo "------------------------------------------------"
echo "OCI Manager Installer / OCI 管理器安装脚本"
echo "------------------------------------------------"

# 1. Detection
ARCH=$(uname -m)
OS_TYPE="linux"
BINARY_NAME="oci-manager"

if [ "$ARCH" == "x86_64" ]; then
    TARGET="x86_64-unknown-linux-gnu"
elif [ "$ARCH" == "aarch64" ]; then
    TARGET="aarch64-unknown-linux-gnu"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

# 2. Check if binary exists in current dir, or ask where it is
if [ -f "./$BINARY_NAME" ]; then
    echo "Found binary in current directory."
else
    echo "Binary '$BINARY_NAME' not found in current directory."
    echo "Please download it from GitHub Releases first."
    exit 1
fi

# 3. Setup Directories
INSTALL_DIR="/usr/local/bin"
CONF_DIR="/etc/oci-manager"

sudo mkdir -p $CONF_DIR
sudo cp "./$BINARY_NAME" "$INSTALL_DIR/"
sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"

# 4. Check for config file
if [ ! -f "$CONF_DIR/config" ]; then
    echo "Creating dummy config at $CONF_DIR/config"
    echo "Please edit this file with your OCI credentials!"
    sudo bash -c "cat <<EOF > $CONF_DIR/config
[DEFAULT]
user=ocid1.user.oc1..aaaaaaa
fingerprint=00:00:00...
tenancy=ocid1.tenancy.oc1..aaaaaaa
region=us-phoenix-1
key_file=$CONF_DIR/key.pem
enable_admin=true
admin_key=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
EOF"
fi

# 5. Create Systemd Service
echo "Configuring systemd service..."

sudo bash -c "cat <<EOF > /etc/systemd/system/oci-manager.service
[Unit]
Description=OCI Manager Web Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$CONF_DIR
ExecStart=$INSTALL_DIR/$BINARY_NAME --config $CONF_DIR/config serve --host 0.0.0.0 --port 8080
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF"

# 6. Finalize
sudo systemctl daemon-reload
echo ""
echo "Installation complete! / 安装完成！"
echo "------------------------------------------------"
echo "1. Edit config: sudo nano $CONF_DIR/config"
echo "2. Place your .pem key in: $CONF_DIR/key.pem"
echo "3. Start service: sudo systemctl start oci-manager"
echo "4. Enable on boot: sudo systemctl enable oci-manager"
echo "5. Check status: sudo systemctl status oci-manager"
echo "------------------------------------------------"
echo "Web UI will be at: http://YOUR_IP:8080"
