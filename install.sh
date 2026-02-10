#!/bin/bash

# OCI Manager - Quick Install & Systemd Service Setup
# Supports Ubuntu, CentOS, Debian, Oracle Linux (x86_64 & ARM64)

set -e

REPO="umalaaa/oci-manager"
BINARY_NAME="oci-manager"
INSTALL_DIR="/usr/local/bin"
CONF_DIR="/etc/oci-manager"
PORT=9927

echo "------------------------------------------------"
echo "OCI Manager Installer / OCI 管理器安装脚本"
echo "------------------------------------------------"

# 1. Detection
ARCH=$(uname -m)
if [ "$ARCH" == "x86_64" ]; then
    TARGET="x86_64-unknown-linux-gnu"
    FILENAME="oci-manager-x86_64-unknown-linux-gnu.tar.gz"
elif [ "$ARCH" == "aarch64" ]; then
    TARGET="aarch64-unknown-linux-gnu"
    FILENAME="oci-manager-aarch64-unknown-linux-gnu.tar.gz"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

# 2. Version Check
echo "Checking for updates..."
LATEST_VERSION=$(curl -sSf https://raw.githubusercontent.com/$REPO/main/VERSION | tr -d '[:space:]')
INSTALLED_VERSION=""
if [ -f "$CONF_DIR/version" ]; then
    INSTALLED_VERSION=$(cat "$CONF_DIR/version" | tr -d '[:space:]')
fi

if [ "$INSTALLED_VERSION" == "$LATEST_VERSION" ]; then
    echo "OCI Manager is already up to date (v$INSTALLED_VERSION)."
    exit 0
fi

echo "Installing version v$LATEST_VERSION (current: ${INSTALLED_VERSION:-none})..."

# 3. Download Binary
if [ ! -f "./$BINARY_NAME" ]; then
    echo "Downloading latest release for $ARCH..."
    LATEST_URL=$(curl -s https://api.github.com/repos/$REPO/releases/latest | grep "browser_download_url" | grep "$TARGET" | cut -d '"' -f 4)
    if [ -z "$LATEST_URL" ]; then
        echo "Error: Could not find download URL for $TARGET. Is the release published?"
        exit 1
    fi
    curl -L "$LATEST_URL" -o "$FILENAME"
    tar -xzf "$FILENAME"
    rm "$FILENAME"
fi

# 3. Setup Directories & Binary
echo "Installing to $INSTALL_DIR..."
sudo mkdir -p $CONF_DIR
sudo cp "./$BINARY_NAME" "$INSTALL_DIR/"
sudo chmod +x "$INSTALL_DIR/$BINARY_NAME"

# 4. Check for config file
if [ ! -f "$CONF_DIR/config" ]; then
    echo "Creating initial config at $CONF_DIR/config"
    GEN_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
    sudo bash -c "cat <<EOF > $CONF_DIR/config
# Web UI Settings
enable_admin=true
admin_key=$GEN_KEY
port=$PORT

[DEFAULT]
user=ocid1.user.oc1..aaaaaaa
fingerprint=aa:bb:cc...
tenancy=ocid1.tenancy.oc1..aaaaaaa
region=us-phoenix-1
key_file=$CONF_DIR/key.pem
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
ExecStart=$INSTALL_DIR/$BINARY_NAME --config $CONF_DIR/config serve --host 0.0.0.0 --port $PORT --allow-remote
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF"

# 6. Finalize
echo "$LATEST_VERSION" | sudo tee $CONF_DIR/version > /dev/null
sudo systemctl daemon-reload
echo ""
echo "Installation complete! / 安装完成！"
echo "------------------------------------------------"
echo "1. Edit config: sudo nano $CONF_DIR/config"
echo "2. Place your OCI API key (.pem) in: $CONF_DIR/key.pem"
echo "3. Start service: sudo systemctl start oci-manager"
echo "4. Enable on boot: sudo systemctl enable oci-manager"
echo "------------------------------------------------"
echo "Web UI will be at: http://YOUR_SERVER_IP:$PORT"
echo "Default Admin Key (Keep it safe!): $GEN_KEY"
echo "------------------------------------------------"
