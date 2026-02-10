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
IS_ROOT=false
if [ "$EUID" -eq 0 ]; then IS_ROOT=true; fi

# Set Base Directory
if [ "$IS_ROOT" = true ]; then
    BASE_DIR="/opt/oci-manager"
    SERVICE_PATH="/etc/systemd/system/oci-manager.service"
    SYSTEMCTL_CMD="systemctl"
else
    BASE_DIR="$HOME/oci-manager"
    mkdir -p "$HOME/.config/systemd/user"
    SERVICE_PATH="$HOME/.config/systemd/user/oci-manager.service"
    SYSTEMCTL_CMD="systemctl --user"
fi

BINARY_PATH="$BASE_DIR/$BINARY_NAME"
CONFIG_PATH="$BASE_DIR/config"
VERSION_PATH="$BASE_DIR/version"

echo "Installing to: $BASE_DIR"

if [ "$ARCH" == "x86_64" ]; then
    TARGET="x86_64-unknown-linux-musl"
    FILENAME="oci-manager-x86_64-unknown-linux-musl.tar.gz"
elif [ "$ARCH" == "aarch64" ]; then
    TARGET="aarch64-unknown-linux-musl"
    FILENAME="oci-manager-aarch64-unknown-linux-musl.tar.gz"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

# 2. Version Check
echo "Checking for updates..."
LATEST_VERSION=$(curl -sSf https://raw.githubusercontent.com/$REPO/main/VERSION | tr -d '[:space:]')
INSTALLED_VERSION=""
if [ -f "$VERSION_PATH" ]; then
    INSTALLED_VERSION=$(cat "$VERSION_PATH" | tr -d '[:space:]')
fi

if [ "$INSTALLED_VERSION" == "$LATEST_VERSION" ]; then
    echo "OCI Manager is already up to date (v$INSTALLED_VERSION)."
    exit 0
fi

echo "Installing version v$LATEST_VERSION (current: ${INSTALLED_VERSION:-none})..."

# 3. Create Directory
mkdir -p "$BASE_DIR"

# 4. Download Binary
if [ ! -f "$BINARY_PATH" ] || [ "$INSTALLED_VERSION" != "$LATEST_VERSION" ]; then
    echo "Downloading latest release for $ARCH..."
    LATEST_URL=$(curl -s https://api.github.com/repos/$REPO/releases/latest | grep "browser_download_url" | grep "$TARGET" | cut -d '"' -f 4)
    if [ -z "$LATEST_URL" ]; then
        echo "Error: Could not find download URL for $TARGET. Is the release published?"
        exit 1
    fi
    curl -L "$LATEST_URL" -o "$FILENAME"
    tar -xzf "$FILENAME"
    mv "$BINARY_NAME" "$BINARY_PATH"
    rm "$FILENAME"
    chmod +x "$BINARY_PATH"
fi

# 5. Check for config file
if [ ! -f "$CONFIG_PATH" ]; then
    echo "Creating initial config at $CONFIG_PATH"
    GEN_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
    cat <<EOF > "$CONFIG_PATH"
# Web UI Settings
enable_admin=true
admin_key=$GEN_KEY
port=$PORT

[DEFAULT]
user=ocid1.user.oc1..aaaaaaa
fingerprint=aa:bb:cc...
tenancy=ocid1.tenancy.oc1..aaaaaaa
region=us-phoenix-1
key_file=$BASE_DIR/key.pem
EOF
fi

# 6. Create Service
echo "Configuring service at $SERVICE_PATH..."
cat <<EOF > "$SERVICE_PATH"
[Unit]
Description=OCI Manager Web Service
After=network.target

[Service]
Type=simple
WorkingDirectory=$BASE_DIR
ExecStart=$BINARY_PATH --config $CONFIG_PATH serve --host 0.0.0.0 --port $PORT --allow-remote
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF

# 7. Finalize
echo "$LATEST_VERSION" > "$VERSION_PATH"
$SYSTEMCTL_CMD daemon-reload
echo ""
echo "Installation complete! / 安装完成！"
echo "------------------------------------------------"
echo "1. Edit config: nano $CONFIG_PATH"
echo "2. Place your OCI API key (.pem) in: $BASE_DIR/key.pem"
echo "3. Start service: $SYSTEMCTL_CMD start oci-manager"
echo "4. Enable on boot: $SYSTEMCTL_CMD enable oci-manager"
echo "5. Check status: $SYSTEMCTL_CMD status oci-manager"
if [ "$IS_ROOT" = false ]; then
    echo "Note: For non-root persistent service, run: sudo loginctl enable-linger \$USER"
fi
echo "------------------------------------------------"
echo "Web UI will be at: http://YOUR_SERVER_IP:$PORT"
if [ -n "$GEN_KEY" ]; then
    echo "Default Admin Key (Keep it safe!): $GEN_KEY"
fi
echo "------------------------------------------------"
