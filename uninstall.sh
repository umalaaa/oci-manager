#!/bin/bash

# OCI Manager - Uninstall Script
# Stops services and removes all files

set -e

REPO="umalaaa/oci-manager"
BINARY_NAME="oci-manager"

echo "------------------------------------------------"
echo "OCI Manager Uninstaller / OCI 管理器卸载脚本"
echo "------------------------------------------------"

# 1. Detection
IS_ROOT=false
if [ "$EUID" -eq 0 ]; then IS_ROOT=true; fi

if [ "$IS_ROOT" = true ]; then
    INSTALL_DIR="/usr/local/bin"
    CONF_DIR="/etc/oci-manager"
    SERVICE_PATH="/etc/systemd/system/oci-manager.service"
    SYSTEMCTL_CMD="systemctl"
else
    INSTALL_DIR="$HOME/.local/bin"
    CONF_DIR="$HOME/.oci-manager"
    SERVICE_PATH="$HOME/.config/systemd/user/oci-manager.service"
    SYSTEMCTL_CMD="systemctl --user"
fi

echo "This will stop the service and delete all configuration and binaries."
read -p "Are you sure? (y/n): " confirm
if [ "$confirm" != "y" ]; then
    echo "Aborted."
    exit 0
fi

# 2. Stop & Disable Service
echo "Stopping and disabling service..."
$SYSTEMCTL_CMD stop oci-manager || true
$SYSTEMCTL_CMD disable oci-manager || true

# 3. Remove Files
echo "Removing files..."
[ -f "$SERVICE_PATH" ] && rm -f "$SERVICE_PATH"
[ -f "$INSTALL_DIR/$BINARY_NAME" ] && rm -f "$INSTALL_DIR/$BINARY_NAME"

if [ -d "$CONF_DIR" ]; then
    echo "Deleting configuration directory: $CONF_DIR"
    rm -rf "$CONF_DIR"
fi

# 4. Finalize
$SYSTEMCTL_CMD daemon-reload
echo "------------------------------------------------"
echo "Uninstallation complete! / 卸载完成！"
echo "------------------------------------------------"
