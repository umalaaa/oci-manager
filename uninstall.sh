#!/bin/bash

# OCI Manager - Uninstall Script
# Stops services and removes all files

set -e

BINARY_NAME="oci-manager"

echo "------------------------------------------------"
echo "OCI Manager Uninstaller / OCI 管理器卸载脚本"
echo "------------------------------------------------"

# 1. Detection
IS_ROOT=false
if [ "$EUID" -eq 0 ]; then IS_ROOT=true; fi

if [ "$IS_ROOT" = true ]; then
    BASE_DIR="/opt/oci-manager"
    SERVICE_PATH="/etc/systemd/system/oci-manager.service"
    SYSTEMCTL_CMD="systemctl"
else
    BASE_DIR="$HOME/oci-manager"
    SERVICE_PATH="$HOME/.config/systemd/user/oci-manager.service"
    SYSTEMCTL_CMD="systemctl --user"
fi

echo "This will stop the service and delete all files in: $BASE_DIR"
read -p "Are you sure? (y/n): " confirm
if [ "$confirm" != "y" ]; then
    echo "Aborted."
    exit 0
fi

# 2. Stop & Disable Service
echo "Stopping and disabling service..."
$SYSTEMCTL_CMD stop oci-manager 2>/dev/null || true
$SYSTEMCTL_CMD disable oci-manager 2>/dev/null || true

# 3. Remove Service File
echo "Removing service file..."
[ -f "$SERVICE_PATH" ] && rm -f "$SERVICE_PATH"

# 4. Remove Base Directory (binary, config, version, etc.)
if [ -d "$BASE_DIR" ]; then
    echo "Deleting directory: $BASE_DIR"
    rm -rf "$BASE_DIR"
fi

# 5. Finalize
$SYSTEMCTL_CMD daemon-reload 2>/dev/null || true
echo "------------------------------------------------"
echo "Uninstallation complete! / 卸载完成！"
echo "------------------------------------------------"
