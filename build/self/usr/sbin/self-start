#!/bin/bash
set -e

# Configuration file path
CONFIG_FILE="/etc/self/self.conf"

# Function to get first available interface
get_first_interface() {
    ls /sys/class/net | head -n 1
}

# Read interface from config file if it exists and is not commented
if [ -f "$CONFIG_FILE" ]; then
    INTERFACE=$(grep "^INTERFACE=" "$CONFIG_FILE" | cut -d'=' -f2 | tr -d '"' | tr -d "'")
    if [ -z "$INTERFACE" ]; then
        INTERFACE=$(get_first_interface)
    fi
else
    INTERFACE=$(get_first_interface)
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi


if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
    echo "Interface $INTERFACE does not exist"
    exit 1
fi


echo "Starting SELF on interface $INTERFACE..."
exec /usr/lib/self/main --interface="$INTERFACE"


echo "SELF started successfully" 