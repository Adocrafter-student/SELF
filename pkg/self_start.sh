#!/bin/bash
set -e

# Configuration file path
CONFIG_FILE="/etc/self/self.conf"
SERVER_CONFIG_FILE="/etc/self/server.conf"
CLIENT_PID_FILE="/var/run/self_client.pid"
CLIENT_SCRIPT_PATH="/usr/lib/self/backend/fetch_stats.py"

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

# Start client if server.conf exists
if [ -f "$SERVER_CONFIG_FILE" ]; then
    echo "Server config found, managing client process..."
    if [ -f "$CLIENT_PID_FILE" ]; then
        PID=$(cat "$CLIENT_PID_FILE")
        if ps -p $PID > /dev/null; then
            echo "Killing existing client process with PID $PID..."
            kill $PID
        else
            echo "Stale PID file found, removing..."
        fi
        rm "$CLIENT_PID_FILE"
    fi
    
    echo "Starting new client process..."
    python3 "$CLIENT_SCRIPT_PATH" &
    echo $! > "$CLIENT_PID_FILE"
else
    echo "Server config not found, client not started."
fi

exec /usr/lib/self/main --interface="$INTERFACE"


echo "SELF started successfully" 