#!/bin/bash
set -e

# Default interface
INTERFACE="eth0"


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