#!/bin/bash
set -e

CLIENT_PID_FILE="/var/run/self_client.pid"

# Check if user is root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Stop client process
if [ -f "$CLIENT_PID_FILE" ]; then
    CLIENT_PID=$(cat "$CLIENT_PID_FILE")
    if ps -p $CLIENT_PID > /dev/null; then
        echo "Stopping client process with PID $CLIENT_PID..."
        kill $CLIENT_PID
    else
        echo "Client process not active, removing stale PID file."
    fi
    rm "$CLIENT_PID_FILE"
else
    echo "Client PID file not found, no client process to stop."
fi

# Stopping main program
if [ -f /var/run/self.pid ]; then
    PID=$(cat /var/run/self.pid)
    if ps -p $PID > /dev/null; then
        echo "Stopping process with PID $PID..."
        kill $PID
        rm /var/run/self.pid
    else
        echo "Process is not active"
        rm /var/run/self.pid
    fi
else
    echo "PID file does not exist"
fi

echo "Service stopped." 