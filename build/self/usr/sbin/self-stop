#!/bin/bash
set -e

# Check if user is root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
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