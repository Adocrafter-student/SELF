#!/bin/bash
set -e

# Check if user is root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

# Directory for BPF maps
BPF_MOUNT="/sys/fs/bpf"
if [ ! -d "$BPF_MOUNT" ]; then
    echo "Creating bpf filesystem mount..."
    mkdir -p "$BPF_MOUNT"
    mount -t bpf bpf "$BPF_MOUNT"
fi

# Loading eBPF program
PROG_DIR="/usr/lib/self"
echo "Loading eBPF program..."

# Starting main program
echo "Starting main program..."
/usr/lib/self/main &
echo $! > /var/run/self.pid

echo "Service started." 