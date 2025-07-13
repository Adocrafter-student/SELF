# SELF: Self-Learning Firewall

A sophisticated, adaptive DDoS protection system built with eBPF/XDP technology that learns and adapts to network threats in real-time.

## 🚀 Key Features

### 🧠 Self-Learning & Adaptive Protection
- **Adaptive Scoring System**: Dynamic threat scoring (0-100) that adapts to network behavior
- **Self-Learning Algorithm**: Automatically learns legitimate traffic patterns
- **Real-time Threat Assessment**: Continuous evaluation of IP address behavior
- **Intelligent Ban Escalation**: Multiple ban levels from 15 seconds to permanent

### ⚡ High-Performance Architecture
- **eBPF/XDP Technology**: Kernel-level packet filtering for maximum performance
- **Zero-Copy Processing**: Minimal CPU overhead and maximum throughput
- **Pinned BPF Maps**: Persistent state across service restarts
- **Multi-threaded Design**: Parallel processing for optimal performance

### 🔧 Advanced Configuration
- **YAML-Based Configuration**: Human-readable, version-controlled settings
- **Dynamic Configuration Updates**: Change settings which are immediate after service restart
- **Protocol-Specific Thresholds**: Separate limits for TCP, UDP, and ICMP
- **Customizable Scoring Rules**: Fine-tune scoring algorithm parameters

### 🛡️ Comprehensive Protection
- **Multi-Protocol Support**: TCP, UDP, ICMP flood protection
- **SYN Flood Protection**: Advanced TCP SYN attack mitigation
- **Whitelist System**: Protect legitimate IPs from being blocked
- **Flood Detection**: Rate-based attack detection with configurable windows
- **Connection Tracking**: Monitor established vs. half-open connections

### 📊 Monitoring & Management
- **Real-time Statistics**: Live monitoring of traffic and threats
- **Comprehensive Logging**: Detailed event logging with multiple levels
- **CLI Management Tool**: Feature-rich command-line interface
- **Systemd Integration**: Full service management support

## 🏗️ Architecture Overview

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Network       │    │   eBPF/XDP      │    │   User Space    │
│   Interface     │───▶│   Filter        │───▶│   SELF Daemon   │
│   (eth0, etc.)  │    │   (Kernel)      │    │   (main)        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │                        │
                              │                        │
                              ▼                        ▼
                       ┌─────────────────┐    ┌─────────────────┐
                       │   BPF Maps      │    │   Configuration │
                       │   (Persistent   │    │   (YAML)        │
                       │    State)       │    │   & Whitelist   │
                       └─────────────────┘    └─────────────────┘
                              │
                              │
                              ▼
                       ┌─────────────────┐
                       │   self-tool     │
                       │   (CLI Mgmt)    │
                       └─────────────────┘
```

## 🎯 Adaptive Scoring System

The heart of SELF is its adaptive scoring system that intelligently assesses threat levels:

### Score Calculation
- **Base Score**: 0-100 scale for each IP address
- **Dynamic Adjustments**: Real-time score modifications based on behavior
- **Threshold-Based Actions**: Automatic ban escalation based on score ranges

### Default Scoring Rules
| Event Type | Score Change | Description |
|------------|--------------|-------------|
| **Half-Open SYN** | +2 | Incomplete TCP handshake |
| **Successful Handshake** | -5 | Legitimate connection established |
| **Flood Detection** | +15 | Rate threshold exceeded |
| **Repeated SYN** | +2 | Multiple SYN attempts |

### Default Ban Levels
| Score Range | Ban Duration | Use Case |
|-------------|--------------|----------|
| **90-100** | Permanent | Persistent attackers |
| **80-89** | 15 days | Severe violations |
| **70-79** | 4 days | Repeated offenses |
| **50-69** | 1 day | Moderate violations |
| **30-49** | 15 minutes | Minor violations |
| **20-29** | 1 minute | Temporary blocks |
| **10-19** | 15 seconds | Initial warnings |

## 🛠️ Installation

### Prerequisites
- Linux kernel 6.2+ with eBPF/XDP support
- libbpf development libraries
- libyaml development libraries
- clang/LLVM for eBPF compilation

### Build from Source
```bash
# Clone the repository
git clone <repository-url>
cd SELF

# Initialize submodules
git submodule update --init --recursive

# Build the project
make product

# Install system package
sudo make install
```

### Package Installation
```bash
# Build Debian package
make pkg

# Install the package
sudo dpkg -i build/self_1.0.0-1_amd64.deb
```

## ⚙️ Configuration

### Main Configuration File
Edit `/etc/self/self_metric.yaml`:

```yaml
# Scoring thresholds
scores:
  permanent_ban: 90      # Permanent ban score
  ban_15_days: 80        # 15-day ban score
  ban_4_days: 70         # 4-day ban score
  ban_1_day: 50          # 1-day ban score
  ban_15_min: 30         # 15-minute ban score
  ban_1_min: 20          # 1-minute ban score
  ban_15_sec: 10         # 15-second ban score
  half_open_inc: 2       # Score increase for half-open connections
  handshake_dec: 5       # Score decrease for successful handshakes
  flood_inc: 15          # Score increase for flood detection
  max: 100               # Maximum score

# Flood detection settings
flood_detection:
  window_ns: 1000000000  # 1 second window

# Protocol-specific thresholds
thresholds:
  generic:
    packets: 300         # Generic packet threshold
    bytes: 2097152       # Generic byte threshold (2MB)
  icmp:
    packets: 100         # ICMP packet threshold
    bytes: 262144        # ICMP byte threshold (256KB)
  udp:
    packets: 300         # UDP packet threshold
    bytes: 1048576       # UDP byte threshold (1MB)
  tcp:
    packets: 1000        # TCP packet threshold
    bytes: 1048576       # TCP byte threshold (1MB)
```

### Whitelist Configuration
Edit `/etc/self/whitelist.conf`:
```
# Whitelist trusted IP addresses
192.168.1.0
10.1.2.3
172.16.2
8.8.8.8
```

### Interface Configuration
Edit `/etc/self/self.conf`:
```
INTERFACE="eth0"
```

## 🚀 Usage

### Service Management
```bash
# Start the service
sudo systemctl start self

# Enable auto-start
sudo systemctl enable self

# Check status
sudo systemctl status self

# View logs
sudo journalctl -u self -f

## 🔧 Management with self-tool

The `self-tool` command provides comprehensive management capabilities:

### Traffic Monitoring
```bash
# List all monitored IPs and statistics
sudo self-tool list

# Show overall statistics
sudo self-tool stats

# Show current configuration
sudo self-tool config
```

### Threat Assessment
```bash
# View current IP threat scores
sudo self-tool scores

# Monitor flood detection statistics
sudo self-tool flood-stats

# List established TCP connections
sudo self-tool established
```

### IP Management
```bash
# Block an IP permanently
sudo self-tool block 192.168.1.100

# Block an IP for specific duration
sudo self-tool block 192.168.1.100 2d13h14m5s

# List all blocked IPs
sudo self-tool list-blocked

# Unblock an IP
sudo self-tool unblock 192.168.1.100
```

### Whitelist Management
```bash
# Add IP to whitelist
sudo self-tool whitelist-add 192.168.1.50

# Show whitelisted IPs
sudo self-tool whitelist-show

# Remove IP from whitelist
sudo self-tool whitelist-remove 192.168.1.50
```

### System Maintenance
```bash
# Clear all traffic statistics
sudo self-tool clear

# Reset all collected data
sudo self-tool clear
```

## 📊 Monitoring & Logging

### Log Files
- **System logs**: `journalctl -u self`
- **YAML parsing logs**: `/tmp/yaml_parse.log`
- **Debug logs**: Available with `--verbose` flag

### Real-time Monitoring
```bash
# Monitor live traffic
sudo self-tool list

# Watch blocked IPs
watch -n 2 'sudo self-tool list-blocked'

# Monitor scores
watch -n 5 'sudo self-tool scores'
```

### Event Types
The system logs various event types:
- `EV_NEW_IP`: New IP address detected
- `EV_BLOCK`: IP blocked due to threshold
- `EV_UNBLOCK`: IP unblocked after cooldown
- `EV_HANDSHAKE_COMPLETE`: TCP handshake completed
- `EV_FLOOD_DETECTED`: Flood attack detected
- `EV_SYN_RETRY_PENALTY`: SYN retry penalty applied

## 🔍 Troubleshooting

### Common Issues

**eBPF Program Load Failed**
```bash
# Check kernel version
uname -r

# Verify eBPF support
sudo modprobe bpf
```

**Permission Denied**
```bash
# Check memlock limits
ulimit -l

# Run as root
sudo /usr/lib/self/main
```

### Performance Tuning
- Adjust map sizes in source code for high-traffic environments
- Tune threshold values based on legitimate traffic patterns
- Monitor system resources with `htop` and `iotop`

## 📈 Performance Characteristics

- **Packet Processing**: 1M+ packets/second
- **Memory Usage**: ~50MB typical
- **CPU Overhead**: <5% on modern systems
- **Latency Impact**: <1µs per packet

## 🤝 Contributing

This project is licensed under CC BY-NC 4.0. Commercial use requires written permission.

### Development Setup
```bash
# Development build
make clobber && make product

# Package build
make pkg
```

## 📄 License

This project is licensed under the [CC BY-NC 4.0 License](https://creativecommons.org/licenses/by-nc/4.0/).

**Commercial licensing is available upon request.**

- Non-commercial use: ✅ Permitted
- Commercial use: ❌ Requires written permission
- Academic reuse: ❌ Requires written permission

## 🙏 Acknowledgments

- **eBPF/XDP Technology**: Linux kernel community
- **libbpf**: Facebook/Meta open source
- **libyaml**: YAML community
- **Senior Design Project**: Academic research contribution

---

## 📞 Support

For commercial licensing, support, or feature requests, please contact the author.

**Note**: This is a sophisticated security tool. Proper configuration and monitoring are essential for production use.
**Note to myself** Please use following command to start frontend REACT_APP_API_URL=http://<your-python-server-ip>:5000 npm start