# Makefile

BPF_CFLAGS   = -O2 -target bpf -c
USER_CFLAGS  = -Wall -O2 -I/usr/include -I/usr/local/include -I/usr/include/bpf
USER_LDFLAGS = -lelf -lbpf -lpthread -lz -lrt

BPF_PROG  = ddos_protect.o
USER_PROG = main

SRC_DIR   = src
PKG_DIR   = pkg
BUILD_DIR = build

# Ensure build directory exists
$(shell mkdir -p $(BUILD_DIR))

all: $(BUILD_DIR)/$(BPF_PROG) $(BUILD_DIR)/$(USER_PROG)

# Compile eBPF program
$(BUILD_DIR)/$(BPF_PROG): $(SRC_DIR)/ddos_protect.c
	clang $(BPF_CFLAGS) $< -o $@

# Compile user-space program
$(BUILD_DIR)/$(USER_PROG): $(SRC_DIR)/main.c
	gcc $(USER_CFLAGS) $< -o $@ $(USER_LDFLAGS)

# Simple clean
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BUILD_DIR)/$(BPF_PROG) $(BUILD_DIR)/$(USER_PROG)

# Remove the entire build directory
clobber:
	@echo "Removing entire build directory..."
	rm -rf $(BUILD_DIR)

# Build Debian package
pkg: all
	@echo "Building Debian package..."
	mkdir -p $(BUILD_DIR)/debian
	cp -r debian/* $(BUILD_DIR)/debian/
	cp $(BUILD_DIR)/$(BPF_PROG) $(BUILD_DIR)/$(USER_PROG) $(BUILD_DIR)/debian/
	cp $(PKG_DIR)/self_start.sh $(PKG_DIR)/self_stop.sh $(BUILD_DIR)/debian/
	# Run dpkg-buildpackage within the build directory
	cd $(BUILD_DIR) && dpkg-buildpackage -us -uc -b

# Alias
deb: pkg

# Remove Debian build artifacts from previous packaging
debian-clean:
	@echo "Cleaning Debian packaging artifacts..."
	rm -rf $(BUILD_DIR)/debian
	rm -f ../self_*.deb ../self_*.changes ../self_*.buildinfo ../self_*.dsc

# Thoroughly remove everything including Debian artifacts
debian-clobber: clobber debian-clean

.PHONY: all clean clobber pkg deb start stop debian-clean debian-clobber
