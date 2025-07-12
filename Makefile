# Makefile

# Directories
SRC_DIR     := src
BUILD_DIR   := build
PKG_DIR     := pkg
LIBBPF_DIR  := third_party/libbpf
LIBYAML_DIR := third_party/libyaml

# Files
BPF_PROG    := ddos_protect.o
USER_PROG   := main
SELF_TOOL   := self-tool

# Create build directory if not exists
$(shell mkdir -p $(BUILD_DIR))

# Source files
SRCS := $(SRC_DIR)/main.c $(SRC_DIR)/logger.c $(SRC_DIR)/config.c
OBJS := $(SRCS:.c=.o)

# Compilation flags
BPF_CFLAGS   := -g -O2 -target bpf -c
USER_CFLAGS  := -Wall -O2 -I$(SRC_DIR) -I$(LIBBPF_DIR)/src -I$(LIBYAML_DIR)/include
USER_LDFLAGS := $(LIBBPF_DIR)/src/libbpf.a $(LIBYAML_DIR)/src/.libs/libyaml.a -lelf -lz -lpthread -lrt

# Default target
all: $(BUILD_DIR)/$(BPF_PROG) $(BUILD_DIR)/$(USER_PROG) $(BUILD_DIR)/$(SELF_TOOL)

# Build libyaml if not already built
$(LIBYAML_DIR)/src/.libs/libyaml.a:
	cd $(LIBYAML_DIR) && ./bootstrap && ./configure --enable-static --disable-shared && make

# Compile eBPF program
$(BUILD_DIR)/$(BPF_PROG): $(SRC_DIR)/ddos_protect.c
	clang $(BPF_CFLAGS) $< -o $@

# Compile user-space loader (main binary)
$(BUILD_DIR)/$(USER_PROG): $(SRCS) $(LIBYAML_DIR)/src/.libs/libyaml.a
	$(CC) $(USER_CFLAGS) $(SRCS) -o $@ $(USER_LDFLAGS)

# Compile self-tool
$(BUILD_DIR)/$(SELF_TOOL): $(SRC_DIR)/self_tool/self_tool.c
	$(CC) $(USER_CFLAGS) -o $@ $< $(USER_LDFLAGS)

# Just compile everything (like all)
self: all
	@echo "SELF build complete – binaries compiled."

# Build Debian package
pkg: all
	@echo "Building Debian package..."
	$(PKG_DIR)/pkg_make.sh

# Full build product
product: all pkg
	@echo "SELF product build complete – binaries compiled and packaged."

# Clean just binaries
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BUILD_DIR)/$(BPF_PROG) $(BUILD_DIR)/$(USER_PROG) $(BUILD_DIR)/$(SELF_TOOL)

# Full cleanup
clobber:
	@echo "Removing entire build directory..."
	rm -rf $(BUILD_DIR)

.PHONY: all clean clobber self pkg product
