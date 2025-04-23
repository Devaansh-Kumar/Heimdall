# Paths and variables
BPFOBJ = pkg/syscallfilter/syscallfilter_x86_bpfel.o
BPFOBJ_GO = pkg/syscallfilter/syscallfilter_x86_bpfel.go
VMLINUX = vmlinux.h
EBPF_DIR = src
GO_CLI_DIR = .
CLI_BINARY = heimdall

# Default target
all: vmlinux build-bpf-obj build-cli

# Generate vmlinux.h using bpftool
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(EBPF_DIR)/$(VMLINUX)

# Compile eBPF program using "go generate"
build-bpf-obj: vmlinux
	go generate

# Build the Go CLI userspace binary
build-cli:
	go build -o $(CLI_BINARY) $(GO_CLI_DIR)/main.go

# Clean generated files
clean:
	rm -f $(EBPF_DIR)/$(VMLINUX) $(BPFOBJ) $(BPFOBJ_GO) $(CLI_BINARY)

# Clean and rebuild everything
rebuild: clean all

.PHONY: all vmlinux build-bpf-obj build-cli clean rebuild
