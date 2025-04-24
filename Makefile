# Paths and variables
BPFOBJ = pkg/syscallfilter/syscallfilter_x86_bpfel.o pkg/privilege/privilege_x86_bpfel.o pkg/fileaccess/fileaccess_x86_bpfel.o
BPFOBJ_GO = pkg/syscallfilter/syscallfilter_x86_bpfel.go pkg/privilege/privilege_x86_bpfel.go pkg/fileaccess/fileaccess_x86_bpfel.go
EBPF_DIR = src
VMLINUX = $(EBPF_DIR)/vmlinux.h
GO_CLI_DIR = .
CLI_BINARY = heimdall

# Default target
all: $(VMLINUX) build-bpf-obj build-cli

# Generate vmlinux.h using bpftool
$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

# Compile eBPF program using "go generate"
build-bpf-obj: $(VMLINUX)
	go generate

# Build the Go CLI userspace binary
build-cli:
	go build -o $(CLI_BINARY) $(GO_CLI_DIR)/main.go

# Format Go code
fmt:
	gofmt -s -w .

# Run Go tests
test:
	go test ./...

# Lint Go code (requires golint or staticcheck installed)
lint:
	staticcheck ./...

# Clean generated files
clean:
	rm -f $(VMLINUX) $(BPFOBJ) $(BPFOBJ_GO) $(CLI_BINARY)

# Clean and rebuild everything
rebuild: clean all

# Help
help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Available targets:"
	@echo "  all           Build everything (default)"
	@echo "  vmlinux       Generate vmlinux.h using bpftool"
	@echo "  build-bpf-obj Compile eBPF object files with go generate"
	@echo "  build-cli     Build the Go userspace CLI binary"
	@echo "  fmt           Format Go source code"
	@echo "  test          Run Go unit tests"
	@echo "  lint          Run linter on Go code (requires staticcheck)"
	@echo "  clean         Remove all generated files"
	@echo "  rebuild       Clean and build everything from scratch"
	@echo "  help          Show this help message"

.PHONY: all build-bpf-obj build-cli fmt test lint clean rebuild help
