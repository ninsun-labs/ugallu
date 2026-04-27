# Regenerate the BPF artifacts consumed by the resolver eBPF tracker.
#
# Toolchain prerequisites (Fedora):
#   sudo dnf install clang llvm bpftool libbpf-devel
#
# `make generate` regenerates `vmlinux.h` from the running kernel's
# BTF and re-runs `go generate ./...` (which invokes bpf2go and
# refreshes cgrouptracker_*_bpfel.{go,o}). Commit the bpf2go output
# alongside the C source; downstream builds need neither clang nor
# bpftool.

.PHONY: generate vmlinux.h clean

PACKAGE_DIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))/..

generate: vmlinux.h
	cd $(PACKAGE_DIR) && go generate ./...

vmlinux.h:
	@if [ ! -r /sys/kernel/btf/vmlinux ]; then \
		echo "kernel BTF unavailable at /sys/kernel/btf/vmlinux"; \
		exit 1; \
	fi
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f vmlinux.h
	rm -f $(PACKAGE_DIR)/cgrouptracker_*_bpfel.go
	rm -f $(PACKAGE_DIR)/cgrouptracker_*_bpfel.o
