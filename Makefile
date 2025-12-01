# Makefile for Lattice-Based Group Signature System

# Build configuration
BINARY_NAME=lattice-gs
GO=go
CGO_ENABLED=1

# Platform detection
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

# Default target
.PHONY: all
all: build

# Standard build (no CGO)
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	@CGO_ENABLED=0 $(GO) build -o $(BINARY_NAME)
	@echo "✓ Build complete"

# Build with CGO for GPU support
.PHONY: build-cgo
build-cgo:
	@./build_cgo.sh

# Build with verbose output
.PHONY: build-verbose
build-verbose:
	@./build_cgo.sh --verbose

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	@$(GO) test -v ./...

# Run benchmarks
.PHONY: benchmark
benchmark:
	@echo "Running benchmarks..."
	@./scripts/benchmark_gpu.sh

# Run demo
.PHONY: demo
demo:
	@echo "Running demo..."
	@./scripts/demo.sh

# Show statistics
.PHONY: stats
stats: build
	@./$(BINARY_NAME) stats

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning..."
	@rm -f $(BINARY_NAME)
	@rm -rf ~/.lattice-gs
	@echo "✓ Clean complete"

# Install to system
.PHONY: install
install: build-cgo
	@echo "Installing $(BINARY_NAME)..."
	@cp $(BINARY_NAME) /usr/local/bin/
	@echo "✓ Installed to /usr/local/bin/$(BINARY_NAME)"

# Uninstall from system
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	@rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "✓ Uninstalled"

# Development build with race detector
.PHONY: dev
dev:
	@echo "Building with race detector..."
	@CGO_ENABLED=1 $(GO) build -race -o $(BINARY_NAME)
	@echo "✓ Development build complete"

# Quick test workflow
.PHONY: quick-test
quick-test: build
	@echo "Running quick test..."
	@./$(BINARY_NAME) gm setup --lambda 32 --max-users 4 --force > /dev/null 2>&1
	@./$(BINARY_NAME) member keygen 0 > /dev/null 2>&1
	@./$(BINARY_NAME) gm issue 0 > /dev/null 2>&1
	@./$(BINARY_NAME) member sign 0 "test" > /dev/null 2>&1
	@echo "✓ Quick test passed"

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	@$(GO) fmt ./...
	@echo "✓ Format complete"

# Lint code
.PHONY: lint
lint:
	@echo "Linting code..."
	@golangci-lint run ./... || echo "Install golangci-lint for linting"

# Show GPU info
.PHONY: gpu-info
gpu-info: build-cgo
	@./$(BINARY_NAME) stats

# Help
.PHONY: help
help:
	@echo "Lattice-Based Group Signature System - Build Commands"
	@echo ""
	@echo "Basic Commands:"
	@echo "  make build          - Build without CGO (default)"
	@echo "  make build-cgo      - Build with CGO for GPU support"
	@echo "  make build-verbose  - Build with verbose output"
	@echo "  make clean          - Remove build artifacts"
	@echo ""
	@echo "Testing:"
	@echo "  make test          - Run Go tests"
	@echo "  make quick-test    - Run quick integration test"
	@echo "  make benchmark     - Run performance benchmarks"
	@echo "  make demo          - Run full system demo"
	@echo ""
	@echo "GPU Support:"
	@echo "  make gpu-info      - Show GPU configuration"
	@echo "  make stats         - Show performance statistics"
	@echo ""
	@echo "Development:"
	@echo "  make dev           - Build with race detector"
	@echo "  make fmt           - Format Go code"
	@echo "  make lint          - Lint Go code"
	@echo ""
	@echo "Installation:"
	@echo "  make install       - Install to /usr/local/bin"
	@echo "  make uninstall     - Remove from /usr/local/bin"
	@echo ""
	@echo "Platform: $(UNAME_S) $(UNAME_M)"

# Default help on no target
.DEFAULT_GOAL := help
