# Project configuration.
PROJECT := github.com/globalcyberalliance/domain-security-scanner/v3
CGO_ENABLED := 0

# Tool paths.
GO := $(shell which go 2>/dev/null)
GOFIELDALIGNMENT := $(shell which betteralign 2>/dev/null)
GOFUMPT := $(shell which gofumpt 2>/dev/null)
GOLINTER := $(shell which golangci-lint 2>/dev/null)
GONILAWAY := $(shell which nilaway 2>/dev/null)

# Build configuration.
GO_PRIVATE := GOPRIVATE=github.com/globalcyberalliance
BUILD_FLAGS := -ldflags "-s -w" -trimpath

# Common build variables.
GO_BUILD_BASE := $(GO_PRIVATE) CGO_ENABLED=$(CGO_ENABLED)
GO_BUILD := $(GO_BUILD_BASE) $(GO) build $(BUILD_FLAGS)

# Other tool commands.
GO_FORMAT := $(GOFUMPT) -w
GO_OPTIMIZE := $(GOFIELDALIGNMENT) -fix
GO_TEST := $(GO) test -v -short
GO_TIDY := $(GO) mod tidy

# Build targets.
TARGETS := bin/dss

# Default target.
all: check-dependencies prepare optimize $(TARGETS) clean

# Development build (no optimization).
dev: prepare $(TARGETS)

# Pattern rule for building binaries.
bin/%: $(shell find . -name "*.go" -type f)
	@echo "Building $@..."
	@if [ "$(MAKECMDGOALS)" != "dev" ]; then \
		cd build && $(GO_BUILD) -o ../$@ $(PROJECT)/cmd/$*; \
	else \
		$(GO_BUILD) -o $@ $(PROJECT)/cmd/$*; \
	fi

# Dependency checks.
check-dependencies:
	@echo "Checking dependencies..."
	@if [ -z "$(GO)" ]; then \
		echo "Error: Cannot find 'go' in your PATH"; \
		exit 1; \
	fi
	@if [ -z "$(GOFIELDALIGNMENT)" ]; then \
		echo "Error: Cannot find 'betteralign' in your PATH"; \
		exit 1; \
	fi

# Cleanup tasks.
clean:
	@echo "Cleaning temporary build directory..."
	@rm -rf build

clean-all: clean
	@echo "Cleaning all build artifacts..."
	@rm -rf bin

# Code formatting and optimization.
format:
	@if [ -z "$(GOFUMPT)" ]; then \
		echo "Error: Cannot find 'gofumpt' in your PATH"; \
		exit 1; \
	fi
	@echo "Formatting code..."
	@$(GO_FORMAT) $(PWD)

lint:
	@if [ -z "$(GOLINTER)" ]; then \
		echo "Error: Cannot find 'golangci-lint' in your PATH"; \
		exit 1; \
	fi
	@echo "Running linter..."
	@$(GOLINTER) run ./...

lint-fix:
	@if [ -z "$(GOLINTER)" ]; then \
		echo "Error: Cannot find 'golangci-lint' in your PATH"; \
		exit 1; \
	fi
	@echo "Running linter with autofix..."
	@$(GOLINTER) run --fix ./...

nil-check:
	@if [ -z "$(GONILAWAY)" ]; then \
		echo "Error: Cannot find 'nilaway' in your PATH"; \
		exit 1; \
	fi
	@echo "Running nilaway..."
	@$(GONILAWAY) ./...

optimize:
	@echo "Creating temporary build directory..."
	@cp -r cmd go.* pkg build/
	@echo "Optimizing struct field alignment..."
	@cd build && $(GO_OPTIMIZE) ./... > /dev/null 2>&1 || true

# Preparation tasks.
prepare:
	@echo "Cleaning previous builds..."
	@rm -rf bin build
	@mkdir -p bin build
	@$(GO_TIDY)

# Development setup.
setup:
	@echo "Installing development dependencies..."
	@$(GO) install github.com/dkorunic/betteralign/cmd/betteralign@latest
	@$(GO) install mvdan.cc/gofumpt@latest
	@$(GO) install go.uber.org/nilaway/cmd/nilaway@latest
	@$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Testing.
test:
	@echo "Running tests..."
	@$(GO_TEST) ./...

benchmark:
	@echo "Running benchmarks..."
	@$(GO) test -short -bench=. -benchmem ./...

# Help target.
help:
	@echo "Available targets:"
	@echo "  all          - Build optimized binaries (default)"
	@echo "  dev          - Build development binaries (no optimization)"
	@echo "  clean        - Remove temporary build directory"
	@echo "  clean-all    - Remove all build artifacts"
	@echo "  format       - Format Go code"
	@echo "  lint         - Run linter"
	@echo "  lint-fix     - Run linter with autofix"
	@echo "  nil-check    - Run nilaway null pointer analysis"
	@echo "  test         - Run tests"
	@echo "  benchmark    - Run benchmarks"
	@echo "  setup        - Install development dependencies"
	@echo "  help         - Show this help message"

# Declare phony targets.
.PHONY: all dev clean clean-all format lint lint-fix nil-check optimize prepare setup test benchmark help check-dependencies