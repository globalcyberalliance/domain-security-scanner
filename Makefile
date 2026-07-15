PROJECT   := github.com/globalcyberalliance/domain-security-scanner/v3
CMD       := $(PROJECT)/cmd/dss
BIN       := bin/dss

GO        := go
GOPRIVATE := github.com/globalcyberalliance
LDFLAGS   := -s -w
GOBUILD    = GOPRIVATE=$(GOPRIVATE) CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)"

# VERSION is optional. The binary carries a default version baked into the source
# (cmd/dss/main.go). Passing VERSION= (e.g. a release tag from CI) overrides it via
# -ldflags -X. A passed-but-empty VERSION= is stripped and ignored so we never embed
# an empty main.version, which would silently drop cobra's --version output.
VERSION := $(strip $(VERSION))
ifneq ($(VERSION),)
LDFLAGS += -X main.version=$(VERSION)
endif

# need <tool> — abort with an install hint when a required tool is missing.
need = command -v $(1) >/dev/null 2>&1 || { echo "$(1) not found — run 'make setup'"; exit 1; }

.DEFAULT_GOAL := dev
.PHONY: dev prod optimize clean clean-all format lint lint-fix nil test benchmark tidy setup help

dev: ## Default: fast local build, compiles in-place
	@$(call need,$(GO))
	@echo "Building $(BIN)..."
	@mkdir -p bin
	@$(GOBUILD) -o $(BIN) $(CMD)

prod: ## Production release build (stripped, trimmed, reproducible)
	@$(call need,$(GO))
	@echo "Building $(BIN)..."
	@mkdir -p bin
	@$(GOBUILD) -o $(BIN) $(CMD)

optimize: ## Rewrite structs for optimal field alignment — run manually, review the diff, commit
# Struct alignment is deliberately kept OFF the build path. betteralign -fix mutates source
# and can intermittently corrupt files, so it must never gate a build; run it by hand and let
# `go build`/review catch any bad rewrite. `|| true` because betteralign exits non-zero simply
# when it has findings, even after a successful fix.
	@$(call need,betteralign)
	@echo "Optimizing struct field alignment..."
	@betteralign -fix ./... || true

clean: ## Remove build artifacts
	@echo "Cleaning..."
	@rm -rf bin build

clean-all: clean ## Alias for clean (kept for compatibility)

format: ## Format code (gofumpt)
	@$(call need,gofumpt)
	@echo "Formatting..."
	@gofumpt -w .

lint: ## Run linter (golangci-lint)
	@$(call need,golangci-lint)
	@echo "Linting..."
	@golangci-lint run ./...

lint-fix: ## Run linter with autofix
	@$(call need,golangci-lint)
	@echo "Linting with autofix..."
	@golangci-lint run --fix ./...

nil: ## Run nilaway nil-safety analysis
	@$(call need,nilaway)
	@echo "Running nilaway..."
	@nilaway ./...

test: ## Run tests (short)
	@echo "Testing..."
	@$(GO) test -v -short ./...

benchmark: ## Run benchmarks
	@echo "Running benchmarks..."
	@$(GO) test -short -bench=. -benchmem ./...

tidy: ## Tidy go.mod / go.sum
	@$(GO) mod tidy

setup: ## Install dev tools (gofumpt, nilaway, golangci-lint, betteralign)
	@echo "Installing dev tools..."
	@$(GO) install mvdan.cc/gofumpt@latest
	@$(GO) install go.uber.org/nilaway/cmd/nilaway@latest
	@$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@$(GO) install github.com/dkorunic/betteralign/cmd/betteralign@latest

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
