PROJECT   := github.com/globalcyberalliance/domain-security-scanner/v3
CMD       := $(PROJECT)/cmd/dss
BIN       := bin/dss

GO        := go
GOPRIVATE := github.com/globalcyberalliance
LDFLAGS   := -s -w
GOBUILD    = GOPRIVATE=$(GOPRIVATE) CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)"

# betteralign is PINNED. v0.14.0 regressed -fix (GoReleaser v2 migration + "honor -fix in
# shipped binary") and intermittently corrupts multi-struct files with per-field doc comments,
# which broke the release build. v0.13.0 is the last release carrying all the correctness fixes
# (v0.9.0 multi-struct rewrite loss + data race, v0.12.0 comment-handling hardening) before that
# regression. Do NOT bump to @latest without re-validating against pkg/scanner.
BETTERALIGN_VERSION := v0.13.0

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
.PHONY: dev prod clean clean-all format lint lint-fix nil test benchmark tidy setup-prod setup help

dev: ## Default: fast local build, no struct alignment, compiles in-place
	@$(call need,$(GO))
	@echo "Building $(BIN)..."
	@mkdir -p bin
	@$(GOBUILD) -o $(BIN) $(CMD)

prod: ## Production binary: struct-aligned, optimized (working tree untouched)
	@$(call need,$(GO))
	@$(call need,betteralign)
	@echo "Preparing build directory..."
	@rm -rf bin build && mkdir -p bin build
	@cp -r cmd go.mod go.sum pkg build/
	@echo "Optimizing struct field alignment..."
# betteralign exits non-zero whenever it has findings (even after -fix succeeds, and when
# already aligned), so `|| true` is required — alignment is best-effort here, not a gate.
# The version is pinned (see BETTERALIGN_VERSION) because @latest corrupts source.
	@cd build && betteralign -fix ./... >/dev/null 2>&1 || true
	@echo "Building $(BIN)..."
	@cd build && $(GOBUILD) -o ../$(BIN) $(CMD)
	@rm -rf build

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

setup-prod: ## Install build-time tools only (pinned betteralign — needed by `make prod`)
	@echo "Installing build tools..."
	@$(GO) install github.com/dkorunic/betteralign/cmd/betteralign@$(BETTERALIGN_VERSION)

setup: setup-prod ## Install all dev tools (build + gofumpt, nilaway, golangci-lint)
	@echo "Installing dev tools..."
	@$(GO) install mvdan.cc/gofumpt@latest
	@$(GO) install go.uber.org/nilaway/cmd/nilaway@latest
	@$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
