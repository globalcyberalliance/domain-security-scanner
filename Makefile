PROJECT			 := github.com/globalcyberalliance/domain-security-scanner/v3
GO				 := $(shell which go 2>/dev/null)
GOFIELDALIGNMENT := $(shell which betteralign 2>/dev/null)
GOFUMPT			 := $(shell which gofumpt 2>/dev/null)
GOLINTER		 := $(shell which golangci-lint 2>/dev/null)
GONILAWAY        := $(shell which nilaway 2>/dev/null)
GO_BENCH_FLAGS	 := -short -bench=. -benchmem
GO_BENCH		 := $(GO) test $(GO_BENCH_FLAGS)
GO_BUILD		 := CGO_ENABLED=0 $(GO) build -ldflags "-s -w" -trimpath
GO_FORMAT		 := $(GOFUMPT) -w
GO_OPTIMIZE		 := $(GOFIELDALIGNMENT) -fix
GO_TEST			 := $(GO) test -v -short
GO_TIDY			 := $(GO) mod tidy
TARGETS			 := bin/dss

all: check-dependencies prepare optimize $(TARGETS) clean

dev: prepare $(TARGETS)

bin/%: $(shell find . -name "*.go" -type f)
	@echo "Building $@..."
	@if [ "$(MAKECMDGOALS)" != "dev" ]; then \
        cd build && $(GO_BUILD) -o ../$@ $(PROJECT)/cmd/$*; \
    else \
        $(GO_BUILD) -o $@ $(PROJECT)/cmd/$*; \
    fi

check-dependencies:
	@echo "Checking dependencies..."
	@if [ -z "${GO}" ]; then \
		echo "Cannot find 'go' in your $$PATH"; \
		exit 1; \
	fi
	@if [ -z "${GOFIELDALIGNMENT}" ]; then \
		echo "Cannot find 'fieldalignment' in your $$PATH"; \
		exit 1; \
	fi

clean:
	@echo "Cleaning temporary build directory..."
	@rm -rf build

format:
	@if [ -z "${GOFUMPT}" ]; then \
		echo "Cannot find 'gofumpt' in your $$PATH"; \
		exit 1; \
	fi
	@echo "Formatting code..."
	@$(GO_FORMAT) $(PWD)

lint:
	@if [ -z "${GOLINTER}" ]; then \
		echo "Cannot find 'golangci-lint' in your $$PATH"; \
		exit 1; \
	fi
	@echo "Running linter..."
	@$(GOLINTER) run ./...

nil:
	@if [ -z "${GONILAWAY}" ]; then \
		echo "Cannot find 'nilaway' in your $$PATH"; \
		exit 1; \
	fi
	@echo "Running nilaway..."
	@$(GONILAWAY) ./...

optimize:
	@echo "Creating temporary build directory..."
	@cp -r cmd go.* pkg ./build/
	@echo "Optimizing struct field alignment..."
	@cd build && $(GO_OPTIMIZE) ./... > /dev/null 2>&1 || true

prepare:
	@echo "Cleaning previous builds..."
	@rm -rf bin build
	@mkdir -p bin build
	@$(GO_TIDY)