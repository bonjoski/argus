# ==============================================================================
# Argus (vetpkg): Pre-Flight Dependency Provenance & Slopsquatting Interceptor
# Makefile - Build, Test, Security & Quality Automation
# ==============================================================================

SHELL       := /bin/bash
BINARY_NAME := argus
BIN_DIR     := bin
PKG         := bonjoski/argus
CMD_DIR     := ./cmd/argus

# Build Metadata Variables
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE  ?= $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

# Linker Flags for Stripping and Metadata Injection
LDFLAGS     := -s -w \
  -X $(PKG)/internal/cli.Version=$(VERSION) \
  -X $(PKG)/internal/cli.GitCommit=$(COMMIT) \
  -X $(PKG)/internal/cli.BuildDate=$(BUILD_DATE)

# Go Environment Variables
export CGO_ENABLED ?= 0
GO_BUILD    := go build -trimpath -ldflags "$(LDFLAGS)"

.DEFAULT_GOAL := help

# ==============================================================================
# Development & Build Targets
# ==============================================================================

.PHONY: all
all: tidy fmt-check vet sentinel vulncheck test build ## Run full CI pipeline (tidy, fmt, vet, sentinel, vulncheck, test, build)

.PHONY: build
build: ## Build the native binary into bin/argus
	@echo "==> Building $(BINARY_NAME) [$(VERSION)]..."
	@mkdir -p $(BIN_DIR)
	$(GO_BUILD) -o $(BIN_DIR)/$(BINARY_NAME) $(CMD_DIR)
	@echo "==> Built: $(BIN_DIR)/$(BINARY_NAME)"

.PHONY: install
install: build ## Install argus to $(GOPATH)/bin or system PATH
	@echo "==> Installing $(BINARY_NAME) to $(shell go env GOPATH)/bin..."
	@cp $(BIN_DIR)/$(BINARY_NAME) $(shell go env GOPATH)/bin/$(BINARY_NAME)
	@echo "==> Installed: $(shell go env GOPATH)/bin/$(BINARY_NAME)"

.PHONY: cross-build
cross-build: ## Cross-compile binaries for macOS, Linux, and Windows
	@echo "==> Cross-compiling release binaries..."
	@mkdir -p $(BIN_DIR)
	GOOS=darwin  GOARCH=arm64 $(GO_BUILD) -o $(BIN_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)
	GOOS=darwin  GOARCH=amd64 $(GO_BUILD) -o $(BIN_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)
	GOOS=linux   GOARCH=amd64 $(GO_BUILD) -o $(BIN_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)
	GOOS=linux   GOARCH=arm64 $(GO_BUILD) -o $(BIN_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)
	GOOS=windows GOARCH=amd64 $(GO_BUILD) -o $(BIN_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)
	@echo "==> Cross-compile completed. Artifacts in $(BIN_DIR)/"

# ==============================================================================
# Testing & Benchmarking Targets
# ==============================================================================

.PHONY: test
test: ## Run all unit tests with race detection enabled
	@echo "==> Running unit tests with -race..."
	go test -race -v ./...

.PHONY: test-adversarial
test-adversarial: ## Run the 13-point Adversarial Red Team regression suite
	@echo "==> Running Adversarial Regression Suite (test/adversarial)..."
	go test -race -v ./test/adversarial/...

.PHONY: test-cover
test-cover: ## Run test suite and generate HTML coverage report (coverage.html)
	@echo "==> Running test suite with coverage..."
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "==> HTML coverage report generated: coverage.html"

.PHONY: bench
bench: ## Run performance and latency benchmarks with memory allocation metrics
	@echo "==> Running benchmarks..."
	go test -bench=. -benchmem -run=^$$ ./...

# ==============================================================================
# Security, Linting & Code Hygiene Targets
# ==============================================================================

.PHONY: sentinel
sentinel: ## Run the Adversarial Architecture & Security Sentinel audit scanner
	@echo "==> Running Adversarial Architecture & Security Sentinel scanner..."
	@python3 /Users/benskolmoski/.super.engineering/hooks/antigravity-customization/.agents/skills/adversarial-sentinel/scripts/sentinel_audit.py --path .

.PHONY: vulncheck
vulncheck: ## Scan dependencies for known CVEs using official govulncheck
	@echo "==> Running govulncheck..."
	@if command -v govulncheck >/dev/null 2>&1; then \
		govulncheck ./...; \
	elif [ -f /opt/homebrew/bin/govulncheck ]; then \
		/opt/homebrew/bin/govulncheck ./...; \
	else \
		echo "govulncheck not found. Installing via 'go install golang.org/x/vuln/cmd/govulncheck@latest'..."; \
		go install golang.org/x/vuln/cmd/govulncheck@latest && govulncheck ./...; \
	fi

.PHONY: lint
lint: vet ## Run linter (golangci-lint if installed, fallback to go vet)
	@echo "==> Checking linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "Notice: golangci-lint not in PATH. Ran 'go vet'. (Install: brew install golangci-lint)"; \
	fi

.PHONY: vet
vet: ## Run standard go vet static analyzer
	@echo "==> Running go vet..."
	go vet ./...

.PHONY: fmt
fmt: ## Auto-format all Go source files with gofmt
	@echo "==> Formatting code..."
	go fmt ./...

.PHONY: fmt-check
fmt-check: ## Verify that all Go source files are formatted
	@echo "==> Verifying code formatting..."
	@DIFF=$$(gofmt -l .); \
	if [ -n "$$DIFF" ]; then \
		echo "The following files are not formatted:"; \
		echo "$$DIFF"; \
		exit 1; \
	fi; \
	echo "All files properly formatted."

.PHONY: tidy
tidy: ## Verify and tidy Go modules
	@echo "==> Tidying and verifying modules..."
	go mod tidy
	go mod verify

# ==============================================================================
# Operational & Smoke Test Targets
# ==============================================================================

.PHONY: demo
demo: build ## Run live demo smoke tests on npm (express) and PyPI (requests)
	@echo "==> Running live smoke tests..."
	./$(BIN_DIR)/$(BINARY_NAME) vet npm express
	@echo ""
	./$(BIN_DIR)/$(BINARY_NAME) vet pypi requests

.PHONY: clean
clean: ## Remove build artifacts, test binaries, and coverage reports
	@echo "==> Cleaning build artifacts..."
	rm -rf $(BIN_DIR) dist coverage.out coverage.html
	@echo "==> Clean complete."

# ==============================================================================
# Help Documentation
# ==============================================================================

.PHONY: help
help: ## Display this interactive help table
	@echo "Argus (vetpkg) Development Automation"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
