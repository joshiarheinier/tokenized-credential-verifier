# Load local overrides from .env if present (git-ignored).
-include .env
export

GO      ?= go
BIN_DIR ?= bin

.PHONY: help run build test test-race cover lint fmt tidy clean anchor-build anchor-test integration-test

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*## "}{printf "  %-10s %s\n",$$1,$$2}'

run: ## Run the API locally
	$(GO) run ./cmd/api

build: ## Build the API binary into bin/
	$(GO) build -o $(BIN_DIR)/ ./cmd/api

test: ## Run all Go tests
	$(GO) test ./...

test-race: ## Run tests with the race detector (requires cgo)
	$(GO) test -race ./...

cover: ## Run tests with a coverage report
	$(GO) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out

lint: ## gofmt check + go vet
	@unformatted="$$(gofmt -l .)"; if [ -n "$$unformatted" ]; then \
		echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	$(GO) vet ./...

fmt: ## Format Go code
	gofmt -w .

tidy: ## Tidy go.mod/go.sum
	$(GO) mod tidy

clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) coverage.out

# Anchor lives in WSL (see contracts/credential-registry/scripts/anchor-wsl.sh).
anchor-build: ## Build the Anchor program (via WSL)
	wsl -e bash -ic 'cd contracts/credential-registry && ./scripts/anchor-wsl.sh build'

anchor-test: anchor-build ## Run Anchor tests on a local validator (via WSL)
	wsl -e bash -ic 'cd contracts/credential-registry && ./scripts/anchor-wsl.sh test --skip-build --validator legacy'

integration-test: anchor-build ## Run Go integration tests against a local validator (WSL)
	bash scripts/integration-test.sh
