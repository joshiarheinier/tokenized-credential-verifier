# Load local overrides from .env if present (git-ignored).
-include .env
export

GO      ?= go
BIN_DIR ?= bin

.PHONY: help run build test test-race cover lint fmt tidy clean

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
