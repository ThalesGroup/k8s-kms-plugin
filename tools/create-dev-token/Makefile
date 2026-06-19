# SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
# SPDX-License-Identifier: MIT

BINARY      := create-dev-token
# CGO is required for the PKCS#11 shared-library bindings (crypto11 / miekg/pkcs11).
CGO_ENABLED := 1

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  := -ldflags="-X main.version=$(VERSION)"

.PHONY: build clean help

build: ## Build the create-dev-token binary into this directory
	CGO_ENABLED=$(CGO_ENABLED) go build $(LDFLAGS) -o $(BINARY) .

clean: ## Remove the compiled binary
	rm -f $(BINARY)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'
