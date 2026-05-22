# Copyright 2026 Thales Group
# SPDX-License-Identifier: MIT

BINARY  := create-dev-token
# CGO is required for the PKCS#11 shared-library bindings (crypto11 / miekg/pkcs11).
CGO_ENABLED := 1

.PHONY: build clean help

build: ## Build the create-dev-token binary into this directory
	CGO_ENABLED=$(CGO_ENABLED) go build -o $(BINARY) .

clean: ## Remove the compiled binary
	rm -f $(BINARY)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-10s %s\n", $$1, $$2}'
