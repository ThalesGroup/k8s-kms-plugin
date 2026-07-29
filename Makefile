# SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
# SPDX-License-Identifier: MIT

.PHONY: all lint lint-fix build build-linux-amd64 build-linux-amd64-debug build-linux-arm64 build-linux-arm64-debug build-linux-riscv64 build-linux-riscv64-debug coverage test test-integration test-e2e gen notices clean

all: build-linux-amd64 build-linux-arm64 build-linux-riscv64

# Project name
PROJECT_NAME := k8s-kms-plugin
GO_MODULE_NAME := "github.com/eclipse-keysealer/$(PROJECT_NAME)"
BINARY_NAME = $(PROJECT_NAME)

# Useful variables for build metadata
VERSION ?= $(shell git describe --tags --always --dirty)
# equivalent command to test git dirty status in bash terminal: [[ -n "$(git status --porcelain)" ]] && echo "true" || echo "false"
IS_GIT_DIRTY := $(shell [ -n "$$(git status --porcelain)" ] && echo "true" || echo "false")
COMMIT_LONG ?= $(shell git rev-parse HEAD)
COMMIT_SHORT ?= $(shell git rev-parse --short=8 HEAD)
COMMIT_TIMESTAMP := $(shell git show -s --format=%cI HEAD)
GO_VERSION ?= $(shell go version)
BUILD_PLATFORM  ?= $(shell uname -m)
BUILD_DATE ?= $(shell date -u --iso-8601=seconds)

# Go Flags
GIT_INFO_LDFLAGS = -X '$(GO_MODULE_NAME)/pkg/version.RawGitDescribe=$(VERSION)' \
	-X '$(GO_MODULE_NAME)/pkg/version.GitCommitIDLong=$(COMMIT_LONG)' \
	-X '$(GO_MODULE_NAME)/pkg/version.GitCommitIDShort=$(COMMIT_SHORT)' \
	-X '$(GO_MODULE_NAME)/pkg/version.GoVersion=$(GO_VERSION)' \
	-X '$(GO_MODULE_NAME)/pkg/version.BuildPlatform=$(BUILD_PLATFORM)' \
	-X '$(GO_MODULE_NAME)/pkg/version.BuildDate=$(BUILD_DATE)' \
	-X '$(GO_MODULE_NAME)/pkg/version.GitCommitTimestamp=$(COMMIT_TIMESTAMP)' \
	-X '$(GO_MODULE_NAME)/pkg/version.GitDirtyStr=$(IS_GIT_DIRTY)'

# Go build parameters
CGO_ENABLED := 1
DIST_DIR := dist
# Cross-compilers
LINUX_AMD64_GCC := gcc
LINUX_ARM64_GCC := aarch64-linux-gnu-gcc
LINUX_RISCV64_GCC := riscv64-linux-gnu-gcc

## Licenses
notices:
		@go-licenses report ./... --ignore github.com/eclipse-keysealer/k8s-kms-plugin --template go-licenses.tpl > NOTICES.md
		@echo "NOTICES.md generated"

GOLANGCI_LINT ?= golangci-lint

lint:
		@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { \
		    echo "golangci-lint not found. Install the v2 binary with:"; \
		    echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"; \
		    exit 1; \
		}
		CGO_ENABLED=$(CGO_ENABLED) $(GOLANGCI_LINT) run

# Auto-fix the mechanically-fixable findings (formatting, some conversions):
lint-fix:
		@command -v $(GOLANGCI_LINT) >/dev/null 2>&1 || { \
		    echo "golangci-lint not found. Install the v2 binary with:"; \
		    echo "  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest"; \
		    exit 1; \
		}
		CGO_ENABLED=$(CGO_ENABLED) $(GOLANGCI_LINT) run --fix

## SAST
coverage:
		mkdir -p build
		CGO_ENABLED=$(CGO_ENABLED) go test -race -v -coverprofile build/coverage.out ./pkg/... ./cmd/...
		go tool cover -html=build/coverage.out -o build/coverage.html

## Build

# Local dev build (native arch)
build:
		@go version
		CGO_ENABLED=$(CGO_ENABLED) go build -ldflags="$(GIT_INFO_LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME) cmd/k8s-kms-plugin/main.go

build-linux-amd64:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/amd64"
		@go version
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 CC=$(LINUX_AMD64_GCC) go build -ldflags="$(GIT_INFO_LDFLAGS) -s -w" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_amd64 cmd/k8s-kms-plugin/main.go

build-linux-amd64-debug:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/amd64 with debug option"
		@go version
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 CC=$(LINUX_AMD64_GCC) go build -gcflags="all=-N -l" -ldflags="$(GIT_INFO_LDFLAGS)" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_amd64 cmd/k8s-kms-plugin/main.go
		$(info use cmd : dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec k8s-kms-plugin)
		$(info will listen to port 2345)

build-linux-arm64:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/arm64"
		@go version
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 CC=$(LINUX_ARM64_GCC) go build -ldflags="$(GIT_INFO_LDFLAGS) -s -w" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_arm64 cmd/k8s-kms-plugin/main.go

build-linux-arm64-debug:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/arm64 with debug option"
		@go version
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 CC=$(LINUX_ARM64_GCC) go build -gcflags="all=-N -l" -ldflags="$(GIT_INFO_LDFLAGS)" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_arm64 cmd/k8s-kms-plugin/main.go
		$(info use cmd : dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec k8s-kms-plugin)
		$(info will listen to port 2345)

build-linux-riscv64:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/riscv64"
		@go version
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=riscv64 CC=$(LINUX_RISCV64_GCC) go build -ldflags="$(GIT_INFO_LDFLAGS) -s -w" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_riscv64 cmd/k8s-kms-plugin/main.go

build-linux-riscv64-debug:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/riscv64 with debug option"
		@go version
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=riscv64 CC=$(LINUX_RISCV64_GCC) go build -gcflags="all=-N -l" -ldflags="$(GIT_INFO_LDFLAGS)" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_riscv64 cmd/k8s-kms-plugin/main.go
		$(info use cmd : dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec k8s-kms-plugin)
		$(info will listen to port 2345)

## Docs
doc:
		@go run -ldflags="$(GIT_INFO_LDFLAGS)" cmd/k8s-kms-plugin/main.go docs --output-dir docs/cli-user-interface/markdown/
		@go run -ldflags="$(GIT_INFO_LDFLAGS)" cmd/k8s-kms-plugin/main.go docs --output-dir docs/cli-user-interface/txt/ --format cli-table-pretty

## Testing
test:
		@CGO_ENABLED=$(CGO_ENABLED) go test -race ./pkg/... ./cmd/...

test-integration:
		@CGO_ENABLED=$(CGO_ENABLED) go test -race -v ./test/integration/...

test-e2e: build
		@CGO_ENABLED=$(CGO_ENABLED) go test -race -v ./test/e2e/...

## Release
release-local-test:
		@echo "Makefile: Running goreleaser release --clean for project $(PROJECT_NAME)"
		LDFLAGS="$(GIT_INFO_LDFLAGS) -s -w" goreleaser release --clean --skip sign,validate,ko

release:
		@echo "Makefile: Running goreleaser release --clean for project $(PROJECT_NAME)"
		LDFLAGS="$(GIT_INFO_LDFLAGS) -s -w" goreleaser release --clean

get-ldflags:
		@echo "$(GIT_INFO_LDFLAGS) -s -w"

## Clean
clean:
		@echo "Makefile: cleaning dist directory"
		rm -rf $(DIST_DIR)
