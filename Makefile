# SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
# SPDX-License-Identifier: MIT

.PHONY: all lint lint-fix vet govulncheck build build-linux-amd64 build-linux-amd64-debug build-linux-arm64 build-linux-arm64-debug build-linux-riscv64 build-linux-riscv64-debug coverage test test-integration test-e2e doc notices image image-from-source release release-local-test get-ldflags clean

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

## Tool preconditions
# $(call require,<binary>,<how to install it>) — fail early with an install hint.
#
# Probes by running the tool, not `command -v`: a goenv shim stays on PATH even
# when the tool is not installed for the active Go version, so `command -v` says
# yes and the build dies later. Exit 127 (missing binary or dead shim) is the
# only status treated as missing; tools without --version exit 1 or 2 and pass.
#
# A hint must not contain a comma — make would read it as another $(call) argument.
define require
@$(1) --version >/dev/null 2>&1; \
if [ $$? -eq 127 ]; then \
    echo "$(1) not found. Install it with:"; \
    echo "  $(2)"; \
    exit 1; \
fi
endef

# Debian/Ubuntu package names, matching the CI runner (setup-build-env).
CC_INSTALL_HINT := sudo apt-get install build-essential
ARM64_CC_INSTALL_HINT := sudo apt-get install gcc-aarch64-linux-gnu libc6-dev-arm64-cross
RISCV64_CC_INSTALL_HINT := sudo apt-get install gcc-riscv64-linux-gnu libc6-dev-riscv64-cross

## Licenses
# go-licenses renders go-licenses.tpl, which cannot pad the table cells to a
# common width, so the raw output is piped through align-md-tables.awk.
notices:
		$(call require,go-licenses,go install github.com/google/go-licenses@latest)
		@go-licenses report ./... --ignore github.com/eclipse-keysealer/k8s-kms-plugin --template go-licenses.tpl > NOTICES.md.tmp
		@awk -f scripts/align-md-tables.awk NOTICES.md.tmp > NOTICES.md
		@rm -f NOTICES.md.tmp
		@echo "NOTICES.md generated"

## Lint
GOLANGCI_LINT ?= golangci-lint
GOLANGCI_LINT_INSTALL_HINT := go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

lint:
		$(call require,$(GOLANGCI_LINT),$(GOLANGCI_LINT_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) $(GOLANGCI_LINT) run

# Auto-fix the mechanically-fixable findings (formatting, some conversions):
lint-fix:
		$(call require,$(GOLANGCI_LINT),$(GOLANGCI_LINT_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) $(GOLANGCI_LINT) run --fix

## Vet
# Same check as the CI "Vet, build & test" job (.github/workflows/ci.yml).
vet:
		CGO_ENABLED=$(CGO_ENABLED) go vet ./...

## Vulnerability scan
# Runs govulncheck (reachability-aware, cross-checked against the Go vuln DB) —
# the same check as the CI govulncheck job (.github/workflows/security.yaml).
#
# Install govulncheck:
#   go install golang.org/x/vuln/cmd/govulncheck@latest
GOVULNCHECK ?= govulncheck

govulncheck:
		$(call require,$(GOVULNCHECK),go install golang.org/x/vuln/cmd/govulncheck@latest)
		CGO_ENABLED=$(CGO_ENABLED) $(GOVULNCHECK) -show verbose ./...

## SAST
coverage:
		mkdir -p build
		CGO_ENABLED=$(CGO_ENABLED) go test -race -v -coverprofile build/coverage.out ./pkg/... ./cmd/...
		go tool cover -html=build/coverage.out -o build/coverage.html

## Build

# Local dev build (native arch)
build:
		@go version
		$(call require,$(LINUX_AMD64_GCC),$(CC_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) go build -ldflags="$(GIT_INFO_LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME) cmd/k8s-kms-plugin/main.go

build-linux-amd64:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/amd64"
		@go version
		$(call require,$(LINUX_AMD64_GCC),$(CC_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 CC=$(LINUX_AMD64_GCC) go build -ldflags="$(GIT_INFO_LDFLAGS) -s -w" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_amd64 cmd/k8s-kms-plugin/main.go

build-linux-amd64-debug:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/amd64 with debug option"
		@go version
		$(call require,$(LINUX_AMD64_GCC),$(CC_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=amd64 CC=$(LINUX_AMD64_GCC) go build -gcflags="all=-N -l" -ldflags="$(GIT_INFO_LDFLAGS)" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_amd64 cmd/k8s-kms-plugin/main.go
		$(info use cmd : dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec k8s-kms-plugin)
		$(info will listen to port 2345)

build-linux-arm64:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/arm64"
		@go version
		$(call require,$(LINUX_ARM64_GCC),$(ARM64_CC_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 CC=$(LINUX_ARM64_GCC) go build -ldflags="$(GIT_INFO_LDFLAGS) -s -w" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_arm64 cmd/k8s-kms-plugin/main.go

build-linux-arm64-debug:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/arm64 with debug option"
		@go version
		$(call require,$(LINUX_ARM64_GCC),$(ARM64_CC_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=arm64 CC=$(LINUX_ARM64_GCC) go build -gcflags="all=-N -l" -ldflags="$(GIT_INFO_LDFLAGS)" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_arm64 cmd/k8s-kms-plugin/main.go
		$(info use cmd : dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec k8s-kms-plugin)
		$(info will listen to port 2345)

build-linux-riscv64:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/riscv64"
		@go version
		$(call require,$(LINUX_RISCV64_GCC),$(RISCV64_CC_INSTALL_HINT))
		CGO_ENABLED=$(CGO_ENABLED) GOOS=linux GOARCH=riscv64 CC=$(LINUX_RISCV64_GCC) go build -ldflags="$(GIT_INFO_LDFLAGS) -s -w" -o $(DIST_DIR)/$(PROJECT_NAME)_$(VERSION)_linux_riscv64 cmd/k8s-kms-plugin/main.go

build-linux-riscv64-debug:
		@echo "Makefile: Building $(PROJECT_NAME) for linux/riscv64 with debug option"
		@go version
		$(call require,$(LINUX_RISCV64_GCC),$(RISCV64_CC_INSTALL_HINT))
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

## Container image
# The Containerfile does not compile anything by default: `image` builds the
# binary with the LDFLAGS above, then packages dist/$(BINARY_NAME) into the
# runtime image. The released ghcr.io image is built by ko via goreleaser.
CONTAINER_ENGINE ?= podman
# Docker works too: run make with CONTAINER_ENGINE=docker
CONTAINER_ENGINE_INSTALL_HINT := sudo apt-get install podman
IMAGE_REGISTRY ?= ghcr.io
IMAGE_REPOSITORY ?= eclipse-keysealer/$(PROJECT_NAME)
IMAGE_TAG ?= $(VERSION)
IMAGE ?= $(IMAGE_REGISTRY)/$(IMAGE_REPOSITORY):$(IMAGE_TAG)

# OCI annotations that cannot be derived inside the build
IMAGE_BUILD_ARGS = \
	--build-arg LABEL_CREATED="$(BUILD_DATE)" \
	--build-arg LABEL_VERSION="$(VERSION)" \
	--build-arg LABEL_REVISION="$(COMMIT_LONG)" \
	--build-arg LABEL_REF_NAME="$(IMAGE_TAG)"

image: build
		@echo "Makefile: Building container image $(IMAGE) from dist/$(BINARY_NAME)"
		$(call require,$(CONTAINER_ENGINE),$(CONTAINER_ENGINE_INSTALL_HINT))
		$(CONTAINER_ENGINE) build -f Containerfile \
			--build-arg BINARY=$(DIST_DIR)/$(BINARY_NAME) \
			$(IMAGE_BUILD_ARGS) \
			-t $(IMAGE) .

# Self-contained variant: compiles inside the builder stage instead of reusing
# dist/. Useful where `make build` cannot run (no Go toolchain, cross-arch).
image-from-source:
		@echo "Makefile: Building container image $(IMAGE) from source"
		$(call require,$(CONTAINER_ENGINE),$(CONTAINER_ENGINE_INSTALL_HINT))
		$(CONTAINER_ENGINE) build -f Containerfile \
			--build-arg BINARY_SOURCE=source \
			--build-arg VERSION="$(VERSION)" \
			--build-arg COMMIT_LONG="$(COMMIT_LONG)" \
			--build-arg COMMIT_SHORT="$(COMMIT_SHORT)" \
			--build-arg COMMIT_TIMESTAMP="$(COMMIT_TIMESTAMP)" \
			--build-arg BUILD_DATE="$(BUILD_DATE)" \
			--build-arg IS_GIT_DIRTY="$(IS_GIT_DIRTY)" \
			$(IMAGE_BUILD_ARGS) \
			-t $(IMAGE) .

## Release
GORELEASER ?= goreleaser
GORELEASER_INSTALL_HINT := go install github.com/goreleaser/goreleaser/v2@latest

release-local-test:
		@echo "Makefile: Running goreleaser release --clean for project $(PROJECT_NAME)"
		$(call require,$(GORELEASER),$(GORELEASER_INSTALL_HINT))
		LDFLAGS="$(GIT_INFO_LDFLAGS) -s -w" $(GORELEASER) release --clean --skip sign,validate,ko

release:
		@echo "Makefile: Running goreleaser release --clean for project $(PROJECT_NAME)"
		$(call require,$(GORELEASER),$(GORELEASER_INSTALL_HINT))
		LDFLAGS="$(GIT_INFO_LDFLAGS) -s -w" $(GORELEASER) release --clean

get-ldflags:
		@echo "$(GIT_INFO_LDFLAGS) -s -w"

## Clean
clean:
		@echo "Makefile: cleaning dist directory"
		rm -rf $(DIST_DIR)
