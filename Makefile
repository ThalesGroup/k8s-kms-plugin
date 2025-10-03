# Copyright 2025 Thales Group
# SPDX-License-Identifier: MIT
#
# Use of this source code is governed by an MIT-style
# license that can be found in the LICENSE file or at
# https://opensource.org/licenses/MIT.
.PHONY: all lint build coverage dev gen

all: build

# Project name
PROJECT_NAME := k8s-kms-plugin
GO_MODULE_NAME := "github.com/ThalesGroup/$(PROJECT_NAME)"

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

LDFLAGS = "-X '$(GO_MODULE_NAME)/pkg/version.RawGitDescribe=$(VERSION)' \
	-X '$(GO_MODULE_NAME)/pkg/version.GitCommitIdLong=$(COMMIT_LONG)' \
	-X '$(GO_MODULE_NAME)/pkg/version.GitCommitIdShort=$(COMMIT_SHORT)' \
	-X '$(GO_MODULE_NAME)/pkg/version.GoVersion=$(GO_VERSION)' \
	-X '$(GO_MODULE_NAME)/pkg/version.BuildPlatform=$(BUILD_PLATFORM)' \
	-X '$(GO_MODULE_NAME)/pkg/version.BuildDate=$(BUILD_DATE)' \
	-X '$(GO_MODULE_NAME)/pkg/version.GitCommitTimestamp=$(COMMIT_TIMESTAMP)' \
	-X '$(GO_MODULE_NAME)/pkg/version.GitDirtyStr=$(IS_GIT_DIRTY)'"

GO_LDFLAGS = -ldflags=$(LDFLAGS)
BINARY_NAME = $(PROJECT_NAME)

# For dev
SECRET_NAME=gcr-json-key
P11_TOKEN=ajak
P11_PIN=password
## Pipeline

# Go parameters
CGO_ENABLED := "1"

lint:
		@golangci-lint run
coverage:
		mkdir -p build
		go test -race -v -coverprofile build/coverage.out ./pkg/...
		go tool cover -html=build/coverage.out -o build/coverage.html

## Dev
gen: gen-grpc gen-openapi
gen-grpc:
		@prototool all || true
		@cp -r generated/github.com/thalescpl-io/k8s-kms-plugin/apis/* apis/
		@cp -r generated/apis/* apis/
		@rm -rf generated/
gen-openapi:
		@swagger generate server --quiet -m pkg/est/models -s pkg/est/restapi -f apis/kms/v1/est.yaml
		@swagger generate client --quiet --existing-models=pkg/est/models -c pkg/est/client -f apis/kms/v1/est.yaml
build:
		@go version
		@go build $(GO_LDFLAGS) -o k8s-kms-plugin cmd/k8s-kms-plugin/main.go
build-debug:
		@go version
		@go build -gcflags="all=-N -l" $(GO_LDFLAGS) -o k8s-kms-plugin cmd/k8s-kms-plugin/main.go
		$(info use cmd : dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec k8s-kms-plugin)
		$(info will listen to port 2345)
run:
		@go run cmd/k8s-kms-plugin/main.go serve --disable-socket --enable-server --p11-lib /usr/local/lib/softhsm/libsofthsm2.so --p11-pin $(P11_PIN) --p11-label $(P11_TOKEN)
run-test:
		@go run cmd/k8s-kms-plugin/main.go test


dev:
		@skaffold dev --port-forward=true

## Docs
doc:
		@go run $(GO_LDFLAGS) cmd/k8s-kms-plugin/main.go docs --output-dir docs/cli-user-interface/markdown/
		@go run $(GO_LDFLAGS) cmd/k8s-kms-plugin/main.go docs --output-dir docs/cli-user-interface/txt/ --format cli-table-pretty

## Testing

p11tool-list:
		@kubectl exec -it k8s-kms-plugin-server -- p11tool --lib /usr/lib/softhsm/libsofthsm2.so --pin changeme --token default list

p11tool-delete:
		@kubectl exec -it k8s-kms-plugin-server -- p11tool --lib /usr/lib/softhsm/libsofthsm2.so --pin $(P11_PIN) --token $(P11_TOKEN) delete


## Deploy

deploy:
		@gcloud endpoints services deploy --format json "./apis/api-service.yaml" "./apis/istio/v1/v1.pb"  > "./deployed.json"

release: 
		@echo "Makefile: Running goreleaser release --clean fro project $(PROJECT_NAME)"
		LDFLAGS=$(LDFLAGS) goreleaser release --clean --skip sign,validate,ko
get-ldflags:
		@echo $(LDFLAGS)
