.PHONY: all lint build coverage dev  gen

all: build

VERSION ?= $(shell git describe --tags)
COMMITLONG ?=$(shell git rev-parse HEAD)
COMMITSHORT ?= $(shell git rev-parse HEAD | cut -c 1-8)
GOVERSION ?= $(shell go version)
PLATFORM  ?= $(shell uname -i )
BUILDDATE ?= $(shell date -Is)
GOLDFLAGS=-ldflags="-X github.com/ThalesGroup/k8s-kms-plugin/cmd/k8s-kms-plugin/cmd.RawGitVersion=$(VERSION) -X github.com/ThalesGroup/k8s-kms-plugin/cmd/k8s-kms-plugin/cmd.CommitVersionIdLong=$(COMMITLONG) -X github.com/ThalesGroup/k8s-kms-plugin/cmd/k8s-kms-plugin/cmd.CommitVersionIdShort=$(COMMITSHORT) -X github.com/ThalesGroup/k8s-kms-plugin/cmd/k8s-kms-plugin/cmd.GoVersion=$(GOVERSION) -X github.com/ThalesGroup/k8s-kms-plugin/cmd/k8s-kms-plugin/cmd.BuildPlatform=$(PLATFORM) -X github.com/ThalesGroup/k8s-kms-plugin/cmd/k8s-kms-plugin/cmd.BuildDate=$(BUILDDATE)"

SECRETNAME=gcr-json-key
P11_TOKEN=ajak
P11_PIN=password
## Pipeline

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
	
		@go build $(GOLDFLAGS) -o k8s-kms-plugin cmd/k8s-kms-plugin/main.go
run:
		@go run cmd/k8s-kms-plugin/main.go serve --disable-socket --enable-server --p11-lib /usr/local/lib/softhsm/libsofthsm2.so --p11-pin $(P11_PIN) --p11-label $(P11_TOKEN)
run-test:
		@go run cmd/k8s-kms-plugin/main.go test


dev:
		@skaffold dev --port-forward=true

## Testing

p11tool-list:
		@kubectl exec -it k8s-kms-plugin-server -- p11tool --lib /usr/lib/softhsm/libsofthsm2.so --pin changeme --token default list

p11tool-delete:
		@kubectl exec -it k8s-kms-plugin-server -- p11tool --lib /usr/lib/softhsm/libsofthsm2.so --pin $(P11_PIN) --token $(P11_TOKEN) delete


## Deploy

deploy:
		@gcloud endpoints services deploy --format json "./apis/api-service.yaml" "./apis/istio/v1/v1.pb"  > "./deployed.json"

release: 
	export GITHUB_TOKEN=$(GITHUB_TOKEN)
	LDFLAGS=$(GOLDFLAGS) goreleaser release --clean