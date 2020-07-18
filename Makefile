.PHONY: all lint build coverage dev  gen

all: build
## Pipeline
lint:
		@golangci-lint run
coverage:
		mkdir -p build
		go test -race -v -coverprofile build/coverage.out ./pkg/...
		go tool cover -html=build/coverage.out -o build/coverage.html

## Dev
gen:
		@prototool all
		@cp -r generated/github.com/thalescpl-io/k8s-kms-plugin/apis/* apis/
		@rm -rf generated/
build:
		@go build -o k8s-kms-plugin main.go

dev:
		@skaffold dev --port-forward=true

