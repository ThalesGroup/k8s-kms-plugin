.PHONY: all lint build coverage dev  gen

all: build

SECRETNAME=gcr-json-key
## Pipeline
tools:
		GO111MODULE=off go get -u github.com/square/certstrap

lint:
		@golangci-lint run
coverage:
		mkdir -p build
		go test -race -v -coverprofile build/coverage.out ./pkg/...
		go tool cover -html=build/coverage.out -o build/coverage.html

## Dev
gen: gen-grpc gen-openapi
gen-grpc:
		@prototool all
		@cp -r generated/github.com/thalescpl-io/k8s-kms-plugin/apis/* apis/
		@rm -rf generated/
gen-openapi:
		@swagger generate server --quiet --flag-strategy=pflag --exclude-main -m pkg/est/models -s pkg/est/restapi -f apis/kms/v1/est.yaml
		@swagger generate client --quiet --existing-models=pkg/est/models -c pkg/est/client -f apis/kms/v1/est.yaml
build:
		@go build -o k8s-kms-plugin main.go

dev:
		@skaffold dev --port-forward=true

## Testing

ports:
		@kubectl exec -ti  k8s-kms-plugin-server-0 -- bash -c "netstat -an | grep LISTEN"

