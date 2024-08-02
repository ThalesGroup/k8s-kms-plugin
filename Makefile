.PHONY: all lint build coverage dev  gen

all: build

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
		@go version
		@go build -o k8s-kms-plugin cmd/k8s-kms-plugin/main.go
build-debug:
		@go version
		@go build -gcflags="all=-N -l" -o k8s-kms-plugin cmd/k8s-kms-plugin/main.go
		$(info use cmd : dlv --listen=:2345 --headless=true --api-version=2 --accept-multiclient exec k8s-kms-plugin)
		$(info will listen to port 2345)
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
