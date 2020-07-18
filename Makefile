.PHONY: all build dev gentls prep secrets helm gen gen-go gen-python



gen:
		@prototool all
		@cp -r generated/github.com/thalescpl-io/k8s-kms-plugin/apis/* apis/
		@rm -rf generated/
build:
		@go build -o k8s-kms-plugin main.go
install:
		@go install
##
client-version:
		@go run main.go version
client-encrypt:
		@go run main.go encrypt --string test
client-decrypt:
		@go run main.go decrypt --string eyJhbGciOiJkaXIiLCJraWQiOiIyN2JhMjIxYmJkZDZjMjQ1YWVkM2EwNTE4NzMxZDdlNTI5YmQwOGJlMjBiNTM3M2VlY2ZmNzk0MTZiOWY5MDVjIiwiZW5jIjoiQTI1NkdDTSJ9..S6FYgl6CnqdLTkUp.vBZZRw.D2bkbfT24p6SIj6e-yoWow

## Template
helm-template:
		@helm template --name k8ms charts/ --values=values-development.yaml
## Dev
dev:
		@skaffold dev --port-forward=true

