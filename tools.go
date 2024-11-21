//go:build tools
// +build tools

package tools

import (
	_ "github.com/golang/protobuf/protoc-gen-go"
	_ "github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway"
	_ "github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger"
	_ "github.com/infobloxopen/atlas-app-toolkit/rpc/resource"
	_ "github.com/mitchellh/protoc-gen-go-json"
	_ "golang.org/x/tools/cmd/cover"

	_ "k8s.io/kms/apis/v1beta1"
)
