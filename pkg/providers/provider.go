package providers

import (
	"context"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/kms/v1"

	"google.golang.org/grpc"
)

type Provider interface {
	kms.KeyManagementServiceServer
	// Additional features
	UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error)
	LoadIntKek() (err error)
}
