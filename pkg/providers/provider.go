package providers

import (
	"context"
	"errors"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/istio/v1"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/k8s/v1"
	"google.golang.org/grpc"
)

var (
	keyOps       = []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}
	ErrNoSuchKey = errors.New("no such key")
)

type Provider interface {
	k8s.KeyManagementServiceServer
	istio.KeyManagementServiceServer
	// Ad
	UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error)

}
