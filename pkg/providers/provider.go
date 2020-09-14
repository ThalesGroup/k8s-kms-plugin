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

	kekKeyOps = []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}
	dekKeyOps = []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}
	sKeyKeyOps    = []jose.KeyOps{jose.KeyOpsSign, jose.KeyOpsVerify}
	ErrNoSuchKey = errors.New("no such key")
	ErrNoSuchCert = errors.New("no such cert")
)
type Config struct {
	CaKid []byte
	KekKid []byte
}
type Provider interface {
	k8s.KeyManagementServiceServer
	istio.KeyManagementServiceServer
	// Ad
	UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error)
}
