package kms

import (
	"context"
	"github.com/ThalesIgnite/crypto11"
	"github.com/sirupsen/logrus"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/providers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"k8s.io/apiserver/pkg/storage/value/encrypt/envelope/v1beta1"
	"net"
)

var (
	provider string
	keyName  string
	keyID    string
	debug    bool
)

const socketName = ".sock"

type KMS struct {
	ctx        *crypto11.Context
	provider   providers.Provider
	socketPath string
}

func New(p providers.Provider, socketPath string) (l *KMS, err error) {
	l = &KMS{
		provider:   p,
		socketPath: socketPath,
	}

	return
}

func (l *KMS) Version(ctx context.Context, req *v1beta1.VersionRequest) (resp *v1beta1.VersionResponse, err error) {

	resp = &v1beta1.VersionResponse{
		Version:        "0.1.0",
		RuntimeName:    "k8s-kms-plugin",
		RuntimeVersion: "v0",
	}
	return
}

func (l *KMS) Decrypt(ctx context.Context, req *v1beta1.DecryptRequest) (resp *v1beta1.DecryptResponse, err error) {

	return l.provider.Decrypt(ctx, req)
}

func (l *KMS) Encrypt(ctx context.Context, req *v1beta1.EncryptRequest) (resp *v1beta1.EncryptResponse, err error) {

	return l.provider.Encrypt(ctx, req)
}

func (l *KMS) Start(ctx context.Context, shutdown chan error, lis net.Listener) (err error) {

	// Create a gRPC server to host the services
	serverOptions := []grpc.ServerOption{}
	// Add some response

	s := grpc.NewServer(serverOptions...)
	// And if we are in debug add reflection
	if debug {
		reflection.Register(s)
	}
	v1beta1.RegisterKeyManagementServiceServer(s, l)
	logrus.Infof("gRPC Listening on %s://%s ", lis.Addr().Network(), lis.Addr().String())

	if err = s.Serve(lis); err != nil {
		shutdown <- err
		return
	}

	return
}
