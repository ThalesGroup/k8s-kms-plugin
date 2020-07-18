package kms

import (
	"context"
	"github.com/ThalesIgnite/crypto11"
	"github.com/sirupsen/logrus"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/common/v1"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/istio/v1"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/k8s/v1"

	"github.com/thalescpl-io/k8s-kms-plugin/pkg/providers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"net"
)

var (
	debug bool
)

const socketName = ".sock"

type KMS struct {
	ctx        *crypto11.Context
	provider   providers.Provider
	socketPath string
}

func (l *KMS) Version(ctx context.Context, request *common.VersionRequest) (*common.VersionResponse, error) {
	panic("implement me")
}

func (l *KMS) GenerateDEK(ctx context.Context, request *istio.GenerateDEKRequest) (*istio.GenerateDEKResponse, error) {
	panic("implement me")
}

func (l *KMS) GenerateSEK(ctx context.Context, request *istio.GenerateSEKRequest) (*istio.GenerateSEKRequest, error) {
	panic("implement me")
}

func (l *KMS) LoadDEK(ctx context.Context, request *istio.LoadDEKRequest) (*istio.LoadDEKResponse, error) {
	panic("implement me")
}

func New(p providers.Provider, socketPath string) (l *KMS, err error) {
	l = &KMS{
		provider:   p,
		socketPath: socketPath,
	}

	return
}

func (l *KMS) Decrypt(ctx context.Context, req *k8s.DecryptRequest) (resp *k8s.DecryptResponse, err error) {

	return l.provider.Decrypt(ctx, req)
}

func (l *KMS) Encrypt(ctx context.Context, req *k8s.EncryptRequest) (resp *k8s.EncryptResponse, err error) {

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
	//v1beta1.RegisterKeyManagementServiceServer(s, l)
	k8s.RegisterKeyManagementServiceServer(s, l)
	logrus.Infof("gRPC Listening on %s://%s ", lis.Addr().Network(), lis.Addr().String())

	if err = s.Serve(lis); err != nil {
		shutdown <- err
		return
	}

	return
}
