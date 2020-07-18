package providers

import (
	"context"
	"errors"
	"github.com/ThalesIgnite/gose/jose"
	"k8s.io/apiserver/pkg/storage/value/encrypt/envelope/v1beta1"
)

var (
	keyOps       = []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}
	ErrNoSuchKey = errors.New("no such key")
)

type Provider interface {
	// Execute decryption operation in KMS provider.
	Decrypt(context.Context, *v1beta1.DecryptRequest) (*v1beta1.DecryptResponse, error)
	// Execute encryption operation in KMS provider.
	Encrypt(context.Context, *v1beta1.EncryptRequest) (*v1beta1.EncryptResponse, error)
}
