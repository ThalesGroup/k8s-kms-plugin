package providers

import (
	"context"
	"errors"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/k8s/v1"
)

var (
	keyOps       = []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}
	ErrNoSuchKey = errors.New("no such key")
)

type Provider interface {
	// Execute decryption operation in KMS provider.
	Decrypt(context.Context, *k8s.DecryptRequest) (*k8s.DecryptResponse, error)
	// Execute encryption operation in KMS provider.
	Encrypt(context.Context, *k8s.EncryptRequest) (*k8s.EncryptResponse, error)
}
