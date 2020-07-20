package providers

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/istio/v1"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/k8s/v1"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/kms/v1"
	"google.golang.org/grpc"
	"io/ioutil"
	"os"
	"path"
)



const defaultKey = "_master_key"

func pathExists(filePath string) (exists bool) {
	exists = true

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		exists = false
	}

	return
}

type Native struct {
	path      string
	encryptor *gose.JweDirectEncryptionEncryptorImpl
	decryptor *gose.JweDirectDecryptorImpl
}

func NewNative(path string) (n *Native, err error) {
	n = &Native{
		path: path,
	}
	var key gose.AuthenticatedEncryptionKey
	if key, err = n.Load(defaultKey); err != nil {
		if err == ErrNoSuchKey {
			// If not exist, generate...
			if key, err = n.Generate(defaultKey, jose.AlgA256GCM); err != nil {
				return
			}
		} else {
			return
		}
	}
	n.encryptor = gose.NewJweDirectEncryptorImpl(key)
	n.decryptor = gose.NewJweDirectDecryptorImpl([]gose.AuthenticatedEncryptionKey{key})
	return
}

//Close the key manager
func (km *Native) Close() (err error) {
	return
}

func (n *Native) Decrypt(ctx context.Context, req *k8s.DecryptRequest) (resp *k8s.DecryptResponse, err error) {
	resp = &k8s.DecryptResponse{}
	if resp.Plain, _, err = n.decryptor.Decrypt(string(req.Cipher)); err != nil {
		return
	}
	return
}

func (n *Native) Encrypt(ctx context.Context, req *k8s.EncryptRequest) (resp *k8s.EncryptResponse, err error) {
	resp = &k8s.EncryptResponse{}
	var payload string
	if payload, err = n.encryptor.Encrypt(req.Plain, nil); err != nil {
		return
	}
	resp.Cipher = []byte(payload)
	return
}
//Generate an AEK
func (km *Native) Generate(identity string, alg jose.Alg) (key gose.AuthenticatedEncryptionKey, err error) {
	if err = os.MkdirAll(km.path, 0600); err != nil {
		return
	}
	generator := gose.AuthenticatedEncryptionKeyGenerator{}
	var jwk jose.Jwk
	if key, jwk, err = generator.Generate(alg, keyOps); err != nil {
		return
	}
	var jwkStr string
	if jwkStr, err = gose.JwkToString(jwk); err != nil {
		return
	}

	// See if file/dir exists in amazon
	if !pathExists(km.path) {
		err = errors.New("key manager directory is corrupt or missing")
		return
	}
	err = ioutil.WriteFile(path.Join(km.path, identity), []byte(jwkStr), 0600)
	return
}
func (n *Native) GenerateDEK(ctx context.Context, request *istio.GenerateDEKRequest) (*istio.GenerateDEKResponse, error) {
	panic("implement me")
}

func (n *Native) GenerateSEK(ctx context.Context, request *istio.GenerateSEKRequest) (*istio.GenerateSEKResponse, error) {
	panic("implement me")
}

//Identity returns the ID of thise KeyManager
func (km *Native) Identity() string {
	return base64.RawURLEncoding.EncodeToString([]byte(km.path))
}

//Load an AEK
func (km *Native) Load(identity string) (key gose.AuthenticatedEncryptionKey, err error) {
	filePath := path.Join(km.path, identity)
	var jwk jose.Jwk
	if jwk, err = gose.LoadJwkFromFile(filePath, keyOps); err != nil {
		if err == gose.ErrInvalidSigningKeyURL {
			err = ErrNoSuchKey
		}
		return
	}

	key, err = gose.NewAesGcmCryptorFromJwk(jwk, keyOps)
	return
}

func (n *Native) LoadDEK(ctx context.Context, request *istio.LoadDEKRequest) (*istio.LoadDEKResponse, error) {
	panic("implement me")
}

func (n *Native) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	var h interface{}
	var err error
	fmt.Printf("Path: %s\n", info.FullMethod)
	return h, err
}

func (n *Native) Version(ctx context.Context, request *kms.VersionRequest) (*kms.VersionResponse, error) {
	panic("implement me")
}
