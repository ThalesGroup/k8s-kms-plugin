package providers

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/istio/v1"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/k8s/v1"
	v1 "github.com/thalescpl-io/k8s-kms-plugin/apis/kms/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
)

const (
	defaultkeyLabel = "k8s-kms-plugin-root-key"
	defaultDEKSize  = 32 // 32 == 256 AES Key
)

var (
	algToKeyGenParams = map[jose.Alg]keyGenerationParameters{
		jose.AlgA128GCM: {
			size:   128,
			cipher: crypto11.CipherAES,
		},
		jose.AlgA192GCM: {
			size:   192,
			cipher: crypto11.CipherAES,
		},
		jose.AlgA256GCM: {
			size:   256,
			cipher: crypto11.CipherAES,
		},
	}
)

type P11 struct {
	keyId     []byte
	keyLabel  []byte
	config    *crypto11.Config
	ctx       *crypto11.Context
	encryptor gose.JweEncryptor
	decryptor gose.JweDecryptor
	createKey bool
}

func NewP11(keyId string, keyLabel string, config *crypto11.Config, createKey bool) (p *P11, err error) {

	p = &P11{
		keyId:     []byte(keyId),
		keyLabel:  []byte(keyLabel),
		config:    config,
		createKey: createKey,
	}
	return
}

//Close the key manager
func (p *P11) Close() (err error) {
	p.encryptor = nil
	p.decryptor = nil
	err = p.ctx.Close()

	return
}

func (p *P11) Decrypt(ctx context.Context, req *k8s.DecryptRequest) (resp *k8s.DecryptResponse, err error) {
	if p.decryptor == nil {
		if err = p.loadDevice(); err != nil {
			return
		}
	}
	var out []byte
	if out, _, err = p.decryptor.Decrypt(string(req.Cipher)); err != nil {
		return
	}
	resp = &k8s.DecryptResponse{
		Plain: out,
	}
	return
}

func (p *P11) Encrypt(ctx context.Context, req *k8s.EncryptRequest) (resp *k8s.EncryptResponse, err error) {
	if p.encryptor == nil {
		if err = p.loadDevice(); err != nil {
			return
		}
	}
	var out string
	if out, err = p.encryptor.Encrypt(req.Plain, nil); err != nil {
		return
	}
	resp = &k8s.EncryptResponse{
		Cipher: []byte(out),
	}
	return
}

//Generate an AEK
func (p *P11) Generate(identity, label []byte, alg jose.Alg) (key gose.AuthenticatedEncryptionKey, err error) {
	params, supported := algToKeyGenParams[alg]
	if !supported {
		err = fmt.Errorf("algorithm %v is not supported", alg)
		return
	}

	if _, err = p.ctx.GenerateSecretKeyWithLabel(identity, label, params.size, params.cipher); err != nil {
		return
	}

	key, err = p.Load(identity)
	return
}

// Generate a 256 bit AES DEK Key , Wrapped via JWE with the PKCS11 base KEK
func (p *P11) GenerateDEK(ctx context.Context, request *istio.GenerateDEKRequest) (resp *istio.GenerateDEKResponse, err error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "no request sent")
	}
	if p.encryptor == nil {
		if err = p.loadDevice(); err != nil {
			return
		}
	}
	var encryptedKeyBlob []byte

	if encryptedKeyBlob, err = generateDEK(p.ctx, p.encryptor, request.Kind, int(request.Size)); err != nil {
		return
	}
	resp = &istio.GenerateDEKResponse{
		EncryptedKeyBlob: encryptedKeyBlob,
	}
	return
}

func generateDEK(ctx *crypto11.Context, encryptor gose.JweEncryptor, kind istio.KeyKind, size int) (encryptedKeyBlob []byte, err error) {



	switch kind {
	case istio.KeyKind_AES:
		var aesbits = make([]byte, size)
		var rng io.Reader
		if rng, err =ctx.NewRandomReader(); err != nil {
			return
		}
		if _, err = rng.Read(aesbits); err != nil {
			return
		}

		// using the AES key as it's payload
		var encryptedString string
		if encryptedString, err = encryptor.Encrypt(aesbits, nil); err != nil {
			return
		}
		encryptedKeyBlob = []byte(encryptedString)
	default:
		err = status.Error(codes.InvalidArgument, "invalid DEK key kind")
		return
	}
	// fill aesbits with 32bytes of random data from the RNG

	return
}

// GenerateSEK gens a 4096 RSA Key with the DEK that is protected by the KEK for later Unwrapping by the remote client in it's pod/container
func (p *P11) GenerateSEK(ctx context.Context, request *istio.GenerateSEKRequest) (resp *istio.GenerateSEKResponse, err error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "no request sent")
	}
	if request.EncryptedKeyBlob == nil {
		err = status.Error(codes.InvalidArgument, "EncryptedKeyBlob required ")
	}
	if p.decryptor == nil {
		if err = p.loadDevice(); err != nil {
			return
		}
	}
	var rng io.Reader
	if rng, err = p.ctx.NewRandomReader(); err != nil {
		return
	}

	var dekClear []byte
	if dekClear, _, err = p.decryptor.Decrypt(string(request.EncryptedKeyBlob)); err != nil {
		return
	}
	var jwk jose.Jwk
	jwk, err = gose.LoadJwk(bytes.NewReader(dekClear), keyOps)

	var aead gose.AuthenticatedEncryptionKey
	if aead, err = gose.NewAesGcmCryptorFromJwk(jwk, keyOps); err != nil {
		return
	}
	dekEncryptor := gose.NewJweDirectEncryptorImpl(aead)

	// Generate the actual SEK
	var wrappedSEK string

	switch request.Kind {
	case istio.KeyKind_RSA:
		var kp *rsa.PrivateKey
		if kp, err = rsa.GenerateKey(rng, int(request.Size)); err != nil {
			return
		}
		kpPEM := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(kp),
		}
		// Wrap and return the wrappedSEK

		if wrappedSEK, err = dekEncryptor.Encrypt(kpPEM.Bytes, nil); err != nil {
			return
		}
	case istio.KeyKind_ECC:
		err = status.Error(codes.Unimplemented, "ECC not yet implemented")
		return
	default:
		err = status.Error(codes.InvalidArgument, "unsupported key kind")
		return
	}
	resp = &istio.GenerateSEKResponse{}
	resp.EncryptedKeyBlob = []byte(wrappedSEK)
	return
}

// LoadDEK unwraps the supplied EncryptedKeyBlob with the HSM's KEK for this cluster.
func (p *P11) LoadDEK(ctx context.Context, request *istio.LoadDEKRequest) (resp *istio.LoadDEKResponse, err error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "no request sent")
	}
	if p.decryptor == nil {
		if err = p.loadDevice(); err != nil {
			return
		}
	}

	resp = &istio.LoadDEKResponse{}
	if resp.ClearKey, _, err = p.decryptor.Decrypt(string(request.EncryptedKeyBlob)); err != nil {
		return
	}

	return
}

//Identity of the Key manager
func (p *P11) Identity() string {
	return string(p.keyId)
}

//Load an AEK
func (p *P11) Load(identity []byte) (key gose.AuthenticatedEncryptionKey, err error) {
	var rng io.Reader

	if rng, err = p.ctx.NewRandomReader(); err != nil {
		return
	}
	var handle *crypto11.SecretKey
	if handle, err = p.ctx.FindKey(identity, p.keyLabel); err != nil {
		return
	}
	if handle == nil {
		err = ErrNoSuchKey
		return
	}
	var aead cipher.AEAD
	if aead, err = handle.NewGCM(); err != nil {
		return
	}
	if key, err = gose.NewAesGcmCryptor(aead, rng, string(p.keyId), jose.AlgA256GCM, keyOps); err != nil {
		return
	}
	return
}

func (s *P11) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	var h interface{}
	var err error
	fmt.Printf("Path: %s\n", info.FullMethod)
	return h, err
}

func (p *P11) Version(ctx context.Context, request *v1.VersionRequest) (*v1.VersionResponse, error) {
	panic("implement me")
}

func (p *P11) loadDevice() (err error) {
	if p.ctx, err = crypto11.Configure(p.config); err != nil {
		return
	}
	var rng io.Reader
	var aek gose.AuthenticatedEncryptionKey

	if rng, err = p.ctx.NewRandomReader(); err != nil {
		return
	}
	var handle *crypto11.SecretKey
	if handle, err = p.ctx.FindKey(p.keyId, p.keyLabel); err != nil {
		return
	}
	if handle == nil {
		if p.createKey {
			if aek, err = p.Generate(p.keyId, p.keyLabel, jose.AlgA256GCM); err != nil {
				return
			}
		} else {
			err = errors.New("no such key")
			return
		}

	} else {
		var aead cipher.AEAD
		if aead, err = handle.NewGCM(); err != nil {
			return
		}
		if aek, err = gose.NewAesGcmCryptor(aead, rng, string(p.keyId), jose.AlgA256GCM, keyOps); err != nil {
			return
		}
	}

	p.decryptor = gose.NewJweDirectDecryptorImpl([]gose.AuthenticatedEncryptionKey{aek})
	p.encryptor = gose.NewJweDirectEncryptorImpl(aek)

	return
}

type keyGenerationParameters struct {
	size   int
	cipher *crypto11.SymmetricCipher
}
