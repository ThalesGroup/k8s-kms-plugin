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
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
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

func generateDEK(ctx *crypto11.Context, encryptor gose.JweEncryptor, kind istio.KeyKind, size int) (encryptedKeyBlob []byte, err error) {

	switch kind {
	case istio.KeyKind_AES:
		var aesbits = make([]byte, size)
		var rng io.Reader
		if rng, err = ctx.NewRandomReader(); err != nil {
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

type P11 struct {
	//keyId     []byte
	keyLabel   []byte
	config     *crypto11.Config
	ctx        *crypto11.Context
	encryptors map[string]gose.JweEncryptor
	decryptors map[string]gose.JweDecryptor
	createKey  bool
}

func NewP11(keyLabel string, config *crypto11.Config, createKey bool) (p *P11, err error) {

	p = &P11{
		keyLabel:  []byte(keyLabel),
		config:    config,
		createKey: createKey,
	}
	// Bootstrap the Pkcs11 device or die
	if p.ctx, err = crypto11.Configure(p.config); err != nil {
		return
	}
	return
}

//Close the key manager
func (p *P11) Close() (err error) {
	p.encryptors = nil
	p.decryptors = nil
	err = p.ctx.Close()

	return
}

// Symmetric Encryption....
func (p *P11) Decrypt(ctx context.Context, req *k8s.DecryptRequest) (resp *k8s.DecryptResponse, err error) {
	var decryptor gose.JweDecryptor
	if decryptor = p.decryptors[req.KeyId]; decryptor == nil {
		if _, decryptor, err = p.loadKeyWithID([]byte(req.KeyId)); err != nil {
			return
		}
	}

	var out []byte
	if out, _, err = decryptor.Decrypt(string(req.Cipher)); err != nil {
		return
	}
	resp = &k8s.DecryptResponse{
		Plain: out,
	}
	return
}

func (p *P11) DestroyKEK(ctx context.Context, request *istio.DestroyKEKRequest) (*istio.DestroyKEKResponse, error) {
	panic("implement me")
}

func (p *P11) Encrypt(ctx context.Context, req *k8s.EncryptRequest) (resp *k8s.EncryptResponse, err error) {
	var encryptor gose.JweEncryptor
	if encryptor = p.encryptors[req.KeyId]; encryptor == nil {
		if encryptor, _, err = p.loadKeyWithID([]byte(req.KeyId)); err != nil {
			return
		}
	}

	var out string
	if out, err = encryptor.Encrypt(req.Plain, nil); err != nil {
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
	var encryptor gose.JweEncryptor
	if encryptor = p.encryptors[string(request.KekKid)]; encryptor == nil {
		if encryptor, _, err = p.loadKeyWithID(request.KekKid); err != nil {
			return
		}
	}
	var dekBlob []byte

	if dekBlob, err = generateDEK(p.ctx, encryptor, request.Kind, int(request.Size)); err != nil {
		return
	}
	resp = &istio.GenerateDEKResponse{
		EncryptedDekBlob: dekBlob,
	}
	return
}

func (p *P11) GenerateKEK(ctx context.Context, request *istio.GenerateKEKRequest) (resp *istio.GenerateKEKResponse, err error) {
	logrus.Infof("Got GenerateKEK call")
	if request.KekKid == nil {
		request.KekKid, err = p.genKekKid()
		if err != nil {
			logrus.Error(err)
			return
		}
	}
	_, err = p.Generate(request.KekKid, []byte(defaultkeyLabel), jose.AlgA256GCM)
	if err != nil {
		logrus.Error(err)
		return
	}
	resp = &istio.GenerateKEKResponse{
		KekKid: request.KekKid,
	}
	return

}

// GenerateSEK gens a 4096 RSA Key with the DEK that is protected by the KEK for later Unwrapping by the remote client in it's pod/container
func (p *P11) GenerateSEK(ctx context.Context, request *istio.GenerateSEKRequest) (resp *istio.GenerateSEKResponse, err error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "no request sent")
	}
	if request.EncryptedDekBlob == nil {
		err = status.Error(codes.InvalidArgument, "EncryptedDekBlob required ")
		return
	}
	var decryptor gose.JweDecryptor
	if decryptor = p.decryptors[string(request.KekKid)]; decryptor == nil {
		if _, decryptor, err = p.loadKeyWithID(request.KekKid); err != nil {
			return
		}
	}
	var dekClear []byte
	if dekClear, _, err = decryptor.Decrypt(string(request.EncryptedDekBlob)); err != nil {
		return
	}
	var jwk jose.Jwk
	if jwk, err = gose.LoadJwk(bytes.NewReader(dekClear), keyOps); err != nil {
		return
	}

	var aead gose.AuthenticatedEncryptionKey
	if aead, err = gose.NewAesGcmCryptorFromJwk(jwk, keyOps); err != nil {
		return
	}
	dekEncryptor := gose.NewJweDirectEncryptorImpl(aead)

	var wrappedSEK []byte
	if wrappedSEK, err = p.generateSEK(ctx, request, dekEncryptor); err != nil {
		return
	}
	resp = &istio.GenerateSEKResponse{}
	resp.EncryptedSekBlob = []byte(wrappedSEK)
	return
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
	if key, err = gose.NewAesGcmCryptor(aead, rng, string(identity), jose.AlgA256GCM, keyOps); err != nil {
		return
	}
	return
}

// LoadDEK unwraps the supplied SEK with the Wrapped SEK
func (p *P11) LoadSEK(ctx context.Context, request *istio.LoadSEKRequest) (resp *istio.LoadSEKResponse, err error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "no request sent")
	}
	var decryptor gose.JweDecryptor
	if decryptor = p.decryptors[string(request.KekKid)]; decryptor == nil {
		if _, decryptor, err = p.loadKeyWithID(request.KekKid); err != nil {
			return
		}
	}
	var clearDEK []byte
	if clearDEK, _, err = decryptor.Decrypt(string(request.EncryptedDekBlob)); err != nil {
		return
	}
	var jwk jose.Jwk
	if jwk, err = gose.LoadJwk(bytes.NewReader(clearDEK), keyOps); err != nil {
		return
	}
	var aead gose.AuthenticatedEncryptionKey
	if aead, err = gose.NewAesGcmCryptorFromJwk(jwk, keyOps); err != nil {
		return
	}
	dekDecryptor := gose.NewJweDirectDecryptorImpl([]gose.AuthenticatedEncryptionKey{aead})
	resp = &istio.LoadSEKResponse{

	}
	if resp.ClearSek, _, err = dekDecryptor.Decrypt(string(request.EncryptedSekBlob)); err != nil {
		return
	}

	return
}

func (s *P11) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	var h interface{}
	var err error
	logrus.Infof("Path: %s\n", info.FullMethod)
	h, err = handler(ctx, req)
	return h, err
}

func (p *P11) Version(ctx context.Context, request *v1.VersionRequest) (*v1.VersionResponse, error) {
	panic("implement me")
}

func (p *P11) genKekKid() (kid []byte, err error) {
	var u uuid.UUID
	u, err = uuid.NewRandom()
	if err != nil {
		return
	}
	kid, err = u.MarshalText()
	if err != nil {
		return
	}
	return
}

func (p *P11) generateSEK(ctx context.Context, request *istio.GenerateSEKRequest, dekEncryptor gose.JweEncryptor) (wrappedSEK []byte, err error) {
	// Generate the actual SEK
	var rng io.Reader
	if rng, err = p.ctx.NewRandomReader(); err != nil {
		return
	}
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
		var wrappedSEKString string
		if wrappedSEKString, err = dekEncryptor.Encrypt(kpPEM.Bytes, nil); err != nil {
			return
		}
		wrappedSEK = []byte(wrappedSEKString)
	case istio.KeyKind_ECC:
		err = status.Error(codes.Unimplemented, "ECC not yet implemented")
		return
	default:
		err = status.Error(codes.InvalidArgument, "unsupported key kind")
		return
	}

	return
}

func (p *P11) loadKeyWithID(identity []byte) (encryptor gose.JweEncryptor, decryptor gose.JweDecryptor, err error) {

	var rng io.Reader
	var aek gose.AuthenticatedEncryptionKey

	if rng, err = p.ctx.NewRandomReader(); err != nil {
		return
	}
	var handle *crypto11.SecretKey
	if handle, err = p.ctx.FindKey(identity, p.keyLabel); err != nil {
		return
	}
	if handle == nil {
		if p.createKey {
			if aek, err = p.Generate(identity, p.keyLabel, jose.AlgA256GCM); err != nil {
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
		if aek, err = gose.NewAesGcmCryptor(aead, rng, string(identity), jose.AlgA256GCM, keyOps); err != nil {
			return
		}
	}

	decryptor = gose.NewJweDirectDecryptorImpl([]gose.AuthenticatedEncryptionKey{aek})
	encryptor = gose.NewJweDirectEncryptorImpl(aek)

	return
}

type keyGenerationParameters struct {
	size   int
	cipher *crypto11.SymmetricCipher
}
