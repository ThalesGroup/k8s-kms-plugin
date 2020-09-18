package providers

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
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
	"math/big"
	"reflect"
)

var (
	defaultKEKlabel    = []byte("k8s-kms-plugin-kek")
	defaultRootCAlabel = []byte("k8s-kms-plugin-root-ca")
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

func generateDEK(ctx11 *crypto11.Context, encryptor gose.JweEncryptor) (encryptedKeyBlob []byte, err error) {

	key := make([]byte, 32)

	var rng io.Reader
	if rng, err = ctx11.NewRandomReader(); err != nil {
		logrus.Error(err)
		return
	}

	if _, err = rng.Read(key); err != nil {
		return
	}

	var dekJWK jose.Jwk
	if dekJWK, err = gose.JwkFromSymmetric(key, jose.AlgA256GCM); err != nil {
		return
	}
	var dekStr []byte
	dekStr, err = json.Marshal(dekJWK)
	// using the AES key as it's payload
	var encryptedString string
	if encryptedString, err = encryptor.Encrypt(dekStr, nil); err != nil {
		logrus.Error(err)
		return
	}
	encryptedKeyBlob = []byte(encryptedString)

	return
}

// generateKEK an KEK
func generateKEK(ctx *crypto11.Context, identity, label []byte, alg jose.Alg) (key gose.AuthenticatedEncryptionKey, err error) {
	params, supported := algToKeyGenParams[alg]
	if !supported {
		err = fmt.Errorf("algorithm %v is not supported", alg)
		return
	}

	if _, err = ctx.GenerateSecretKeyWithLabel(identity, label, params.size, params.cipher); err != nil {
		return
	}

	return
}

func generateSKey(ctx *crypto11.Context, request *istio.GenerateSKeyRequest, dekEncryptor gose.JweEncryptor) (wrappedSKey []byte, err error) {
	var rng io.Reader
	if rng, err = ctx.NewRandomReader(); err != nil {
		return
	}
	switch request.Kind {
	case istio.KeyKind_RSA:
		var kp *rsa.PrivateKey
		if kp, err = rsa.GenerateKey(rng, int(request.Size)); err != nil {
			return
		}
		kpPEM := &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(kp),
		}
		buf := bytes.NewBuffer([]byte{})
		if err = pem.Encode(buf, kpPEM); err != nil {
			return
		}

		// Wrap and return the wrappedSKey
		var wrappedSKeyString string
		if wrappedSKeyString, err = dekEncryptor.Encrypt(buf.Bytes(), nil); err != nil {
			return
		}
		wrappedSKey = []byte(wrappedSKeyString)
	case istio.KeyKind_ECC:
		err = status.Error(codes.Unimplemented, "ECC not yet implemented")
		return
	default:
		err = status.Error(codes.InvalidArgument, "unsupported key kind")
		return
	}

	return
}

func loadKEKbyID(ctx *crypto11.Context, identity, label []byte, ) (encryptor gose.JweEncryptor, decryptor gose.JweDecryptor, err error) {

	var rng io.Reader
	var aek gose.AuthenticatedEncryptionKey

	if rng, err = ctx.NewRandomReader(); err != nil {
		return
	}
	// get the HSM Key
	var handle *crypto11.SecretKey
	if handle, err = ctx.FindKey(identity, label); err != nil {
		return
	}
	if handle == nil {
		err = errors.New("no such key")
		return
	}
	var aead cipher.AEAD
	if aead, err = handle.NewGCM(); err != nil {
		return
	}
	if aek, err = gose.NewAesGcmCryptor(aead, rng, string(identity), jose.AlgA256GCM, kekKeyOps); err != nil {
		return
	}
	decryptor = gose.NewJweDirectDecryptorImpl([]gose.AuthenticatedEncryptionKey{aek})
	encryptor = gose.NewJweDirectEncryptorImpl(aek)

	return
}

func randomSerial() (serial *big.Int) {
	serial, _ = rand.Int(rand.Reader, big.NewInt(20000))
	return
}

type P11 struct {
	kid        []byte
	cid        []byte
	config     *crypto11.Config
	ctx        *crypto11.Context
	encryptors map[string]gose.JweEncryptor
	decryptors map[string]gose.JweDecryptor
	createKey  bool
}

func NewP11(config *crypto11.Config, createKey bool) (p *P11, err error) {

	p = &P11{
		config:    config,
		createKey: createKey,
	}
	// Bootstrap the Pkcs11 device or die
	if p.ctx, err = crypto11.Configure(p.config); err != nil {
		logrus.Error(err)
		return
	}
	return
}

func (p *P11) AuthenticatedDecrypt(ctx context.Context, request *istio.AuthenticatedDecryptRequest) (resp *istio.AuthenticatedDecryptResponse, err error) {
	var kekDecryptor gose.JweDecryptor
	if kekDecryptor = p.decryptors[string(request.KekKid)]; kekDecryptor == nil {
		if _, kekDecryptor, err = loadKEKbyID(p.ctx, request.KekKid, defaultKEKlabel); err != nil {
			return
		}
	}

	var dekDecrypted []byte
	var aadFromWrappedDek []byte
	dekDecrypted, aadFromWrappedDek, err = kekDecryptor.Decrypt(string(request.EncryptedDekBlob))
	if nil != err {
		return
	}

	// Should be nil
	if nil != aadFromWrappedDek {
		return
	}

	var loadedDek jose.Jwk
	loadedDek, err = gose.LoadJwk(bytes.NewReader(dekDecrypted), []jose.KeyOps{jose.KeyOpsDecrypt})
	if nil != err {
		return
	}

	var dekAead gose.AuthenticatedEncryptionKey
	if dekAead, err = gose.NewAesGcmCryptorFromJwk(loadedDek, []jose.KeyOps{jose.KeyOpsDecrypt}); nil != err {
		return
	}

	var dekAeadDecryptor gose.JweDecryptor
	dekAeadDecryptor = gose.NewJweDirectDecryptorImpl([]gose.AuthenticatedEncryptionKey{dekAead})

	var pt, aad []byte
	if pt, aad, err = dekAeadDecryptor.Decrypt(string(request.Ciphertext)); err != nil {
		return
	}
	if !reflect.DeepEqual(aad, request.Aad) {
		err = status.Error(codes.InvalidArgument, "AAD does not match... invalid request/code")
		return
	}
	resp = &istio.AuthenticatedDecryptResponse{
		Plaintext: pt,
	}

	return
}

func (p *P11) AuthenticatedEncrypt(ctx context.Context, request *istio.AuthenticatedEncryptRequest) (resp *istio.AuthenticatedEncryptResponse, err error) {
	var kekDecryptor gose.JweDecryptor
	if kekDecryptor = p.decryptors[string(request.KekKid)]; nil == kekDecryptor {
		if _, kekDecryptor, err = loadKEKbyID(p.ctx, request.KekKid, defaultKEKlabel); nil != err {
			return
		}
	}

	var dekDecrypted []byte
	var aadFromWrappedDek []byte
	dekDecrypted, aadFromWrappedDek, err = kekDecryptor.Decrypt(string(request.EncryptedDekBlob))
	if nil != err {
		return
	}

	// Should be nil
	if nil != aadFromWrappedDek {
		return
	}

	var loadedDek jose.Jwk
	loadedDek, err = gose.LoadJwk(bytes.NewReader(dekDecrypted), []jose.KeyOps{jose.KeyOpsEncrypt})
	if nil != err {
		return
	}

	var dekAead gose.AuthenticatedEncryptionKey
	if dekAead, err = gose.NewAesGcmCryptorFromJwk(loadedDek, []jose.KeyOps{jose.KeyOpsEncrypt}); nil != err {
		return
	}

	var dekAeadEncryptor gose.JweEncryptor
	dekAeadEncryptor = gose.NewJweDirectEncryptorImpl(dekAead)

	resp = &istio.AuthenticatedEncryptResponse{}
	var ct string
	if ct, err = dekAeadEncryptor.Encrypt(request.Plaintext, request.Aad); err != nil {
		return
	}
	resp.Ciphertext = []byte(ct)
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
		if _, decryptor, err = loadKEKbyID(p.ctx, []byte(req.KeyId), []byte(defaultKEKlabel)); err != nil {
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

func (p *P11) Encrypt(ctx context.Context, req *k8s.EncryptRequest) (resp *k8s.EncryptResponse, err error) {
	var encryptor gose.JweEncryptor
	if encryptor = p.encryptors[req.KeyId]; encryptor == nil {
		if encryptor, _, err = loadKEKbyID(p.ctx, []byte(req.KeyId), []byte(defaultKEKlabel)); err != nil {
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

// GenerateDEK a 256 bit AES DEK Key , Wrapped via JWE with the PKCS11 base KEK
func (p *P11) GenerateDEK(ctx context.Context, request *istio.GenerateDEKRequest) (resp *istio.GenerateDEKResponse, err error) {
	if request == nil {
		logrus.Error(err)
		return nil, status.Error(codes.InvalidArgument, "no request sent")
	}
	var encryptor gose.JweEncryptor
	if encryptor = p.encryptors[string(request.KekKid)]; encryptor == nil {
		if encryptor, _, err = loadKEKbyID(p.ctx, []byte(request.KekKid), []byte(defaultKEKlabel)); err != nil {
			return
		}
	}
	var dekBlob []byte

	if dekBlob, err = generateDEK(p.ctx, encryptor); err != nil {
		logrus.Error(err)
		return
	}
	resp = &istio.GenerateDEKResponse{
		EncryptedDekBlob: dekBlob,
	}
	return
}

// GenerateKEK a 256 bit AES KEK Key that resides in the Pkcs11 device
func (p *P11) GenerateKEK(ctx context.Context, request *istio.GenerateKEKRequest) (resp *istio.GenerateKEKResponse, err error) {
	if request.KekKid == nil {
		request.KekKid, err = p.genKekKid()
		if err != nil {
			logrus.Error(err)
			return
		}
	}

	_, err = generateKEK(p.ctx, request.KekKid, []byte(defaultKEKlabel), jose.AlgA256GCM)
	if err != nil {
		logrus.Error(err)
		return
	}
	resp = &istio.GenerateKEKResponse{
		KekKid: request.KekKid,
	}
	return

}

// GenerateSKey gens a 4096 RSA Key with the DEK that is protected by the KEK for later Unwrapping by the remote client in it's pod/container
func (p *P11) GenerateSKey(ctx context.Context, request *istio.GenerateSKeyRequest) (resp *istio.GenerateSKeyResponse, err error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "no request sent")
	}
	if request.EncryptedDekBlob == nil {
		err = status.Error(codes.InvalidArgument, "EncryptedDekBlob required ")
		return
	}
	var decryptor gose.JweDecryptor
	if decryptor = p.decryptors[string(request.KekKid)]; decryptor == nil {
		if _, decryptor, err = loadKEKbyID(p.ctx, request.KekKid, []byte(defaultKEKlabel)); err != nil {
			return
		}
	}

	var dekClear []byte
	if dekClear, _, err = decryptor.Decrypt(string(request.EncryptedDekBlob)); err != nil {
		return
	}
	var jwk jose.Jwk
	if jwk, err = gose.LoadJwk(bytes.NewReader(dekClear), kekKeyOps); err != nil {
		return
	}

	var aead gose.AuthenticatedEncryptionKey
	if aead, err = gose.NewAesGcmCryptorFromJwk(jwk, kekKeyOps); err != nil {
		return
	}
	dekEncryptor := gose.NewJweDirectEncryptorImpl(aead)

	var wrappedSKey []byte
	if wrappedSKey, err = generateSKey(p.ctx, request, dekEncryptor); err != nil {
		return
	}
	resp = &istio.GenerateSKeyResponse{}
	resp.EncryptedSkeyBlob = []byte(wrappedSKey)
	return
}

// ImportCACert inserts the Root CA cert chain
func (p *P11) ImportCACert(ctx context.Context, request *istio.ImportCACertRequest) (resp *istio.ImportCACertResponse, err error) {
	resp = &istio.ImportCACertResponse{
		Success: false,
	}
	var pp *pem.Block
	if pp, _ = pem.Decode(request.CaCertBlob); pp == nil {
		err = fmt.Errorf("unable to decode provided cert blob")
		return
	}
	var cert *x509.Certificate
	if cert, err = x509.ParseCertificate(pp.Bytes); err != nil {
		return
	}

	// RF: setting p.kid to request.KekKid so we can recall the kid later for retrieving the cert
	p.cid = request.CaId

	// RF: Todo - are we using cert.subject.string or the default label here? If we use cert.subject.string we don't currently have any way of recalling this later on when using to verify
	if err = p.ctx.ImportCertificateWithLabel(p.cid, []byte(cert.Subject.String()), cert); err != nil {
		return
	}
	resp.Success = true

	return
}

// LoadSKey unwraps the supplied sKey with the Wrapped sKey
func (p *P11) LoadSKey(ctx context.Context, request *istio.LoadSKeyRequest) (resp *istio.LoadSKeyResponse, err error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "no request sent")
	}
	var decryptor gose.JweDecryptor
	if decryptor = p.decryptors[string(request.KekKid)]; decryptor == nil {
		if _, decryptor, err = loadKEKbyID(p.ctx, request.KekKid, []byte(defaultKEKlabel)); err != nil {
			return
		}
	}

	// Decrypt and Load the DEK for usage...
	var clearDEK []byte
	if clearDEK, _, err = decryptor.Decrypt(string(request.EncryptedDekBlob)); err != nil {
		return
	}
	var jwk jose.Jwk
	if jwk, err = gose.LoadJwk(bytes.NewReader(clearDEK), kekKeyOps); err != nil {
		return
	}

	var aead gose.AuthenticatedEncryptionKey
	if aead, err = gose.NewAesGcmCryptorFromJwk(jwk, kekKeyOps); err != nil {
		return
	}
	dekDecryptor := gose.NewJweDirectDecryptorImpl([]gose.AuthenticatedEncryptionKey{aead})
	resp = &istio.LoadSKeyResponse{
		PlaintextSkey: nil,
	}

	// Return the clear sKey in PEM format or bust
	if resp.PlaintextSkey, _, err = dekDecryptor.Decrypt(string(request.EncryptedSkeyBlob)); err != nil {
		return
	}

	return
}

func (s *P11) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	var h interface{}
	var err error
	h, err = handler(ctx, req)
	return h, err
}

// VerifyCertChain verifies a provided cert-chain (currently self-contained)
func (p *P11) VerifyCertChain(ctx context.Context, request *istio.VerifyCertChainRequest) (resp *istio.VerifyCertChainResponse, err error) {
	defer func() {
		if err != nil {
			logrus.Errorf("Error in VerifyCertChain: %v", err)
		}
	}()
	if nil == request {
		return nil, status.Error(codes.InvalidArgument, "no request sent")
	}

	if nil == request.Certificates {
		err = fmt.Errorf("no certificates provided")
		return
	}

	if 1 != len(request.Certificates) {
		err = fmt.Errorf("test VerifyCertChain currently needs a target cert")
		return
	}

	var parsedTargetCert *x509.Certificate
	parsedTargetCert, err = x509.ParseCertificate(request.Certificates[0])
	if nil != err {
		return
	}

	var verifyOpts = x509.VerifyOptions{
		Roots: x509.NewCertPool(),
	}

	if nil == p.cid {
		err = fmt.Errorf("no loaded CA cert for verification")
		return
	}
	// Todo - do we want to record the label/serial during import too?
	var retrievedRootCert *x509.Certificate
	if retrievedRootCert, err = p.ctx.FindCertificate(p.cid, nil, nil); nil != err {
		return
	}

	verifyOpts.Roots.AddCert(retrievedRootCert)

	resp = &istio.VerifyCertChainResponse{}

	_, verifyErr := parsedTargetCert.Verify(verifyOpts)
	if nil != verifyErr {
		err = verifyErr
	} else {
		resp.SuccessfulVerification = true
	}

	return

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

type keyGenerationParameters struct {
	size   int
	cipher *crypto11.SymmetricCipher
}
