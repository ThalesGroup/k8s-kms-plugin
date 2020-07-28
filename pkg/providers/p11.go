package providers

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"time"
)

var (
	defaultKEKlabel = []byte("k8s-kms-plugin-kek")
	defaultCAKlabel = []byte("k8s-kms-plugin-cak")
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

func generateCAK(ctx *crypto11.Context, kid []byte, kind istio.KeyKind, size int) (signer crypto11.SignerDecrypter, err error) {

	switch kind {
	case istio.KeyKind_RSA:
		signer, err = ctx.GenerateRSAKeyPairWithLabel(kid, defaultCAKlabel, size)

	default:
		err = status.Error(codes.Unimplemented, "unsupported key kind")
	}

	return
}

func generateDEK(ctx *crypto11.Context, encryptor gose.JweEncryptor, kind istio.KeyKind, size int) (encryptedKeyBlob []byte, err error) {

	switch kind {
	case istio.KeyKind_AES:
		var key []byte
		switch size {
		case 256:
			key = make([]byte, 32)
		default:
			err = errors.New("only AES 256 supported for DEK keys currently")
		}
		var rng io.Reader
		if rng, err = ctx.NewRandomReader(); err != nil {
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
	default:
		err = status.Error(codes.InvalidArgument, "invalid DEK key kind")
		logrus.Error(err)

		return
	}
	// fill aesbits with 32bytes of random data from the RNG

	return
}

//generateKEK an KEK
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
func generateSEK(ctx *crypto11.Context, request *istio.GenerateSEKRequest, dekEncryptor gose.JweEncryptor) (wrappedSEK []byte, err error) {
	// generateKEK the actual SEK
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
			Type:  "PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(kp),
		}
		buf := bytes.NewBuffer([]byte{})
		if err = pem.Encode(buf, kpPEM); err != nil {
			return
		}
		// Wrap and return the wrappedSEK
		var wrappedSEKString string
		if wrappedSEKString, err = dekEncryptor.Encrypt(buf.Bytes(), nil); err != nil {
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

func loadCADbyID(ctx *crypto11.Context, identity, label []byte, ) (private crypto11.SignerDecrypter, err error) {
	var sd crypto11.Signer
	sd, err = ctx.FindKeyPair(identity, label)
	if err != nil {
		return
	}
	var ok bool
	if private, ok = sd.(crypto11.SignerDecrypter); !ok {
		err = errors.New("unable to load signer decryptor")
	}
	return
}
func loadCAbyID(ctx *crypto11.Context, identity, label []byte, serial *big.Int) (ca *x509.Certificate, err error) {
	if ca, err = ctx.FindCertificate(identity, label, serial); err != nil {
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

type P11 struct {
	//keyId     []byte
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

func (p *P11) DestroyKEK(ctx context.Context, request *istio.DestroyKEKRequest) (*istio.DestroyKEKResponse, error) {
	panic("implement me")
}

func (p *P11) DestroyRootCAK(ctx context.Context, request *istio.DestroyRootCAKRequest) (*istio.DestroyRootCAKResponse, error) {
	panic("implement me")
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

// generateKEK a 256 bit AES DEK Key , Wrapped via JWE with the PKCS11 base KEK
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

	if dekBlob, err = generateDEK(p.ctx, encryptor, request.Kind, int(request.Size)); err != nil {
		logrus.Error(err)
		return
	}
	resp = &istio.GenerateDEKResponse{
		EncryptedDekBlob: dekBlob,
	}
	return
}

// generateKEK a 256 bit AES KEK Key that resides in the Pkcs11 device
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

func (p *P11) GenerateRootCA(ctx context.Context, request *istio.GenerateRootCARequest) (resp *istio.GenerateRootCAResponse, err error) {

	resp = &istio.GenerateRootCAResponse{

	}
	var ca *x509.Certificate
	if ca, err = generateRootCA(p.ctx, request); err != nil {
		return
	}

	logrus.Infof("CA Generated: %v", ca.Issuer)

	return
}
func generateRootCA(ctx *crypto11.Context, request *istio.GenerateRootCARequest) (ca *x509.Certificate, err error) {
	templateCA := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			CommonName: fmt.Sprintf("CA for CAK %s", string(request.RootCaKid)),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	var rng io.Reader
	if rng, err = ctx.NewRandomReader(); err != nil {
		return
	}
	var k crypto11.Signer
	if k, err = ctx.FindKeyPair(request.RootCaKid, defaultCAKlabel); err != nil {
		return
	}
	var caBytes []byte
	if caBytes, err = x509.CreateCertificate(rng, templateCA, templateCA, k.Public(), k); err != nil {
		return
	}
	caPEM := new(bytes.Buffer)
	if err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}); err != nil {
		return
	}
	ca = templateCA
	if err = ctx.ImportCertificateWithLabel(request.RootCaKid, defaultCAKlabel, ca); err != nil {
		return
	}

	return
}
func (p *P11) GenerateRootCAK(ctx context.Context, request *istio.GenerateRootCAKRequest) (resp *istio.GenerateRootCAKResponse, err error) {
	resp = &istio.GenerateRootCAKResponse{

	}
	if _, err = generateCAK(p.ctx, request.RootCaKid, request.Kind, int(request.Size)); err != nil {
		return
	}

	resp.RootCaKid = request.RootCaKid
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

	var wrappedSEK []byte
	if wrappedSEK, err = generateSEK(p.ctx, request, dekEncryptor); err != nil {
		return
	}
	resp = &istio.GenerateSEKResponse{}
	resp.EncryptedSekBlob = []byte(wrappedSEK)
	return
}

// LoadDEK unwraps the supplied SEK with the Wrapped SEK
func (p *P11) LoadSEK(ctx context.Context, request *istio.LoadSEKRequest) (resp *istio.LoadSEKResponse, err error) {
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
	resp = &istio.LoadSEKResponse{
		ClearSek: nil,
	}

	// Return the clear SEK in PEM format or bust
	if resp.ClearSek, _, err = dekDecryptor.Decrypt(string(request.EncryptedSekBlob)); err != nil {
		return
	}

	return
}

func (p *P11) SignCSR(ctx context.Context, request *istio.SignCSRRequest) (resp *istio.SignCSRResponse, err error) {
	var pp crypto11.SignerDecrypter
	if pp, err = loadCADbyID(p.ctx, request.RootCaKid, defaultCAKlabel); err != nil {
		return
	}
	var ca *x509.Certificate
	if ca, err = loadCAbyID(p.ctx, request.RootCaKid, defaultCAKlabel, nil); err != nil {
		return
	}
	var rng io.Reader
	if rng, err = p.ctx.NewRandomReader(); err != nil {
		return
	}
	var template *x509.CertificateRequest
	if template, err = x509.ParseCertificateRequest(request.Csr); err != nil {
		return
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(int64(1)),
		Subject:      template.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     template.DNSNames,
		IPAddresses:  template.IPAddresses,

		BasicConstraintsValid: true,
	}
	var certBytes []byte
	if certBytes, err = x509.CreateCertificate(rng, leaf, ca, pp.Public(), pp); err != nil {
		return
	}
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}

	resp = &istio.SignCSRResponse{
		Cert: pem.EncodeToMemory(certPEM),
	}
	return
}

func (s *P11) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	var h interface{}
	var err error
	h, err = handler(ctx, req)
	return h, err
}

func (p *P11) Version(ctx context.Context, request *v1.VersionRequest) (*v1.VersionResponse, error) {
	panic("implement me")
}

func (p *P11) genCA() (err error) {

	return
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
