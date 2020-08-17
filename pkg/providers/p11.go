package providers

import (
	"bytes"
	"context"
	"crypto"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/ThalesIgnite/crypto11"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/sirupsen/logrus"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/kms/v1"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/keystore"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"math/big"
	"net"
	"reflect"
	"time"
)

const (
	wellKnownIntKEK      = "7652596c-714b-4354-96cc-bc708ce50113"
	wellKnownRootKEK     = "63631c88-d466-471c-b000-f369b7609bdf"
	wellKnownIntKeyPair  = "d02ff72f-8ec8-431a-a9eb-9427be7cc972"
	wellKnownRootKeyPair = "d31e0263-c868-40d8-bd72-c581afae0f1e"
	wellKnownCertificate = "e24d4136-c750-4e10-ba25-e0935a962dee"

	labelKEK         = "k8s-kms-plugin-kek"
	labelRootKeypair = "k8s-kms-plugin-root-keypair"
	labelRootCA      = "k8s-kms-plugin-root-ca"
	labelIntKeypair  = "k8s-kms-plugin-int-keypair"
	labelIntCA       = "k8s-kms-plugin-int-ca"
)

var (
	intKekAAD = []byte("wrapper-key")
)

var serialBound = (&big.Int{}).Exp(big.NewInt(2), big.NewInt(160), nil)
var rootCASerial = big.NewInt(42)  // What was the question again?
var intCASerial = big.NewInt(1337) // you know why...

// Return a random serial number suitable for an RFC5280 certificate
func newSerial(randReader io.Reader) (serial *big.Int, err error) {
	if serial, err = rand.Int(randReader, serialBound); err != nil {
		logrus.Errorf("creating serial: %s", err)
		return
	}
	return
}

func randomSerial() (serial *big.Int) {
	serial, _ = rand.Int(rand.Reader, big.NewInt(20000))
	return
}

type P11 struct {
	config          *crypto11.Config
	ctx             *crypto11.Context
	intKekEncryptor gose.JweEncryptor
	intKekDecryptor gose.JweDecryptor
	encryptors      map[string]gose.JweEncryptor
	decryptors      map[string]gose.JweDecryptor
	signers         map[string]gose.SigningKey
	aeGen           *gose.AuthenticatedEncryptionKeyGenerator
	rsGen           *gose.RsaSigningKeyGenerator
	rkdGen          *gose.RsaKeyDecryptionKeyGenerator
	esGen           *gose.ECDSASigningKeyGenerator
	autoCreate      bool
	pubKey          crypto.PublicKey
	rootCert        *x509.Certificate // make sure to load it into your HSM prior
	intCert         *x509.Certificate
	intKek          jose.Jwk
	store           keystore.KeyStore

	// Dev stuff
	overwrite bool
}

func (p *P11) LoadIntKek() (err error) {

	if err = p.genOrLoadRootKek(); err != nil {
		logrus.Error(err)
	}

	return
}

func (p *P11) SignCSR(ctx context.Context, request *kms.SignCSRRequest) (resp *kms.SignCSRResponse, err error) {

	if err = p.loadSigner(request.Name); err != nil {
		return
	}
	resp = &kms.SignCSRResponse{
		Name: request.Name,
	}

	return
}

func NewP11(config *crypto11.Config, ks keystore.KeyStore, wrappedIntKek []byte, createKey bool) (p *P11, err error) {

	p = &P11{
		config:     config,
		autoCreate: createKey,
		store:      ks,
		encryptors: map[string]gose.JweEncryptor{},
		decryptors: map[string]gose.JweDecryptor{},
		signers:    map[string]gose.SigningKey{},
		aeGen:      &gose.AuthenticatedEncryptionKeyGenerator{},
		rsGen:      &gose.RsaSigningKeyGenerator{},
		rkdGen:     &gose.RsaKeyDecryptionKeyGenerator{},
		esGen:      &gose.ECDSASigningKeyGenerator{},
		overwrite:  true,
	}
	// Bootstrap the Pkcs11 device or die
	if p.ctx, err = crypto11.Configure(p.config); err != nil {
		logrus.Error(err)
		return
	}

	// Bootstrap PKCS11 KEK and Root KeyPair
	err = p.bootstrap(wrappedIntKek)

	return
}

//Close the key manager
func (p *P11) Close() (err error) {

	err = p.ctx.Close()

	return
}

func (p *P11) CreateCryptoKey(ctx context.Context, request *kms.CreateCryptoKeyRequest) (key *kms.CryptoKey, err error) {
	key = request.CryptoKey
	if key == nil {
		err = status.Errorf(codes.InvalidArgument, "no crypto key provided")
		return
	}

	var jwk jose.Jwk
	if jwk, err = p.createCryptoKey(key); err != nil {
		return
	}

	if err = p.store.Store(request.CryptoKey.Name, jwk, p.overwrite); err != nil {
		return
	}
	return key, err
}

// Symmetric Encryption....
func (p *P11) Decrypt(ctx context.Context, req *kms.DecryptRequest) (resp *kms.DecryptResponse, err error) {
	if err = p.loadCryptoKey(req.Name); err != nil {
		return
	}
	var out, oaad []byte
	if out, oaad, err = p.decryptors[req.Name].Decrypt(string(req.Ciphertext)); err != nil {
		return
	}
	resp = &kms.DecryptResponse{
		Plaintext: out,
	}
	if !reflect.DeepEqual(oaad, req.AdditionalAuthenticatedData) {
		err = status.Error(codes.InvalidArgument, "Provided AAD does not match decrypted AAD")
		return
	}
	return
}

func (p *P11) Encrypt(ctx context.Context, req *kms.EncryptRequest) (resp *kms.EncryptResponse, err error) {

	if err = p.loadCryptoKey(req.Name); err != nil {
		return
	}
	var out string
	if out, err = p.encryptors[req.Name].Encrypt(req.Plaintext, req.AdditionalAuthenticatedData); err != nil {
		return
	}
	resp = &kms.EncryptResponse{
		Ciphertext: []byte(out),
	}
	return
}

func (p *P11) GetPublicKey(ctx context.Context, request *kms.GetPublicKeyRequest) (resp *kms.PublicKey, err error) {
	pp := &pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   nil,
	}
	resp = &kms.PublicKey{
		Pem:       string(pem.EncodeToMemory(pp)),
		Algorithm: kms.CryptoKeyAlgorithm_RSA_SIGN_PSS_4096_SHA512,
	}
	return
}

func (s *P11) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	var h interface{}
	var err error
	h, err = handler(ctx, req)
	return h, err
}

func (p *P11) bootstrap(wrappedIntKekBytes []byte) (err error) {

	if err = p.genOrLoadRootKek(); err != nil {
		return
	}

	if err = p.genCA(); err != nil {
		return
	}

	return
}

func (p *P11) createCryptoKey(key *kms.CryptoKey) (jwk jose.Jwk, err error) {

	switch key.Purpose {
	case kms.CryptoKey_CRYPTO_KEY_PURPOSE_UNSPECIFIED:
		err = status.Error(codes.InvalidArgument, "invalid key purpose")
		return
	case kms.CryptoKey_ASYMMETRIC_SIGN:
		// Create an RSA in the HSM

		var sk gose.SigningKey
		if sk, err = p.rsGen.Generate(jose.AlgPS512, 4096, utils.SigningKeyOperations); err != nil {
			return
		}

		if jwk, err = sk.Jwk(); err != nil {
			return
		}

	case kms.CryptoKey_ENCRYPT_DECRYPT:
		if _, jwk, err = p.aeGen.Generate(jose.AlgA256GCM, utils.AuthenticatedEncryptedKeyOperations); err != nil {
			return
		}
	case kms.CryptoKey_ASYMMETRIC_DECRYPT:
		err = status.Error(codes.InvalidArgument, "unsupported key purpose")
		return

	default:
		err = status.Error(codes.InvalidArgument, "unsupported key purpose")
		return
	}

	return
}
func (p *P11) genCA() (err error) {

	if err = p.genOrLoadRootCA(); err != nil {
		return
	}

	if err = p.genOrLoadIntCA(); err != nil {
		return
	}

	return

}

// Generate the root CA key, self-sign it, and store it in the token
func (p *P11) genOrLoadIntCA() (err error) {
	var signer crypto11.Signer
	if signer, err = p.ctx.FindKeyPair([]byte(wellKnownRootKeyPair), []byte(labelKEK)); err != nil {
		return
	}
	if signer == nil {
		// need to generate the KeK for sure now...
		if p.autoCreate {
			if signer, err = p.ctx.GenerateRSAKeyPairWithLabel([]byte(wellKnownRootKEK), []byte(labelKEK), 4096); err != nil {
				return
			}
		}
	}
	p.pubKey = signer.Public()

	// Load the Root Certificate from the PKCS11 device
	p.rootCert, err = p.ctx.FindCertificate([]byte(wellKnownCertificate), []byte(labelIntCA), nil)

	// Compute the validity range
	var notBefore = time.Now()

	var notAfter = notBefore.Add(time.Duration(20) * 365 * 24 * time.Hour)
	templateCert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: labelIntCA,
			Country:    []string{"US"},
			Province:   []string{"Oregon"},
			Locality:   []string{"Portland"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SerialNumber:          intCASerial,
		PublicKey:             signer.Public(),
		SignatureAlgorithm:    x509.SHA512WithRSAPSS,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}

	var rng io.Reader
	if rng, err = p.ctx.NewRandomReader(); err != nil {
		return
	}
	var cert []byte
	if cert, err = x509.CreateCertificate(rng, templateCert, templateCert, p.pubKey, signer); err != nil {
		return
	}
	var rootCert *x509.Certificate
	if rootCert, err = x509.ParseCertificate(cert); err != nil {
		return
	}

	if err = p.ctx.ImportCertificateWithLabel([]byte(wellKnownCertificate), []byte(labelIntCA), rootCert); err != nil {
		return
	}
	return
}

func (p *P11) genOrLoadRootKek() (err error) {
	// load/create enc/decrypter for KEK
	var sk *crypto11.SecretKey
	if sk, err = p.ctx.FindKey([]byte(wellKnownRootKEK), []byte(labelKEK)); err != nil {
		return
	}
	if sk == nil {
		// need to generate the KeK for sure now...
		if p.autoCreate {

			if sk, err = p.ctx.GenerateSecretKeyWithLabel([]byte(wellKnownRootKEK), []byte(labelKEK), 256, crypto11.CipherAES); err != nil {
				return
			}
		} else {
			err = status.Error(codes.InvalidArgument, "Root KEK is not found, not creating")
			return
		}
	}
	var aead cipher.AEAD
	if aead, err = sk.NewGCM(); err != nil {
		return
	}

	var rng io.Reader
	if rng, err = p.ctx.NewRandomReader(); err != nil {
		return
	}
	// get a AEAD handle with the RootKek for 1 of it's 2 jobs :)
	var gaead gose.AuthenticatedEncryptionKey
	if gaead, err = gose.NewAesGcmCryptor(aead, rng, wellKnownRootKEK, jose.AlgA256GCM, []jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt}); err != nil {
		return
	}

	// Load or Gen the IntKek
	var wrappedIntKekBytes []byte
	if wrappedIntKekBytes, err = p.store.RetrieveStoreIntKek(); err != nil {
		if err == utils.ErrNoSuchKey {
			var _ gose.AuthenticatedEncryptionKey
			if _, p.intKek, err = p.aeGen.Generate(jose.AlgA256GCM, utils.AuthenticatedEncryptedKeyOperations); err != nil {
				return
			}
			if err = p.store.LoadIntKek(p.intKek); err != nil {
				return
			}
			//store it...
			var intKekString string
			if intKekString, err = gose.JwkToString(p.intKek); err != nil {
				return
			}
			var wrappedIntKekString string
			if wrappedIntKekString, err = gose.NewJweDirectEncryptorImpl(gaead).Encrypt([]byte(intKekString), intKekAAD); err != nil {
				return
			}
			wrappedIntKekBytes = []byte(wrappedIntKekString)
			if err = p.store.StoreIntKek(wrappedIntKekBytes); err != nil {
				return
			}
		}
	} else {
		// let's unwrap and load
		var unwrappedIntKekBytes, aad []byte
		if unwrappedIntKekBytes, aad, err = gose.NewJweDirectDecryptorImpl([]gose.AuthenticatedEncryptionKey{gaead}).Decrypt(string(wrappedIntKekBytes)); err != nil {
			return
		}
		if !reflect.DeepEqual(aad, intKekAAD) {
			err = status.Error(codes.Internal, "AAD's dont match.  Crypto failure")
			return
		}
		if p.intKek, err = gose.LoadJwk(bytes.NewReader(unwrappedIntKekBytes), utils.AuthenticatedEncryptedKeyOperations); err != nil {
			return
		}
		if err = p.store.LoadIntKek(p.intKek); err != nil {
			return
		}
	}

	return
}

// Generate the root CA key, self-sign it, and store it in the token
func (p *P11) genOrLoadRootCA() (err error) {

	// check if CA already exists in the PKCS11 device

	if p.rootCert, err = p.ctx.FindCertificate([]byte(wellKnownCertificate), []byte(labelRootCA), rootCASerial); err != nil {
		logrus.Fatal(err)
		return
	}

	if p.rootCert == nil {
		// assumed we ahve been here before and we are healthy so far..

	}
	var signer crypto11.Signer
	if signer, err = p.ctx.FindKeyPair([]byte(wellKnownRootKeyPair), []byte(labelKEK)); err != nil {
		return
	}
	if signer == nil {
		// need to generate the KeK for sure now...
		if p.autoCreate {
			if signer, err = p.ctx.GenerateRSAKeyPairWithLabel([]byte(wellKnownRootKEK), []byte(labelKEK), 4096); err != nil {
				return
			}
		}
	}

	p.pubKey = signer.Public()

	// Compute the validity range
	var notBefore = time.Now()
	var notAfter = notBefore.Add(time.Duration(20) * 365 * 24 * time.Hour)
	templateCert := &x509.Certificate{
		Subject: pkix.Name{
			CommonName: labelRootCA,
			Country:    []string{"US"},
			Province:   []string{"Oregon"},
			Locality:   []string{"Portland"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SerialNumber:          rootCASerial,
		PublicKey:             signer.Public(),
		SignatureAlgorithm:    x509.SHA512WithRSAPSS,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
	}

	var rng io.Reader
	if rng, err = p.ctx.NewRandomReader(); err != nil {
		return
	}
	var cert []byte
	if cert, err = x509.CreateCertificate(rng, templateCert, templateCert, p.pubKey, signer); err != nil {
		return
	}
	var rootCert *x509.Certificate
	if rootCert, err = x509.ParseCertificate(cert); err != nil {
		return
	}

	if err = p.ctx.ImportCertificateWithLabel([]byte(wellKnownCertificate), []byte(labelRootCA), rootCert); err != nil {
		return
	}
	return
}

func (p *P11) loadCryptoKey(name string) (err error) {
	var encryptor gose.JweEncryptor
	var decryptor gose.JweDecryptor
	var jwk jose.Jwk
	if encryptor = p.encryptors[name]; encryptor == nil {
		if jwk, err = p.store.Retrieve(name, utils.AuthenticatedEncryptedKeyOperations); err != nil {
			return
		}
		var aead gose.AuthenticatedEncryptionKey
		if aead, err = gose.NewAesGcmCryptorFromJwk(jwk, utils.AuthenticatedEncryptedKeyOperations); err != nil {
			return
		}
		p.encryptors[name] = gose.NewJweDirectEncryptorImpl(aead)

	}
	if decryptor = p.decryptors[name]; decryptor == nil {
		if jwk, err = p.store.Retrieve(name, utils.AuthenticatedEncryptedKeyOperations); err != nil {
			return
		}
		var aead gose.AuthenticatedEncryptionKey
		if aead, err = gose.NewAesGcmCryptorFromJwk(jwk, utils.AuthenticatedEncryptedKeyOperations); err != nil {
			return
		}
		p.decryptors[name] = gose.NewJweDirectDecryptorImpl([]gose.AuthenticatedEncryptionKey{aead})

	}
	return
}

func (p *P11) loadSigner(name string) (err error) {
	var signer gose.SigningKey
	var jwk jose.Jwk
	if signer = p.signers[name]; signer == nil {
		if jwk, err = p.store.Retrieve(name, utils.SigningKeyOperations); err != nil {
			return
		}
		if signer, err = gose.NewSigningKey(jwk, utils.SigningKeyOperations); err != nil {
			return
		}
		p.signers[name] = signer

	}

	return
}

// SANRequest holds names to put in the SubjectAltName field. See RFC5280 4.2.1.6.
type SANRequest struct {
	// dNSName names
	DNSNames []string

	// iPAddress names
	IPs []net.IP

	// rfc822Name names
	Emails []string

	// uniformResourceIdentifier names
	URIs []string
}

type keyGenerationParameters struct {
	size   int
	cipher *crypto11.SymmetricCipher
}
