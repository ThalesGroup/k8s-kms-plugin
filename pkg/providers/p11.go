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
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/thalescpl-io/k8s-kms-plugin/apis/istio/v1"
	k8sv1 "github.com/thalescpl-io/k8s-kms-plugin/apis/k8s/v1beta1"
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
		logrus.Errorf("E1: %v", err)
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
		logrus.Errorf("E2: %v", err)
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

func loadKEKbyID(ctx *crypto11.Context, kekIdentity, label []byte) (encryptor gose.JweEncryptor, decryptor gose.JweDecryptor, err error) {

	var rng io.Reader
	var aek gose.AuthenticatedEncryptionKey

	if rng, err = ctx.NewRandomReader(); err != nil {
		return
	}
	// get the HSM Key
	var handle *crypto11.SecretKey
	if handle, err = ctx.FindKey(kekIdentity, label); err != nil {
		return
	}
	if handle == nil {
		err = fmt.Errorf("tried to find key with identity %v, label %v, but no such key", kekIdentity, label)
		return
	}
	var aead cipher.AEAD
	if aead, err = handle.NewGCM(); err != nil {
		return
	}
	if aek, err = gose.NewAesGcmCryptor(aead, rng, string(kekIdentity), jose.AlgA256GCM, kekKeyOps); err != nil {
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
	k8sKekLabel string
}

func NewP11(config *crypto11.Config, createKey bool, k8sKekLabel string) (p *P11, err error) {

	p = &P11{
		config:    config,
		createKey: createKey,
		k8sKekLabel: k8sKekLabel,
	}
	// Bootstrap the Pkcs11 device or die
	if p.ctx, err = crypto11.Configure(p.config); err != nil {
		return
	}

	allKeys, _ := p.ctx.FindAllKeys()
	logrus.Printf("allKeys: %v\n", allKeys)
	kekKey, _ := p.ctx.FindKey(nil, []byte(p.k8sKekLabel))
	logrus.Printf("%v", kekKey)
	a, _ := p.ctx.GetAttribute(kekKey, crypto11.CkaId)
	logrus.Printf("a: %v", a)

	if p.createKey {
		// Check if the default kek exists. If not, create it
		var foundKekKey *crypto11.SecretKey
		if foundKekKey, err = p.ctx.FindKey(nil, []byte(p.k8sKekLabel)); nil != err {
			return
		}
		if nil == foundKekKey {
			var newKekUUID uuid.UUID
			if newKekUUID, err = uuid.NewRandom(); nil != err {
				return
			}
			var uuidBytes []byte
			if uuidBytes, err = newKekUUID.MarshalText(); nil != err {
				return
			}
			if _, err = generateKEK(p.ctx, uuidBytes, []byte(p.k8sKekLabel), jose.AlgA256GCM); nil != err {
				return
			}
			logrus.Infof("Created new Kek")

			allKeys, _ := p.ctx.FindAllKeys()
			logrus.Printf("allKeys: %v\n", allKeys)
		} else {
			logrus.Infof("Kek already exists (with label %v)", p.k8sKekLabel)
		}

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
func (p *P11) Decrypt(ctx context.Context, req *k8sv1.DecryptRequest) (resp *k8sv1.DecryptResponse, err error) {
	var decryptor gose.JweDecryptor

	var keyLabel []byte
	var requestId []byte
	if req.KeyId != "" {
		requestId = []byte(req.KeyId)
	} else {
		requestId = nil
		keyLabel = []byte(p.k8sKekLabel)
	}

	if decryptor = p.decryptors[req.KeyId]; decryptor == nil {
		if _, decryptor, err = loadKEKbyID(p.ctx, requestId, keyLabel); err != nil {
			return
		}
	}

	var out []byte
	if out, _, err = decryptor.Decrypt(string(req.Cipher)); err != nil {
		return
	}
	resp = &k8sv1.DecryptResponse{
		Plain: out,
	}
	return
}

func (p *P11) Encrypt(ctx context.Context, req *k8sv1.EncryptRequest) (resp *k8sv1.EncryptResponse, err error) {
	var encryptor gose.JweEncryptor

	var keyLabel []byte
	var requestId []byte
	if req.KeyId != "" {
		requestId = []byte(req.KeyId)
	} else {
		requestId = nil
		keyLabel = []byte(p.k8sKekLabel)
	}

	if encryptor = p.encryptors[req.KeyId]; encryptor == nil {
		if encryptor, _, err = loadKEKbyID(p.ctx, requestId, keyLabel); err != nil {
			logrus.Infof("Encrypt err: %v", err.Error())
			return
		}
	}

	var out string
	if out, err = encryptor.Encrypt(req.Plain, nil); err != nil {
		return
	}
	resp = &k8sv1.EncryptResponse{
		Cipher: []byte(out),
	}
	return
}

// GenerateDEK a 256 bit AES DEK Key , Wrapped via JWE with the PKCS11 base KEK
func (p *P11) GenerateDEK(ctx context.Context, request *istio.GenerateDEKRequest) (resp *istio.GenerateDEKResponse, err error) {
	if request == nil {
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
			return
		}
	}

	_, err = generateKEK(p.ctx, request.KekKid, []byte(defaultKEKlabel), jose.AlgA256GCM)
	if err != nil {
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

func (s *P11) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {

	switch req.(type) {
	case *k8sv1.VersionRequest:
	case *k8sv1.EncryptRequest:
		{
            // For now, we look up our existing k8s kek key, pull the attribute and set this to the key id
		    // This is duplicated below and could also be saved at the time of creation
			kekKey, _ := s.ctx.FindKey(nil, []byte(s.k8sKekLabel))
			var a *crypto11.Attribute
			if a, err = s.ctx.GetAttribute(kekKey, crypto11.CkaId); nil != err {
                return
			}

			(req).(*k8sv1.EncryptRequest).KeyId = string(a.Value)
		}
	case *k8sv1.DecryptRequest:
		{

			kekKey, _ := s.ctx.FindKey(nil, []byte(s.k8sKekLabel))
			var a *crypto11.Attribute
			if a, err = s.ctx.GetAttribute(kekKey, crypto11.CkaId); nil != err {
				return
			}

			(req).(*k8sv1.DecryptRequest).KeyId = string(a.Value)
		}
	default:
        err = fmt.Errorf("unhandled request type")
        return nil, err
	}

	resp, err = handler(ctx, req)
	return resp, err
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

	var parsedTargetCert *x509.Certificate

	/*
		Regardless of the length of the supplied chain, we need to try and turn this into a valid chain, with the head of
		the chain being something we pull from the HSM
		The length of the chain must be at least 2 when we're done
	*/

	var retrievedRootCert *x509.Certificate

	var verifyOpts = x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
	}

	if nil == p.cid {
		err = fmt.Errorf("no loaded CA cert for verification")
		return
	}

	if 0 != len(request.Certificates) {
		parsedTargetCert, err = x509.ParseCertificate(request.Certificates[len(request.Certificates)-1])
		if nil != err {
			return
		}
	} else {
		err = fmt.Errorf("no certificates supplied")
		return
	}

	switch len(request.Certificates) {
	case 1:
		// Try to find a workable CA cert in the HSM
		if retrievedRootCert, err = p.ctx.FindCertificate(p.cid, nil, nil); nil != err {
			return
		}
		verifyOpts.Roots.AddCert(retrievedRootCert)
	default:
		{

			/*
			   We try to verify the chain as supplied - if this verifies we then look at the returned chain root and see
			   if matches our existing root cert
			*/
			var parsedFirstCert *x509.Certificate

			if parsedFirstCert, err = x509.ParseCertificate(request.Certificates[0]); nil != err {
				// TODO - RF: unify
				// try PEM instead
				var pemFirstCertBlock *pem.Block
				pemFirstCertBlock, _ = pem.Decode(request.Certificates[0])
				parsedFirstCert, err = x509.ParseCertificate(pemFirstCertBlock.Bytes)
				if nil != err {
					return
				}
			}

			var preliminaryVerifyOpts = x509.VerifyOptions{
				Roots:         x509.NewCertPool(),
				Intermediates: x509.NewCertPool(),
			}
			preliminaryVerifyOpts.Roots.AddCert(parsedFirstCert)

			// And add any supplied intermediate certs
			for i := 1; i < len(request.Certificates)-1; i++ {

				var parsedAdditionalIntermediateCert *x509.Certificate
				if parsedAdditionalIntermediateCert, err = x509.ParseCertificate(request.Certificates[i]); nil != err {
					logrus.Errorf("failed to parse additional intermediate certificate")
					return
				}
				preliminaryVerifyOpts.Intermediates.AddCert(parsedAdditionalIntermediateCert)
			}

			var parsedChains [][]*x509.Certificate
			if parsedChains, err = parsedTargetCert.Verify(preliminaryVerifyOpts); nil != err {
				logrus.Errorf("supplied chain does not verify")
				return
			} else {

				/*
					Here we examine the verified chains, as yet ignoring our CA certs.
					If the verified chain root matches our CA cert, all is good

					If not, we treat it as an intermediate cert and proceed to a verification which takes this into account

					For now, we should only have a single chain, so crash out if there's more than one
				*/
				if 1 != len(parsedChains) {
					err = fmt.Errorf("unhandled: multiple verification chains")
					return
				}

				// Then compare the supplied CA cert against the one currently in the HSM to ensure they're the same
				if retrievedRootCert, err = p.ctx.FindCertificate(p.cid, nil, nil); nil != err {
					return
				}

				/*
					Here, if the preliminary verification root matches our HSM-stored root, we add to verifyOpts.Roots
					Else, we haven't seen this before, so add to verifyOpts.Intermediates
				*/
				if !retrievedRootCert.Equal(parsedChains[0][len(parsedChains[0])-1]) {
					verifyOpts.Intermediates.AddCert(parsedChains[0][len(parsedChains[0])-1])
					// And add our HSM-sourced CA cert as a root
					verifyOpts.Roots.AddCert(retrievedRootCert)
				} else {
					verifyOpts.Roots.AddCert(parsedChains[0][len(parsedChains[0])-1])
				}

			}

			/*
				And add any more possible intermediates (these are treated as being any certificates which are not the
				first or the last)
			*/
			for i := 1; i < len(request.Certificates)-1; i++ {

				var parsedAdditionalIntermediateCert *x509.Certificate
				if parsedAdditionalIntermediateCert, err = x509.ParseCertificate(request.Certificates[i]); nil != err {
					logrus.Errorf("failed to parse additional intermediate certificate")
					return
				}
				verifyOpts.Intermediates.AddCert(parsedAdditionalIntermediateCert)
			}

		}
	}

	resp = &istio.VerifyCertChainResponse{}

	_, verifyErr := parsedTargetCert.Verify(verifyOpts)
	if nil != verifyErr {
		err = verifyErr
	} else {
		resp.SuccessfulVerification = true
	}

	return

}

func (p *P11) Version(ctx context.Context, request *k8sv1.VersionRequest) (versionResponse *k8sv1.VersionResponse, err error) {
	fmt.Printf("version called\n")
	versionResponse = &k8sv1.VersionResponse{
		Version:        "v1beta1",
		RuntimeName:    "Thales k8s KMS plugin",
		RuntimeVersion: "v0.5.0",
	}
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
