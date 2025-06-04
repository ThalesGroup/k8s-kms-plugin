/*
 * Copyright 2025 Thales Group
 * SPDX-License-Identifier: MIT
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package providers

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"reflect"

	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/gose"
	"github.com/ThalesGroup/gose/jose"
	"github.com/ThalesGroup/k8s-kms-plugin/apis/istio/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/sirupsen/logrus"
)

var (
	defaultKEKlabel    = []byte("k8s-kms-plugin-kek")
	defaultRootCAlabel = []byte("k8s-kms-plugin-root-ca")
)

func (p *P11) AuthenticatedEncrypt(ctx context.Context, request *istio.AuthenticatedEncryptRequest) (resp *istio.AuthenticatedEncryptResponse, err error) {
	var kekDecryptor gose.JweDecryptor
	if kekDecryptor = p.decryptors[string(request.KekKid)]; nil == kekDecryptor {
		if _, kekDecryptor, err = p.loadKEKbyID(p.ctx, request.KekKid, defaultKEKlabel); nil != err {
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

	var dekAead gose.AeadEncryptionKey
	if dekAead, err = gose.NewAesGcmCryptorFromJwk(loadedDek, []jose.KeyOps{jose.KeyOpsEncrypt}); nil != err {
		return
	}

	var dekAeadEncryptor gose.JweEncryptor
	dekAeadEncryptor = gose.NewJweDirectEncryptorAead(dekAead, false)

	resp = &istio.AuthenticatedEncryptResponse{}
	var ct string
	if ct, err = dekAeadEncryptor.Encrypt(request.Plaintext, request.Aad); err != nil {
		return
	}
	resp.Ciphertext = []byte(ct)
	return
}

func (p *P11) AuthenticatedDecrypt(ctx context.Context, request *istio.AuthenticatedDecryptRequest) (resp *istio.AuthenticatedDecryptResponse, err error) {
	var kekDecryptor gose.JweDecryptor
	if kekDecryptor = p.decryptors[string(request.KekKid)]; kekDecryptor == nil {
		if _, kekDecryptor, err = p.loadKEKbyID(p.ctx, request.KekKid, defaultKEKlabel); err != nil {
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

	var dekAead gose.AeadEncryptionKey
	if dekAead, err = gose.NewAesGcmCryptorFromJwk(loadedDek, []jose.KeyOps{jose.KeyOpsDecrypt}); nil != err {
		return
	}

	var dekAeadDecryptor gose.JweDecryptor
	dekAeadDecryptor = gose.NewJweDirectDecryptorAeadImpl([]gose.AeadEncryptionKey{dekAead})

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

// generateSKey generates a Symmetric Key (SKey) using the provided
// cryptographic context, kind, and size. The function checks if the
// specified algorithm is supported and, if so, generates a secret key
// with the associated parameters. It returns the generated AEAD
// encryption key or an error if the operation fails.
//
// for Istio: generateSKey is only used by GenerateSKey.
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

// GenerateDEK a 256 bit AES DEK Key , Wrapped via JWE with the PKCS11 base KEK
func (p *P11) GenerateDEK(ctx context.Context, request *istio.GenerateDEKRequest) (resp *istio.GenerateDEKResponse, err error) {
	if request == nil {
		logrus.Error(err)
		return nil, status.Error(codes.InvalidArgument, "no request sent")
	}
	var encryptor gose.JweEncryptor
	if encryptor = p.encryptors[string(request.KekKid)]; encryptor == nil {
		if encryptor, _, err = p.loadKEKbyID(p.ctx, []byte(request.KekKid), []byte(defaultKEKlabel)); err != nil {
			return
		}
	}
	var dekBlob []byte

	// GenerateDEK from p11.go
	if dekBlob, err = GenerateDEK(p.ctx, encryptor); err != nil {
		logrus.Error(err)
		return
	}
	resp = &istio.GenerateDEKResponse{
		EncryptedDekBlob: dekBlob,
	}
	return
}

// for Istio: GenerateKEK a 256 bit AES KEK Key that resides in the Pkcs11 device
func (p *P11) GenerateKEK(ctx context.Context, request *istio.GenerateKEKRequest) (resp *istio.GenerateKEKResponse, err error) {
	if request.KekKid == nil {
		request.KekKid, err = p.genKekKid()
		if err != nil {
			logrus.Error(err)
			return
		}
	}

	// GenerateKEK from p11.go
	_, err = GenerateKEK(p.ctx, request.KekKid, []byte(defaultKEKlabel), jose.AlgA256GCM)
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
		if _, decryptor, err = p.loadKEKbyID(p.ctx, request.KekKid, []byte(defaultKEKlabel)); err != nil {
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

	var aead gose.AeadEncryptionKey
	if aead, err = gose.NewAesGcmCryptorFromJwk(jwk, kekKeyOps); err != nil {
		return
	}
	dekEncryptor := gose.NewJweDirectEncryptorAead(aead, false)

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
		if _, decryptor, err = p.loadKEKbyID(p.ctx, request.KekKid, []byte(defaultKEKlabel)); err != nil {
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

	var aead gose.AeadEncryptionKey
	if aead, err = gose.NewAesGcmCryptorFromJwk(jwk, kekKeyOps); err != nil {
		return
	}
	dekDecryptor := gose.NewJweDirectDecryptorAeadImpl([]gose.AeadEncryptionKey{aead})
	resp = &istio.LoadSKeyResponse{
		PlaintextSkey: nil,
	}

	// Return the clear sKey in PEM format or bust
	if resp.PlaintextSkey, _, err = dekDecryptor.Decrypt(string(request.EncryptedSkeyBlob)); err != nil {
		return
	}

	return
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

	if len(request.Certificates) != 0 {
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
				if len(parsedChains) != 1 {
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
