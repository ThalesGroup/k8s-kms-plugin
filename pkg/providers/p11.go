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
	"context"
	"crypto"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/ThalesGroup/crypto11"
	"github.com/ThalesGroup/gose"
	"github.com/ThalesGroup/gose/hsm"
	"github.com/ThalesGroup/gose/jose"

	"github.com/google/uuid"
	"github.com/miekg/pkcs11"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	k8skmsv2 "k8s.io/kms/apis/v2"
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

// GenerateDEK generates a Data Encryption Key (DEK) and encrypts it using
// the provided JWE encryptor. It first creates a random 32-byte symmetric
// key, converts it to a JWK format, and then encrypts the JWK using the
// encryptor. The resulting encrypted DEK is returned as a byte slice.
// Any errors encountered during random number generation, key conversion,
// or encryption are returned.
//
// for Istio: GenerateDEK is only used by istio.go:GenerateDEK and integration testing.
// TODO: decide if this Istio related method should be separated from the KMS v2 plugin
func GenerateDEK(ctx11 *crypto11.Context, encryptor gose.JweEncryptor) (encryptedKeyBlob []byte, err error) {

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
	if dekStr, err = json.Marshal(dekJWK); err != nil {
		logrus.WithError(err).Error("generateDEK: failed to marshal DEK JWK")
		return
	}
	// using the AES key as it's payload
	var encryptedString string
	if encryptedString, err = encryptor.Encrypt(dekStr, nil); err != nil {
		logrus.Error(err)
		return
	}
	encryptedKeyBlob = []byte(encryptedString)

	return
}

// GenerateKEK generates a Key Encryption Key (KEK) using the provided
// cryptographic context, identity, label, and algorithm. The function
// checks if the specified algorithm is supported and, if so, generates
// a secret key with the associated parameters. It returns the generated
// AEAD encryption key or an error if the operation fails.
//
// for Istio: GenerateKEK is only used by istio.go:GenerateKEK and integration testing.
// TODO: decide if this Istio related method should be separated from the KMS v2 plugin
func GenerateKEK(ctx *crypto11.Context, identity, label []byte, alg jose.Alg) (key gose.AeadEncryptionKey, err error) {
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

// IsPKCS11AuthenticationError returns true
// if further attempts to log in will risk causing the
// device to be locked.
func IsPKCS11AuthenticationError(err error) bool {
	if err == nil {
		return false
	}

	pkErr, ok := errors.Unwrap(err).(pkcs11.Error)
	if !ok {
		return false
	}

	switch pkErr {
	case pkcs11.CKR_PIN_INCORRECT:
		return true
	default:
		return false
	}
}

// P11 is a struct representing a P11 provider, which handles encryption and decryption
// operations using a Hardware Security Module (HSM). It manages keys, contexts, and
// encryption algorithms necessary for secure cryptographic operations within the KMS plugin.
//
// Active Fields: the actual keys being used in StatusResponse and EncryptResponse.
//
// KEK Key Rotation Fields:,old keys used for Decryption of old ciphertext during a key rotation.
// See: https://kubernetes.io/docs/tasks/administer-cluster/kms-provider/#developing-a-kms-plugin-gRPC-server-notes-kms-v2
//
// Istio Related Fields:
// - cid: Certificate Identifier used in Istio operations.
type P11 struct {
	// Starting with [KMS v0.34.0](https://github.com/kubernetes/kms/tree/v0.34.0/apis/v2), the KMS maintainers stoped to use https://github.com/gogo/protobuf to generate protobuf files, as it is deprecated.
	// KMS v0.34.0 and later uses official https://github.com/protocolbuffers/protobuf-go. This demands that the gRPC server embeds UnimplementedKeyManagementServiceServer to automatically satisfy method mustEmbedUnimplementedKeyManagementServiceServer()
	k8skmsv2.UnimplementedKeyManagementServiceServer

	// active KEK parameters
	createKey    bool                         // Indicates whether the k8s-kms-plugin should create a new key. TODO: explain the use case of when should the k8s-kms-plugin create the key, or create a new cobra command
	config       *crypto11.Config             // Active configuration for the crypto11 library
	ctx          *crypto11.Context            // Active cryptographic context for key operations
	encryptors   map[string]gose.JweEncryptor // Active Map of JWE encryptors used for encryption operations
	decryptors   map[string]gose.JweDecryptor // Active Map of JWE decryptors used for decryption operations
	kekCkaId     []byte                       // Active Key Encryption Key KEK Identifier & CKA_ID
	kekCkaLabel  string                       // Active KEK CKA_LABEL utf8
	hmacCkaId    []byte                       // Active HMAC key CKA_ID for AES-CBC + HMAC
	hmacCkaLabel string                       // Active HMAC key CKA_LABEL utf8 for AES-CBC + HMAC
	algorithm    jose.Alg                     // The active cryptographic algorithm being used

	// Istio related fields
	cid []byte // Certificate Identifier

	// KEK Key rotation feature for KMS v2
	oldConfig *crypto11.Config  // for key rotation
	oldCtx    *crypto11.Context // for key rotation
	// no encryptors since the old KEK keys are used for decryption only
	oldDecryptors   map[string]gose.JweDecryptor // for key rotation
	oldKekCkaId     []byte                       // Key Encryption Key KEK Identifier & CKA_ID of old KEK being rotated
	oldKekCkaLabel  string                       // CKA_LABEL utf8 of old KEK being rotated
	oldHmacCkaId    []byte                       // CKA_ID of old HMAC key being rotated
	oldHmacCkaLabel string                       // CKA_LABEL utf8 of old HMAC key being rotated
	oldAlgorithm    jose.Alg                     // algorithm of old KEK being rotated
}

// NewP11 creates a new P11 instance.
//
// The P11 instance is configured with the given crypto11.Config.
//
// The createKey argument is a boolean that indicates whether the P11 instance
// should create a default key with the given label. TODO: explain the use case
// when this would be needed, eventualy move this to a new command.
//
// The kekkeyid argument is the Key Encryption Key (KEK) identifier.
// This is the PKCS #11 CKA_ID.
//
// The k8sKekLabel argument is the label of the default key.
// This is the PKCS #11 CKA_LABEL.
//
// The hmacKeyLabel argument is the label of the HMAC key, for AES-CBC + HMAC.
//
// The algorithm argument specify which algorithm to use, symmetric or
// asymmetric.
//
// The function returns a pointer to the P11 instance and an error value. If
// the error value is not nil, the P11 instance is not valid and should not
// be used.
func NewP11(
	// active KEK parameters
	config *crypto11.Config,
	createKey bool,
	kekkeyid string,
	k8sKekLabel string,
	hmacKeyLabel string,
	hmacCkaId string,
	algorithm jose.Alg,

	// key rotation
	isKeyRotation bool,
	oldConfig *crypto11.Config,
	oldKekkeyid string,
	oldKekCkaLabel string,
	oldHmacKeyLabel string,
	oldHmacCkaId string,
	oldAlgorithm jose.Alg,
) (p *P11, err error) {
	p = &P11{
		// active KEK parameters
		config:    config,
		createKey: createKey,
		algorithm: algorithm,

		// only in case of key rotation
		oldConfig:    oldConfig,
		oldAlgorithm: oldAlgorithm,
	}

	// Bootstrap the active Pkcs11 device or die
	if p.ctx, err = crypto11.Configure(p.config); err != nil {
		logrus.WithError(err).Error("NewP11: failed to configure the active Pkcs11 device")
		return
	}

	// Bootstrap the key rotation Pkcs11 device or die
	if isKeyRotation {
		if p.oldCtx, err = crypto11.Configure(p.oldConfig); err != nil {
			logrus.WithError(err).Error("NewP11: failed to configure the key rotation Pkcs11 device")
			return
		}
	}

	// Case: Attempt to discover KEK ID (CKA_ID) by Key label (CKA_LABEL)
	// From the CLI's user input perspective, the kekkeyid (CKA_ID) and k8sKekLabel (CKA_LABEL)
	// should be marked as MarkFlagsMutuallyExclusive and MarkFlagsOneRequired.
	// This prevent mismatching the two inputs.
	// From kubernetes KMS v2 point of vue, StatusResponse.KeyId, EncryptResponse.KeyId and
	// EncryptRequest.KeyId should use a unique identifier: pkcs11.CKA_ID is a unique identifier.
	// If the user set the k8sKekLabel flag (CKA_LABEL), then the kekkeyid (CKA_ID) is retrieved by
	// the k8sKekLabel.
	// CKA_ID is mandatory to provide the KEK ID to the status requests from Kubernetes' Status
	// Request, so we need to retrieve it mandatorily from the HSM if provided empty.
	// TODO USE SetKekKeyIdString instead of conversions in the method
	p.kekCkaId, p.kekCkaLabel, err = GetKeyIdAndLabel(p, kekkeyid, k8sKekLabel)
	if err != nil {
		return
	}

	// in case the user provide the CKA_ID or the CKA_LABEL of HMAC key
	if p.algorithm == jose.AlgA256CBC {
		p.hmacCkaId, p.hmacCkaLabel, err = GetKeyIdAndLabel(p, hmacCkaId, hmacKeyLabel)
		if err != nil {
			return
		}
	}

	// key rotation
	if isKeyRotation {
		// in case the user provide the OLD CKA_ID or the OLD CKA_LABEL of OLD HMAC key
		if p.oldAlgorithm == jose.AlgA256CBC {
			if oldHmacCkaId == "" && oldHmacKeyLabel != "" { // get id by label
				// old HMAC
				p.oldHmacCkaLabel = oldHmacKeyLabel

				if p.oldHmacCkaId, err = FindCkaAttrByIdOrLabel(p.oldCtx, p.oldAlgorithm, crypto11.CkaId, nil, []byte(p.oldHmacCkaLabel)); err != nil {
					logrus.WithError(err).Error("NewP11: failed to find HMAC CKA_ID by label")
					return nil, err
				}

			} else if oldHmacCkaId != "" && oldHmacKeyLabel == "" { // get label by id
				p.SetOldHmacKeyIdString(oldHmacCkaId)

				var labelBuf []byte
				if labelBuf, err = FindCkaAttrByIdOrLabel(p.oldCtx, p.oldAlgorithm, crypto11.CkaLabel, p.oldHmacCkaId, nil); err != nil {
					logrus.WithError(err).Error("NewP11: failed to find old HMAC CKA_LABEL by ID")
					return nil, err
				}

				p.oldHmacCkaLabel = string(labelBuf)

			} else if oldHmacCkaId == "" && oldHmacKeyLabel == "" {
				logrus.WithError(err).Errorf("NewP11: oldHmacCkaId and oldHmacKeyLabel are both empty, please provide one of them")
				return nil, fmt.Errorf("NewP11: oldHmacCkaId and oldHmacKeyLabel are both empty, please provide one of them")
			} else {
				logrus.WithError(err).Errorf("NewP11: both oldHmacCkaId and oldHmacKeyLabel are provided, please provide only one")
				return nil, fmt.Errorf("NewP11: both oldHmacCkaId and oldHmacKeyLabel are provided, please provide only one")
			}
		}

		// find old KEK ID with LABEL
		if oldKekkeyid == "" && oldKekCkaLabel != "" {
			logrus.Tracef("NewP11: kek key id (CKA_ID) is empty. Find CKA_ID by CKA_LABEL %s", k8sKekLabel)
			p.oldKekCkaLabel = oldKekCkaLabel

			if p.oldKekCkaId, err = FindCkaAttrByIdOrLabel(p.oldCtx, p.oldAlgorithm, crypto11.CkaId, nil, []byte(p.oldKekCkaLabel)); err != nil {
				logrus.WithError(err).Error("NewP11: failed to find OLD KEK CKA_ID by label")
				return nil, err
			}
		}

		// find old KEK label with ID
		if oldKekkeyid != "" && oldKekCkaLabel == "" {
			logrus.Tracef("NewP11: k8sKekLabel (CKA_LABEL) is empty but kekkeyid (CKA_ID) is not empty. Find CKA_LABEL by CKA_ID %s", oldKekkeyid)
			p.SetOldKekKeyIdString(oldKekkeyid)

			var labelBuf []byte
			if labelBuf, err = FindCkaAttrByIdOrLabel(p.oldCtx, p.oldAlgorithm, crypto11.CkaLabel, p.oldKekCkaId, nil); err != nil {
				logrus.WithError(err).Error("NewP11: failed to find OLD KEK CKA_LABEL by CKA_ID")
				return nil, err
			}
			p.oldKekCkaLabel = string(labelBuf)
		}
	}

	if p.createKey {
		// Check if the default key exists - if not, create it
		var foundDefaultDek *crypto11.SecretKey
		if foundDefaultDek, err = p.ctx.FindKey(p.kekCkaId, p.GetKekCkaLabelByteA()); nil != err {
			return
		}
		if nil == foundDefaultDek {
			var newDekUUID uuid.UUID
			if newDekUUID, err = uuid.NewRandom(); nil != err {
				return
			}
			var uuidBytes []byte
			if uuidBytes, err = newDekUUID.MarshalText(); nil != err {
				return
			}
			if _, err = p.ctx.GenerateSecretKeyWithLabel(uuidBytes, p.GetKekCkaLabelByteA(), 256, crypto11.CipherAES); nil != err {
				return
			}
		}
	}
	return
}

func (p *P11) SetKekKeyIdFromBytes(keyID []byte) error {
	if keyID == nil {
		return fmt.Errorf("keyID cannot be nil")
	}
	p.kekCkaId = keyID
	return nil
}

// SetKekKeyIdString sets the internal CKA_ID from a hex-encoded string.
func (p *P11) SetKekKeyIdString(hexKeyID string) error {
	kid, err := hex.DecodeString(hexKeyID)
	if err != nil {
		return fmt.Errorf("invalid hex KeyID: %w", err)
	}
	p.kekCkaId = kid
	return nil
}

// GetKekKeyIdString returns the Key Encryption Key (KEK)  identifier as a
// hex-encoded string. This identifier is used to uniquely identify the
// encryption key within the PKCS#11 CKA_ID context.
func (p *P11) GetKekKeyIdString() string {
	return hex.EncodeToString(p.kekCkaId)
}

// GetKekCkaLabelByteA returns the KEK's CKA_LABEL as a UTF-8 encoded byte slice.
func (p *P11) GetKekCkaLabelByteA() []byte {
	return []byte(p.kekCkaLabel)
}

// SetHmacKeyIdString sets the internal HMAC Key ID from a hex-encoded string.
func (p *P11) SetHmacKeyIdString(hexHmacKeyID string) error {
	hmacId, err := hex.DecodeString(hexHmacKeyID)
	if err != nil {
		return fmt.Errorf("invalid hex HMAC KeyID: %w", err)
	}
	p.hmacCkaId = hmacId
	return nil
}

// GetHmacKeyIdString returns the HMAC Key ID as a hex-encoded string.
func (p *P11) GetHmacKeyIdString() string {
	return hex.EncodeToString(p.hmacCkaId)
}

// SetHmacKeyIdString sets the internal HMAC Key ID from a hex-encoded string.
func (p *P11) SetOldHmacKeyIdString(hexOldHmacKeyID string) error {
	oldHmacId, err := hex.DecodeString(hexOldHmacKeyID)
	if err != nil {
		return fmt.Errorf("invalid hex HMAC KeyID: %w", err)
	}
	p.oldHmacCkaId = oldHmacId
	return nil
}

// SetKekKeyIdString sets the internal CKA_ID from a hex-encoded string.
func (p *P11) SetOldKekKeyIdString(hexOldKeyID string) error {
	kid, err := hex.DecodeString(hexOldKeyID)
	if err != nil {
		return fmt.Errorf("invalid hex KeyID: %w", err)
	}
	p.oldKekCkaId = kid
	return nil
}

// SetEncryptor sets the gose.JWE Encryptor.
func (p *P11) SetEncryptor(encryptor gose.JweEncryptor) error {
	if encryptor == nil {
		return fmt.Errorf("SetEncryptor: encryptor is nil")
	}
	p.encryptors[p.GetKekKeyIdString()] = encryptor
	return nil
}

// SetEncryptors sets the map of encryptors.
func (p *P11) SetEncryptors(encryptors map[string]gose.JweEncryptor) error {
	if encryptors == nil {
		return fmt.Errorf("SetEncryptors: encryptors is nil")
	}
	p.encryptors = encryptors
	return nil
}

// SetDecryptor sets the gose.JWE Decryptor.
func (p *P11) SetDecryptor(decryptor gose.JweDecryptor) error {
	if decryptor == nil {
		return fmt.Errorf("SetDecryptor: decryptor is nil")
	}
	p.decryptors[p.GetKekKeyIdString()] = decryptor
	return nil
}

// SetDecryptors sets the map of decryptors.
func (p *P11) SetDecryptors(decryptors map[string]gose.JweDecryptor) error {
	if decryptors == nil {
		return fmt.Errorf("SetDecryptors: decryptors is nil")
	}
	p.decryptors = decryptors
	return nil
}

// SetContext sets the PKCS#11 context.
func (p *P11) SetContext(ctx *crypto11.Context) error {
	if ctx == nil {
		return fmt.Errorf("SetContext: ctx is nil")
	}
	p.ctx = ctx
	return nil
}

// SetCID sets the Certificate Identifier used in Istio operations.
func (p *P11) SetCID(cid []byte) error {
	if cid == nil {
		return fmt.Errorf("SetCID: cid is nil")
	}
	p.cid = cid
	return nil
}

// loadKEKbyID loads a Key Encryption Key (KEK) from the HSM for the given
// kekIdentity and label. It returns the loaded KEK as a gose.AeadEncryptionKey,
// a gose.JweEncryptor, and a gose.JweDecryptor. If the key is not found or
// there is an error loading the key, loadKEKbyID returns an error.
//
// TODO: for now this method only support AES GCM symmetric keys as ctx.FindKey
// only supports symmetric keys. This needs to be extended to support other
// algorithms inlcuding asymmetric.
func (p *P11) loadKEKbyID(ctx *crypto11.Context, kekId, kekLabel []byte) (encryptor gose.JweEncryptor, decryptor gose.JweDecryptor, err error) {

	var rng io.Reader
	var aek gose.AeadEncryptionKey

	if rng, err = ctx.NewRandomReader(); err != nil {
		return
	}
	// get the HSM Key
	var handle *crypto11.SecretKey
	if handle, err = ctx.FindKey(kekId, kekLabel); err != nil {
		return
	}
	if handle == nil {
		err = errors.New("no such key")
		logrus.WithError(err).WithFields(logrus.Fields{
			"kekIdentity": string(kekId),
			"label":       string(kekLabel),
		}).Error("load KEK by ID or label failed")
		return
	}
	var aead cipher.AEAD
	if aead, err = handle.NewGCM(); err != nil {
		return
	}
	if aek, err = gose.NewAesGcmCryptor(aead, rng, string(kekId), jose.AlgA256GCM, kekKeyOps); err != nil {
		return
	}
	decryptor = gose.NewJweDirectDecryptorAeadImpl([]gose.AeadEncryptionKey{aek})
	encryptor = gose.NewJweDirectEncryptorAead(aek, p.config.UseGCMIVFromHSM)

	return
}

// Close the key manager
func (p *P11) Close() (err error) {
	p.encryptors = nil
	p.decryptors = nil
	err = p.ctx.Close()

	return
}

// makeAeadKey creates a new AES GCM key encryption key from the given HSM key
// and random reader. It returns a gose.AeadEncryptionKey and an error.
func (p *P11) makeAeadKey(rng io.Reader, kek *crypto11.SecretKey) (aek gose.AeadEncryptionKey, err error) {
	var aead cipher.AEAD
	if aead, err = kek.NewGCM(); err != nil {
		return nil, fmt.Errorf("error while creating new gcm cipher: %v", err)
	}
	if aek, err = gose.NewAesGcmCryptor(aead, rng, p.kekCkaLabel, jose.AlgA256GCM, kekKeyOps); err != nil {
		return nil, fmt.Errorf("error while creating aead key: %v", err)
	}
	return
}

// getIVFromDecryptRequest extracts the Initialization Vector from a KMS v2
// DecryptRequest. It first unmarshalls the JWE from the ciphertext, and
// then returns the InitializationVector from the unmarshalled JWE. If
// there is an error during unmarshalling, it is returned.
func getIVFromDecryptRequest(req *k8skmsv2.DecryptRequest) (iv []byte, err error) {
	var jwe jose.JweRfc7516Compact
	if err = jwe.Unmarshal(string(req.GetCiphertext())); err != nil {
		return nil, fmt.Errorf("error unmarshalling the jwe: %v", err)
	}
	if len(jwe.InitializationVector) == 0 {
		return nil, fmt.Errorf("no initialization vector found in jwe")
	}
	return jwe.InitializationVector, nil
}

// Decrypt
// TODO with kms-provider v2 api, the decrypt request body changed as : https://github.com/kubernetes/kms/blob/cf5ec9691661916fb7911e4545ed38d518f0430e/apis/v2/api.pb.go#L133C1-L133C17
//
//	  the protobuf of the k8s-kms-plugin should be changed according to the new version of the api
//	  -
//	  // The data to be decrypted.
//		 Ciphertext []byte
//		 // UID is a unique identifier for the request.
//	  // NOT	SURE IF IT IS NECESSARY FOR US
//		 Uid string
//		 // The keyID that was provided to the apiserver during encryption.
//		 // This represents the KMS KEK that was used to encrypt the data.
//		 KeyId string
//		 // Additional metadata that was sent by the KMS plugin during encryption.
//	  // NOT	SURE IF IT IS NECESSARY FOR US
//		 Annotations          map[string][]byte
func (p *P11) Decrypt(ctx context.Context, req *k8skmsv2.DecryptRequest) (resp *k8skmsv2.DecryptResponse, err error) {
	var out []byte // buffer for the DecryptResponse.Plaintext
	var isRotation bool

	// Support key rotation
	switch req.KeyId {
	case p.GetKekKeyIdString():
		isRotation = false
	case hex.EncodeToString(p.oldKekCkaId):
		isRotation = true
	default:
		logrus.WithError(err).WithField("key_id", req.GetKeyId()).Error("Decrypt: unknown key ID")
		return nil, fmt.Errorf("Decrypt: unknown key ID: %s", req.GetKeyId())
	}

	// decrypt with PKCS#11 context
	out, err = p.decryptWithContext(req, isRotation)
	if err != nil {
		logrus.WithError(err).Error("error while decrypting with old key")
		return nil, err
	}

	resp = &k8skmsv2.DecryptResponse{
		Plaintext: out,
	}
	return
}

// decryptWithContext performs decryption using the provided PKCS#11 context, DecryptRequest and decryptor map.
//
// The method takes into account if the key has been rotated and decrypts the
// ciphertext accordingly.
func (p *P11) decryptWithContext(req *k8skmsv2.DecryptRequest, isRotation bool) ([]byte, error) {
	var actualCtx *crypto11.Context
	var actualDecryptors map[string]gose.JweDecryptor
	var actualAlgo jose.Alg
	var actualHmacCkaId []byte
	var actualHmacCkaLabel string

	var decryptor gose.JweDecryptor // buffer
	var out []byte                  // buffer for the DecryptResponse.Plaintext
	var aad []byte                  // Additional Authenticated Data optional input used in authenticated encryption algorithms like AES-GCM or AES-CBC-HMAC
	var err error

	if isRotation {
		actualCtx = p.oldCtx
		actualDecryptors = p.oldDecryptors
		actualAlgo = p.oldAlgorithm
		actualHmacCkaId = p.oldHmacCkaId
		actualHmacCkaLabel = p.oldHmacCkaLabel
	} else {
		actualCtx = p.ctx
		actualDecryptors = p.decryptors
		actualAlgo = p.algorithm
		actualHmacCkaId = p.hmacCkaId
		actualHmacCkaLabel = p.hmacCkaLabel
	}

	if decryptor = actualDecryptors[req.GetKeyId()]; decryptor == nil {
		// Random source from the HSM (pkcs11 context)
		var rng io.Reader
		if rng, err = actualCtx.NewRandomReader(); err != nil {
			logrus.WithError(err).Error("error while creating random reader")
			return nil, err
		}

		// convert the string DecryptRequest.KeyId containing a hex representation as string to hex []byte
		var reqKekKeyIdByteA []byte
		if reqKekKeyIdByteA, err = hex.DecodeString(req.GetKeyId()); err != nil {
			logrus.WithError(err).WithField("DecryptRequest.KeyId", req.GetKeyId()).Error("error while decoding the key id")
			return nil, fmt.Errorf("error while decoding the key id: %v", err)
		}

		switch actualAlgo {
		case jose.AlgA256GCM:
			logrus.Tracef("p11:Decrypt case %s", jose.AlgA256GCM)

			// get kek by CKA_ID
			var kek *crypto11.SecretKey

			// Since the DecryptRequest comes from kubernetes, the only information k8s has is the keyId via the StatusResponse
			if kek, err = actualCtx.FindKey(reqKekKeyIdByteA, nil); nil != err {
				logrus.WithError(err).WithField("DecryptRequest.KeyId", req.GetKeyId()).Error("error while finding key by CKA_ID")
				return nil, err
			}

			var aek gose.AeadEncryptionKey
			if aek, err = p.makeAeadKey(rng, kek); err != nil {
				logrus.WithError(err).Error("error while creating aead key")
				return nil, err
			}
			decryptor = gose.NewJweDirectDecryptorAeadImpl([]gose.AeadEncryptionKey{aek})

			if out, aad, err = decryptor.Decrypt(string(req.GetCiphertext())); err != nil {
				logrus.WithError(err).Error("error during decryption")
				return nil, err
			}
			if nil != aad {
				// AAD should be nil - if not, needs to be changed in tandem with /Encrypt
				err = fmt.Errorf("bad AAD")
				logrus.WithError(err).Error("error during decryption AAD should be nil")
				return nil, err
			}
		case jose.AlgA256CBC:
			logrus.Tracef("p11:Decrypt case %s", jose.AlgA256CBC)
			// get kek by id
			var kek *crypto11.SecretKey
			if kek, err = actualCtx.FindKey(reqKekKeyIdByteA, nil); nil != err {
				logrus.WithError(err).Error("error finding key by ID")
				return nil, err
			}

			// for decryption, we have to retrieve the iv from the jwe
			var iv []byte
			if iv, err = getIVFromDecryptRequest(req); err != nil {
				return nil, err
			}
			// Initialize the CBC key for decryption
			var blockMode crypto11.BlockModeCloser
			if blockMode, err = kek.NewCBCDecrypterCloser(iv); err != nil {
				return nil, fmt.Errorf("error initializing block cipher: %v", err)
			}

			cbcKey := gose.NewAesCbcCryptor(blockMode, req.GetKeyId(), jose.AlgA256CBC)
			// Initialize the hmac key for authentication
			var hmacp11Key *crypto11.SecretKey
			if hmacp11Key, err = actualCtx.FindKey(actualHmacCkaId, []byte(actualHmacCkaLabel)); err != nil {
				return nil, fmt.Errorf("error getting hmac key from HSM with label '%s' or id '%s': %v", actualHmacCkaLabel, actualHmacCkaId, err)
			}
			var hash hash.Hash
			if hash, err = hmacp11Key.NewHMAC(pkcs11.CKM_SHA256_HMAC, 0); err != nil {
				return nil, fmt.Errorf("error initializing SHA26 with key '%s': %v", actualHmacCkaLabel, err)
			}
			hmacKey := gose.NewHmacShaCryptor(actualHmacCkaLabel, hash)
			// decryptor
			decryptor = gose.NewJweDirectDecryptorBlock(cbcKey, hmacKey)
			// !!! It is very important to finalize each PKCS11 operation
			defer blockMode.Close()

			if out, aad, err = decryptor.Decrypt(string(req.GetCiphertext())); err != nil {
				logrus.WithError(err).Tracef("error during decryption")
				return nil, err
			}
			if nil != aad {
				// AAD should be nil - if not, needs to be changed in tandem with /Encrypt
				err = fmt.Errorf("bad AAD")
				logrus.WithError(err).Error("error during decryption AAD should be nil")
				return nil, err
			}
		case jose.AlgRSAOAEP:
			logrus.Tracef("p11:Decrypt case %s", jose.AlgRSAOAEP)
			logrus.Tracef("p11:Decrypt case %s", jose.AlgRSAOAEP)
			// load pkcs11 context
			var rsaKeyPair crypto11.SignerDecrypter
			if rsaKeyPair, err = actualCtx.FindRSAKeyPair(reqKekKeyIdByteA, nil); err != nil {
				logrus.WithError(err).Errorf("error finding RSA key pair with id %X", reqKekKeyIdByteA)
				return nil, fmt.Errorf("error finding RSA key pair with id %X: %v", reqKekKeyIdByteA, err)
			}

			var privKey *hsm.AsymmetricDecryptionKey
			if privKey, err = hsm.NewAsymmetricDecryptionKey(p.ctx, rsaKeyPair, reqKekKeyIdByteA, nil); err != nil {
				logrus.WithError(err).Errorf("error creating AsymmetricDecryptionKey with id %X: %v", reqKekKeyIdByteA, err)
				return nil, fmt.Errorf("error creating AsymmetricDecryptionKey with id %X: %v", reqKekKeyIdByteA, err)
			}
			// create key store from private key
			var store gose.AsymmetricDecryptionKeyStore
			if store, err = gose.NewAsymmetricDecryptionKeyStoreImpl(map[string]gose.AsymmetricDecryptionKey{req.GetKeyId(): privKey}); err != nil {
				logrus.WithError(err).Errorf("error creating AsymmetricDecryptionKeyStore with id %X: %v", reqKekKeyIdByteA, err)
				return nil, fmt.Errorf("error creating AsymmetricDecryptionKeyStore with id %X: %v", reqKekKeyIdByteA, err)
			}

			// create decryptor
			decryptor := gose.NewJweRsaKeyEncryptionDecryptorImpl(store)

			// decrypt
			out, _, err = decryptor.Decrypt(string(req.GetCiphertext()), crypto.SHA256)
			if err != nil {
				logrus.WithError(err).Error("decryption failed")
				return nil, err
			}
		default:
			logrus.Error("Decrypt: algorithm not supported")
		}
	}
	return out, nil
}

// Encrypt
// TODO support RSA encryption
//   - load the public key from the KMS and encrypt the cyphertext using gose encryptor
//   - For the EncryptResponse in https://github.com/kubernetes/kms/blob/cf5ec9691661916fb7911e4545ed38d518f0430e/apis/v2/api.pb.go#L287:
//   - use the 'Ciphertext' attribute for with the encrypted ciphertext only (ciphertext of jwe)
//   - Use the 'KeyID' attribute with the TPM's key ID for decryption
//   - Use the 'Annotations' attribute for additional information like the nonce
//     ..
//     with kms-provider v2 api, the encryp request body changed as : https://github.com/kubernetes/kms/blob/cf5ec9691661916fb7911e4545ed38d518f0430e/apis/v2/api.pb.go#L133C1-L133C17
//     the protobuf of the k8s-kms-plugin should be changed according to the new version of the api
//     -
//     // The data to be encrypted.
//     Plaintext []byte `protobuf:"bytes,1,opt,name=plaintext,proto3" json:"plaintext,omitempty"`
//     // UID is a unique identifier for the request.
//     // NOT	SURE IF IT IS NECESSARY FOR US
//     Uid string
func (p *P11) Encrypt(ctx context.Context, req *k8skmsv2.EncryptRequest) (resp *k8skmsv2.EncryptResponse, err error) {
	var encryptor gose.JweEncryptor
	var out string // buffer for the EncryptResponse.Ciphertext

	// p.kid is initialized by NewP11
	if encryptor = p.encryptors[p.GetKekKeyIdString()]; encryptor == nil {
		// Select algorithm
		switch p.algorithm {
		case jose.AlgA256GCM:
			logrus.Tracef("p11:Encrypt case %s", jose.AlgA256GCM)
			logrus.Tracef("p11:Encrypt case %s", jose.AlgA256GCM)
			// Find the KEK in the KMS
			var kek *crypto11.SecretKey
			if kek, err = p.ctx.FindKey(p.kekCkaId, p.GetKekCkaLabelByteA()); nil != err {
				logrus.WithError(err).WithFields(logrus.Fields{
					"algorithm": jose.AlgA256GCM,
					"label":     p.kekCkaLabel,
					"keyId":     p.GetKekKeyIdString(),
				}).Errorf("Encrypt: cannot find a symmetric key")
				return
			}

			// Random source from the HSM (pkcs11 context)
			var rng io.Reader
			if rng, err = p.ctx.NewRandomReader(); err != nil {
				logrus.WithError(err).Errorf("Encrypt: cannot get a random source from the HSM (pkcs11 context)")
				return
			}
			var aek gose.AeadEncryptionKey
			// TODO investigate why the aek result does not have a kid
			if aek, err = p.makeAeadKey(rng, kek); err != nil {
				logrus.WithError(err).Errorf("Encrypt: cannot create an aead key")
				return
			}

			encryptor = gose.NewJweDirectEncryptorAead(aek, p.config.UseGCMIVFromHSM)
			// output is the marshalled jwe
			if out, err = encryptor.Encrypt(req.GetPlaintext(), nil); err != nil {
				logrus.WithError(err).Error("Encrypt: encryption failed")
				return
			}

		case jose.AlgA256CBC:
			logrus.Tracef("p11:Encrypt case %s", jose.AlgA256CBC)
			logrus.Tracef("p11:Encrypt case %s", jose.AlgA256CBC)
			// Find the KEK in the KMS
			var kek *crypto11.SecretKey
			if kek, err = p.ctx.FindKey(p.kekCkaId, p.GetKekCkaLabelByteA()); nil != err {
				logrus.WithError(err).WithFields(logrus.Fields{
					"algorithm": p.algorithm,
					"label":     p.kekCkaLabel,
					"keyId":     p.GetKekKeyIdString(),
				}).Errorf("Encrypt: cannot find a symmetric key")
				return
			}

			// Random source from the HSM (pkcs11 context)
			var rng io.Reader
			if rng, err = p.ctx.NewRandomReader(); err != nil {
				logrus.WithError(err).Errorf("Encrypt: cannot get a random source from the HSM (pkcs11 context)")
				return
			}
			// generate the IV from the KMS, using the kek block size
			iv := make([]byte, kek.Cipher.BlockSize)
			if _, err = rng.Read(iv); err != nil {
				return
			}
			// Initialize the CBC key for encryption
			var blockMode crypto11.BlockModeCloser
			if blockMode, err = kek.NewCBCEncrypterCloser(iv); err != nil {
				return nil, fmt.Errorf("error initializing block cipher: %v", err)
			}
			cbcKey := gose.NewAesCbcCryptor(blockMode, p.GetKekKeyIdString(), p.algorithm)

			// Initialize the hmac key for authentication TODO: consider allowing user to use a CKA_ID to get the HMAC key
			var hmacp11Key *crypto11.SecretKey
			if hmacp11Key, err = p.ctx.FindKey(p.hmacCkaId, []byte(p.hmacCkaLabel)); err != nil {
				return nil, fmt.Errorf("error getting hmac key from HSM with label '%s' and id '%s': %v", p.hmacCkaLabel, p.GetHmacKeyIdString(), err)
			}
			var hash hash.Hash
			if hash, err = hmacp11Key.NewHMAC(pkcs11.CKM_SHA256_HMAC, 0); err != nil {
				return nil, fmt.Errorf("error initializing CKM_SHA256_HMAC with key '%s': %v", p.hmacCkaLabel, err)
			}
			hmacKey := gose.NewHmacShaCryptor(p.hmacCkaLabel, hash)
			// encryptor
			encryptor = gose.NewJweDirectEncryptorBlock(cbcKey, hmacKey, iv)
			// !!! It is very important to finalize each PKCS11 operation
			defer blockMode.Close()
			// output is the marshalled jwe
			if out, err = encryptor.Encrypt(req.GetPlaintext(), nil); err != nil {
				logrus.WithError(err).Error("Encrypt: encryption failed")
				return
			}

		case jose.AlgRSAOAEP:
			logrus.Tracef("p11:Encrypt case %s", jose.AlgRSAOAEP)
			logrus.Tracef("p11:Encrypt case %s", jose.AlgRSAOAEP)
			//TODO generate a jwk with the kid of the public key. Ex :
			//      {"kty":"EC",
			//         "crv":"P-256",
			//         "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
			//         "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
			//         "use":"enc",
			//         "kid":"1"},
			//        {"kty":"RSA",
			//         "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
			//    4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
			//    tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
			//    QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
			//    SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
			//    w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
			//         "e":"AQAB",
			//         "alg":"RS256",
			//         "kid":"2011-04-29"
			//    }
			var rsaKeyPair crypto11.SignerDecrypter
			if rsaKeyPair, err = p.ctx.FindRSAKeyPair(p.kekCkaId, p.GetKekCkaLabelByteA()); err != nil {
				logrus.WithError(err).WithFields(logrus.Fields{
					"algorithm": p.algorithm,
					"label":     p.kekCkaLabel,
					"keyId":     p.GetKekKeyIdString(),
				}).Errorf("Encrypt: cannot find an rsa key pair with label %s", p.kekCkaLabel)
				return nil, err
			}

			// ENCRYPTION
			// get public key
			pubkey := rsaKeyPair.Public()

			// generate jwk from public key
			var pubJwk jose.Jwk
			if pubJwk, err = gose.JwkFromPublicKey(pubkey, []jose.KeyOps{jose.KeyOpsEncrypt}, nil); err != nil {
				logrus.WithError(err).Error("Failed to create JWE RSA Key Encryption Encryptor")
				return nil, err
			}
			// set JWK Algorithm for encryption
			pubJwk.SetAlg(jose.AlgRSAOAEP)

			// encrypt plaintext
			var rsaEncryptor *gose.JweRsaKeyEncryptionEncryptorImpl
			if rsaEncryptor, err = gose.NewJweRsaKeyEncryptionEncryptorImpl(pubJwk, rand.Reader); err != nil {
				logrus.WithError(err).Error("Failed to create JWE RSA Key Encryption Encryptor")
				return nil, err
			}
			// output is the marshalled jwe
			if out, err = rsaEncryptor.Encrypt(req.GetPlaintext(), crypto.SHA256); err != nil {
				logrus.WithError(err).Error("Encrypt: encryption failed")
				return
			}
		default:
			logrus.Infof("Encrypt: not supported algorithm: %s", p.algorithm)
		}
	}

	resp = &k8skmsv2.EncryptResponse{
		// the bytes array contains the bytes of the marshalled jwe
		Ciphertext: []byte(out),
		KeyId:      p.GetKekKeyIdString(),
	}
	return resp, nil
}

func (s *P11) UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	switch req.(type) {
	case *k8skmsv2.StatusRequest:
		{
			logrus.Trace("UnaryInterceptor kms v2 StatusRequest")
		}
	case *k8skmsv2.EncryptRequest:
		{
			logrus.Trace("UnaryInterceptor kms v2 EncryptRequest")
		}
	case *k8skmsv2.DecryptRequest:
		{
			logrus.Trace("UnaryInterceptor kms v2 DecryptRequest")
			if (req).(*k8skmsv2.DecryptRequest).GetKeyId() == "" {
				logrus.Error("UnaryInterceptor: KeyId is empty in the DecryptRequest")
				return nil, status.Errorf(codes.InvalidArgument, "UnaryInterceptor: KeyId is empty in the DecryptRequest")
			}
		}
	default:
		{
			logrus.Trace("UnaryInterceptor default")
		}
	}

	resp, err = handler(ctx, req)
	if err != nil {
		logrus.Error(err)
	}
	return resp, err
}

// Status returns the StatusResponse for the KMS plugin. There are two cases:
// The returned StatusResponse contains the KeyID of the KEK (CKA_ID), the Healthz and the Version.
//
// Status() method comes from the KeyManagementServiceClient interface from "k8s.io/kms/apis/v2"
// See https://pkg.go.dev/k8s.io/kms@v0.31.3/apis/v2#KeyManagementServiceClient
// Also check the content of a StatusResponse
// See https://pkg.go.dev/k8s.io/kms@v0.31.3/apis/v2#StatusResponse
func (p *P11) Status(ctx context.Context, request *k8skmsv2.StatusRequest) (statusResponse *k8skmsv2.StatusResponse, err error) {
	logrus.Trace("p11 Status: entering method")

	// NewP11 should populate both KEK ID (CKA_ID) and Key label (CKA_LABEL), but check the content just in case.
	if p.kekCkaId == nil {
		err = errors.New("KEK ID is nil")
		logrus.WithError(err).Error("p11 Status: error due to missing KEK ID")
		return
	}

	if len(p.kekCkaId) == 0 {
		err = errors.New("KEK ID is empty")
		logrus.WithError(err).Error("p11 Status: error due to missing KEK ID")
		return
	}

	statusResponse = &k8skmsv2.StatusResponse{
		Version: "v2",
		Healthz: "ok",
		KeyId:   p.GetKekKeyIdString(),
	}

	logrus.WithFields(logrus.Fields{
		"Version": statusResponse.Version,
		"Healthz": statusResponse.Healthz,
		"KeyId":   statusResponse.KeyId,
	}).Debug("StatusResponse")
	return statusResponse, nil
}

// TODO: decide if this Istio related method should be separated from the KMS v2 plugin
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

// FindCkaAttrByIdOrLabel find a CKA attribute like CKA_ID or CKA_LABEL by id or by label.
func FindCkaAttrByIdOrLabel(ctx *crypto11.Context, algorithm jose.Alg, ckaAttr crypto11.AttributeType, id, label []byte) ([]byte, error) {
	var outBuf []byte // output buffers

	if ( // find ID by label
	(len(id) == 0) &&
		(label != nil || len(label) > 0) &&
		(ckaAttr == crypto11.CkaId)) ||
		( // find label by ID
		(id != nil || len(id) > 0) &&
			(len(label) == 0) &&
			(ckaAttr == crypto11.CkaLabel)) {

		var err error
		switch algorithm {
		case jose.AlgA256GCM, jose.AlgA256CBC:
			// Find the key in the KMS for AES symmetric algorithms
			var symKey *crypto11.SecretKey
			if symKey, err = ctx.FindKey(id, label); nil != err {
				logrus.WithError(err).Errorf("FindCkaAttrByIdOrLabel:cannot find a %s symmetric key with label %x or id %x", algorithm, label, id)
				return nil, err
			}

			// Get the CKA_ID to obtain the KEK key id
			var attr *crypto11.Attribute
			if attr, err = ctx.GetAttribute(symKey, ckaAttr); err != nil {
				logrus.WithError(err).Errorf("FindCkaAttrByIdOrLabel: cannot get the CKA_ attribute %v for algo %s and key with label %x or id %x", ckaAttr, algorithm, label, id)
				return nil, err
			} else {
				outBuf = attr.Value
			}
		case jose.AlgRSAOAEP:
			// Find the key in the KMS for RSA asymmetric algorithms
			var rsaKeyPair crypto11.SignerDecrypter
			if rsaKeyPair, err = ctx.FindRSAKeyPair(id, label); err != nil {
				logrus.WithError(err).Errorf("FindCkaAttrByIdOrLabel: cannot find an rsa key pair with label %x or id %x", label, id)
				return nil, err
			}

			// Get the key id by key label
			var attr *crypto11.Attribute
			if attr, err = ctx.GetAttribute(rsaKeyPair, ckaAttr); err != nil {
				logrus.WithError(err).Errorf("FindCkaAttrByIdOrLabel: cannot get the CKA_ attribute %v for algo %s and with label %x or id %x", ckaAttr, algorithm, label, id)
				return nil, err
			} else {
				outBuf = attr.Value
			}
		}
	} else {
		logrus.Errorf("FindCkaAttrByIdOrLabel: cannot find a key with parameters id%x and label%x", id, label)
		return nil, fmt.Errorf("FindCkaAttrByIdOrLabel: cannot find a key with parameters id%x and label%x", id, label)
	}

	return outBuf, nil
}

// GetKeyIdAndLabel checks the CKA_ID and CKA_LABEL of a key from the P11 provider, and returns
// both of the value from one or the other.
// Indeed, Key ID and Key Label are mutually exclusive and at least one must be provided.
// If the Key ID is provided only, this function retrieves the label of the key.
// If the Key Label is provided, this function retrieves the ID of the key.
// If the key Label is provided and the key is retrieved without a Key ID from the HSM, the process
// exits with a fatal error. Indeed, the K8S KMS v2 protocol requires a Key ID (CKA_ID) for status
// requests.
func GetKeyIdAndLabel(p *P11, keyId string, keyLabel string) (resultKeyId []byte, resultKeyLabel string, err error) {
	var resultKeyLabelBytes []byte
	if keyId == "" && keyLabel != "" {
		logrus.Tracef("NewP11: key id (CKA_ID) is empty. Find CKA_ID by CKA_LABEL %s", keyLabel)
		resultKeyLabel = keyLabel

		keyLabelBytes := []byte(keyLabel)
		resultKeyId, err = FindCkaAttrByIdOrLabel(p.ctx, p.algorithm, crypto11.CkaId, nil, keyLabelBytes)
		if err != nil {
			logrus.WithError(err).Errorf("NewP11: failed to find key CKA_ID by CKA_LABEL '%s'", resultKeyLabel)
			return nil, "", err
		}

		// panic error if the CKA_ID if the key, found using its label, is empty.
		if len(resultKeyId) == 0 {
			logrus.Fatalf("NewP11: Fatal error : key ID (CKA_ID) empty for key label (CKA_LABEL) '%s'. k8s-kms-plugin only supports keys with a CKA_ID in HSM", keyLabel)
		}
	} else if keyId != "" && keyLabel == "" {
		// Case: KEK ID already provided by user at startup with flag --p11-key-id
		// If k8sKekLabel is empty but kekkeyid is not nil, we can get the key label by the key id. But
		// the only purpose of this is for logging messages, as the CKA_LABEL is not use in the KMS v2
		// API calls.
		// But we could use EncryptResponse.Annotations and DecryptRequest.Annotations to store
		// the value of the key label CKA_LABEL.
		logrus.Tracef("NewP11: key label (CKA_LABEL) is empty but key id (CKA_ID) is not empty. Find CKA_LABEL by CKA_ID %s", keyId)
		resultKeyId, err = hex.DecodeString(keyId)
		if err != nil {
			return nil, "", fmt.Errorf("NewP11: cannot decode string CKA_ID into hex expected format '%s': %w", keyId, err)
		}

		if resultKeyLabelBytes, err = FindCkaAttrByIdOrLabel(p.ctx, p.algorithm, crypto11.CkaLabel, resultKeyId, nil); err != nil {
			logrus.WithError(err).Error("NewP11: failed to find key CKA_LABEL by CKA_ID '%s'", resultKeyId)
			return nil, "", err
		}
		resultKeyLabel = string(resultKeyLabelBytes)
	} else if keyId == "" && keyLabel == "" {
		errMsg := "NewP11: key ID (CKA_ID) and key label (CKA_LABEL) are both empty, please provide one of them"
		logrus.WithError(err).Errorf(errMsg)
		return nil, "", fmt.Errorf(errMsg)
	} else {
		errMsg := "NewP11: both key ID (CKA_ID) and key label (CKA_LABEL) are provided, please provide only one"
		logrus.WithError(err).Errorf(errMsg)
		return nil, "", fmt.Errorf(errMsg)
	}

	return
}
