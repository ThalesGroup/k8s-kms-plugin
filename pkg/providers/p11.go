package providers

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/ThalesIgnite/crypto11"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
	"io"
	"k8s.io/apiserver/pkg/storage/value/encrypt/envelope/v1beta1"
)

const (
	defaultkeyId    = "a37807cd-6d1a-4d75-813a-e120f30176f7" // TODO: replace with some kind of better binding.
	defaultkeyLabel = "k8s-kms-plugin-root-key"
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

type keyGenerationParameters struct {
	size   int
	cipher *crypto11.SymmetricCipher
}

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
	if keyId == "" {
		keyId = defaultkeyId
	}
	p = &P11{
		keyId:     []byte(keyId),
		keyLabel:  []byte(keyLabel),
		config:    config,
		createKey: createKey,
	}
	return
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
			if aek, err = p.Generate(p.keyId, jose.AlgA256GCM); err != nil {
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

func (p *P11) Decrypt(ctx context.Context, req *v1beta1.DecryptRequest) (resp *v1beta1.DecryptResponse, err error) {
	if p.decryptor == nil {
		if err = p.loadDevice(); err != nil {
			return
		}
	}
	var out []byte
	if out, _, err = p.decryptor.Decrypt(string(req.Cipher)); err != nil {
		return
	}
	resp = &v1beta1.DecryptResponse{
		Plain: out,
	}
	return
}

func (p *P11) Encrypt(ctx context.Context, req *v1beta1.EncryptRequest) (resp *v1beta1.EncryptResponse, err error) {
	if p.encryptor == nil {
		if err = p.loadDevice(); err != nil {
			return
		}
	}
	var out string
	if out, err = p.encryptor.Encrypt(req.Plain, nil); err != nil {
		return
	}
	resp = &v1beta1.EncryptResponse{
		Cipher: []byte(out),
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

//Generate an AEK
func (p *P11) Generate(identity []byte, alg jose.Alg) (key gose.AuthenticatedEncryptionKey, err error) {
	params, supported := algToKeyGenParams[alg]
	if !supported {
		err = fmt.Errorf("algorithm %v is not supported", alg)
		return
	}

	if _, err = p.ctx.GenerateSecretKeyWithLabel(identity, p.keyLabel, params.size, params.cipher); err != nil {
		return
	}

	key, err = p.Load(identity)
	return
}
