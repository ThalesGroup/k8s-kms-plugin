/*
 * // Copyright 2020 Thales DIS CPL Inc
 * //
 * // Permission is hereby granted, free of charge, to any person obtaining
 * // a copy of this software and associated documentation files (the
 * // "Software"), to deal in the Software without restriction, including
 * // without limitation the rights to use, copy, modify, merge, publish,
 * // distribute, sublicense, and/or sell copies of the Software, and to
 * // permit persons to whom the Software is furnished to do so, subject to
 * // the following conditions:
 * //
 * // The above copyright notice and this permission notice shall be
 * // included in all copies or substantial portions of the Software.
 * //
 * // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * // EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * // NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * // LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * // OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * // WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package keystore

import (
	"errors"
	"fmt"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
)

// ----------------------------------------------------------------------------

// MemoryStore is a nonpersistent memory-backed private key store.
//
// This is only intended to be used for testing.
type MemoryStore struct {
	// Map of key ids to values
	Keys          map[string]jose.Jwk
	KeyIdMap      map[string]string
	wrappedIntKek []byte
	aeGen         *gose.AuthenticatedEncryptionKeyGenerator
	intKek        jose.Jwk
	intKekEnc     gose.JweEncryptor
	intKekDec     gose.JweDecryptor
}

func (ks *MemoryStore) LoadIntKek(jwk jose.Jwk) (err error) {
	var aead gose.AuthenticatedEncryptionKey
	if aead, err = gose.NewAesGcmCryptorFromJwk(jwk, []jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt}); err != nil {
		return
	}

	ks.intKekEnc = gose.NewJweDirectEncryptorImpl(aead)
	ks.intKekDec = gose.NewJweDirectDecryptorImpl([]gose.AuthenticatedEncryptionKey{aead})
	return
}

// NewMemoryPrivateKeyStore constructs a new memory-backed private key store
func NewMemoryPrivateKeyStore(wrappedIntKek []byte) (keystore *MemoryStore) {
	keystore = &MemoryStore{
		Keys:          map[string]jose.Jwk{},
		KeyIdMap:      map[string]string{},
		aeGen:         &gose.AuthenticatedEncryptionKeyGenerator{},
		wrappedIntKek: wrappedIntKek,
	}

	return
}

// Exists tests whether the key exists.
func (ks *MemoryStore) Exists(name string) (exists bool, err error) {
	if _, ok := ks.Keys[name]; !ok {
		return false, nil
	}
	return true, nil
}

// Remove removes private key by name
func (ks *MemoryStore) Remove(name string) (err error) {
	if _, ok := ks.Keys[name]; !ok {
		return errors.New("Not found")
	}

	delete(ks.Keys, name)
	delete(ks.KeyIdMap, name)
	return
}

// RemoveAll removes all private keys from keystore
func (ks *MemoryStore) RemoveAll() (err error) {

	for key := range ks.Keys {
		delete(ks.Keys, key)
	}

	return
}

// Retrieve retrieves the serialized form of the key.
func (ks *MemoryStore) Retrieve(name string, keyops []jose.KeyOps) (jwk jose.Jwk, err error) {
	var ok bool
	var keyid string
	keyid = ks.KeyIdMap[name]
	if jwk, ok = ks.Keys[keyid]; !ok {
		return nil, fmt.Errorf("key %s does not exist", name)
	}

	return
}

func (ks *MemoryStore) Store(name string, jwk jose.Jwk, overwrite bool) (err error) {
	ks.Keys[jwk.Kid()] = jwk
	ks.KeyIdMap[name] = jwk.Kid()
	return
}

func (ks *MemoryStore) StoreIntKek(wrappedIntKek []byte) (err error) {

	ks.wrappedIntKek = wrappedIntKek
	return
}

func (ks *MemoryStore) RetrieveStoreIntKek() (wrappedIntKek []byte, err error) {
	return ks.wrappedIntKek, err
}
