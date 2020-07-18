// Copyright 2019 Thales e-Security, Inc
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package gose

import (
	"io/ioutil"

	"bytes"
	"encoding/json"
	"sync"

	"github.com/ThalesIgnite/gose/jose"
)

//TrustKeyStoreImpl implements the Trust Store API
type TrustKeyStoreImpl struct {
	keys map[string]map[string]jose.Jwk
	mtx  sync.Mutex
}

//Add add an issuer and JWK to the truststore
func (store *TrustKeyStoreImpl) Add(issuer string, jwk jose.Jwk) error {
	if jwk.Kid() == "" {
		// We want a Key ID and we want it now!
		return ErrInvalidKey
	}
	store.mtx.Lock()
	defer store.mtx.Unlock()
	if _, exists := store.keys[issuer]; !exists {
		store.keys[issuer] = make(map[string]jose.Jwk)
	}
	if _, exists := store.keys[issuer][jwk.Kid()]; exists {
		return nil
	}
	store.keys[issuer][jwk.Kid()] = jwk
	return nil
}

//Remove remove JWK for issuer and jwk id
func (store *TrustKeyStoreImpl) Remove(issuer, kid string) bool {
	store.mtx.Lock()
	defer store.mtx.Unlock()
	if _, exists := store.keys[issuer]; !exists {
		return false
	}
	delete(store.keys[issuer], kid)
	return true
}

//Get get verification jwk for issuer and jwk id
func (store *TrustKeyStoreImpl) Get(issuer, kid string) (vk VerificationKey, err error) {
	store.mtx.Lock()
	defer store.mtx.Unlock()
	if keySet, ok := store.keys[issuer]; ok {
		if jwk, ok := keySet[kid]; ok {
			if key, err := NewVerificationKey(jwk); err == nil {
				return key, nil
			}
			return nil, err
		}
	}
	return nil, ErrUnknownKey
}

//NewTrustKeyStore loads truststore for map of jose.JWK
func NewTrustKeyStore(rootData map[string]jose.Jwk) (store *TrustKeyStoreImpl, err error) {
	tmp := TrustKeyStoreImpl{}
	tmp.keys = make(map[string]map[string]jose.Jwk)
	for issuer, jwk := range rootData {
		if err = tmp.Add(issuer, jwk); err != nil {
			return
		}
	}
	store = &tmp
	return
}

//NewTrustKeyStoreFromFile loads truststore for a
func NewTrustKeyStoreFromFile(root string) (store *TrustKeyStoreImpl, err error) {
	tmp := TrustKeyStoreImpl{}
	tmp.keys = make(map[string]map[string]jose.Jwk)
	var entries map[string]json.RawMessage
	rootData, err := ioutil.ReadFile(root)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(rootData, &entries); err != nil {
		return
	}
	for issuer, entry := range entries {
		var jwk jose.Jwk
		if jwk, err = jose.UnmarshalJwk(bytes.NewReader([]byte(entry))); err != nil {
			return
		}
		if err = tmp.Add(issuer, jwk); err != nil {
			return
		}
	}
	store = &tmp
	return
}
