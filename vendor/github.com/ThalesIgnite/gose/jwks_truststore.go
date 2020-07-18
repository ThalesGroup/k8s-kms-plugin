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
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ThalesIgnite/gose/jose"
	"net/http"
	"sync"
)

// Interface wrapper to allow mocking of http client.
type httpClient interface {
	Get(url string) (resp *http.Response, err error)
}

// JwksTrustStore is an implementation of the TrustStore interface and can be used for accessing VerificationKeys.
type JwksTrustStore struct {
	lock   sync.Mutex
	url    string
	issuer string
	keys   []VerificationKey
	client httpClient
}

// Add this method is not supported on a JwksTrustStore instance and will always return an error.
func (store *JwksTrustStore) Add(issuer string, jwk jose.Jwk) error {
	return errors.New("read-only trust store")
}

// Remove this method is not supported on a JwksTrustStore instance and will always return false.
func (store *JwksTrustStore) Remove(issuer, kid string) bool {
	return false
}

// Get returns a verification key for the given issuer and key id. If no key is found nil is returned.
func (store *JwksTrustStore) Get(issuer, kid string) (vk VerificationKey, err error) {
	if issuer == store.issuer {
		store.lock.Lock()
		defer store.lock.Unlock()
		for _, key := range store.keys {
			if key.Kid() == kid {
				vk = key
				return
			}
		}
		// Not found. Refresh the keys
		var response *http.Response
		response, err = store.client.Get(store.url)
		if err != nil {
			err = fmt.Errorf("error encountered retrieving JWKS from %s: %v", store.url, err)
			return
		}
		if response.StatusCode != http.StatusOK {
			err = fmt.Errorf("error encountered retrieving JWKS from %s: %d %s", store.url, response.StatusCode, response.Status)
			return
		}
		decoder := json.NewDecoder(response.Body)
		var jwks jose.Jwks
		if err = decoder.Decode(&jwks); err != nil {
			err = fmt.Errorf("error encountered retrieving JWKS from %s: invalid encoding", store.url)
			return
		}
		keys := make([]VerificationKey, 0, len(jwks.Keys))
		for _, jwk := range jwks.Keys {
			vk, err = NewVerificationKey(jwk)
			if err != nil {
				err = fmt.Errorf("failed to load verification key from JWK: %v", err)
				return
			}
			keys = append(keys, vk)
		}
		// Replace the keys for our store.
		store.keys = keys

		// Try and find key in newly cached keys
		for _, key := range store.keys {
			if key.Kid() == kid {
				vk = key
				return key, nil
			}
		}
		// No such currently valid key.
	}
	return
}

// NewJwksKeyStore creates a new instance of a TrustStore and can be used to load verification keys.
func NewJwksKeyStore(issuer, url string) *JwksTrustStore {
	return &JwksTrustStore{
		url:    url,
		issuer: issuer,
		client: http.DefaultClient,
	}
}
