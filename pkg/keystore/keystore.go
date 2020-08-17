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

import "github.com/ThalesIgnite/gose/jose"


// ----------------------------------------------------------------------------
// KeyStore is the private key storage interface.
//
// We expect that there will only be a small number of private keys.
//
// Names may be constrained by the implementations. For instance the
// file-backed implementation insists that key names are nonempty,
// don't start "." and don't contain "/", making them suitable for use
// in a filesystem.
type KeyStore interface {
	// Store a serialized private key by name
	Store(name string, jwk jose.Jwk, overwrite bool) (err error)

	// Store the wrappedIntKek
	StoreIntKek(wrappedIntKek []byte) (err error)

	// Retrieve the wrappedIntKek
	RetrieveStoreIntKek() (wrappedIntKek []byte, err error)

	// Retrieve a serialized private key by name
	Retrieve(name string, keyops []jose.KeyOps) (jwk jose.Jwk, err error)

	// If the private key exists, returns true,nil
	// If the private key does not exist, returns false,nil
	// If something goes wrong, returns false,non-nil
	Exists(name string) (exists bool, err error)

	// Remove private key by name
	Remove(name string) (err error)

	// RemoveAll removes all private keys from keystore
	RemoveAll() (err error)

	// LoadIntKek will tell the keystore what to encrypt and decrypt it's stored objects with.
	// it's imperative, and if the wrong key is used on an existing keystore, it should fail safely, as the JWE will know
	LoadIntKek(jwk jose.Jwk) (err error)
}
