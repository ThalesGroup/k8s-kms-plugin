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
	"bytes"
	"fmt"
	"github.com/ThalesIgnite/gose"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/sirupsen/logrus"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/utils"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
)

var (
	wrappedIntKekAAD = []byte("wrapped-intermediate-kek")
	intKekName       = "kms-int-kek-wrapped"
)

// FileStore is a file-backed private key store.
//
// The root directory will be created on demand.
type FileStore struct {
	// The root directory for the store
	Root      string
	intKek    jose.Jwk
	encryptor gose.JweEncryptor
	decryptor gose.JweDecryptor
}

// NewFilePrivateKeyStore constructs a new file-backed private key store, rooted at root.
func NewFilePrivateKeyStore(root string) (keystore *FileStore, err error) {
	keystore = &FileStore{Root: root,
	}

	if err = os.MkdirAll(root, 0700); err != nil {
		return
	}

	return
}

// Exists tests whether the key exists.
func (fs *FileStore) Exists(name string) (exists bool, err error) {
	return fs.exists(name)
}

//LoadIntKek will bootstrap the
func (fs *FileStore) LoadIntKek(jwk jose.Jwk) (err error) {
	fs.intKek = jwk
	var aead gose.AuthenticatedEncryptionKey
	if aead, err = gose.NewAesGcmCryptorFromJwk(jwk, []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}); err != nil {
		return
	}
	fs.encryptor = gose.NewJweDirectEncryptorImpl(aead)

	// TODO, allow for historical wrapping keys maybe?
	fs.decryptor = gose.NewJweDirectDecryptorImpl([]gose.AuthenticatedEncryptionKey{aead})
	return
}

// Remove removes a private key by name
func (fs *FileStore) Remove(name string) (err error) {
	var jwk jose.Jwk
	if jwk, err = fs.retrieve(name, []jose.KeyOps{jose.KeyOpsEncrypt, jose.KeyOpsDecrypt}); err != nil {
		return
	}
	// Retrieve first so we can destroy the keyid entry too...
	// TODO: Come back to this with some key rotation/lifecycle
	var fullname, fullkid string
	if fullname, err = fs.name(name); err != nil {
		return
	}
	if fullkid, err = fs.name(jwk.Kid()); err != nil {
		return
	}
	// remove both copies.
	if err = os.Remove(fullname); err != nil {
		return
	}
	if err = os.Remove(fullkid); err != nil {
		return
	}
	return
}

// RemoveAll removes all private keys from a keystore
func (fs *FileStore) RemoveAll() (err error) {
	return os.RemoveAll(fs.Root)
}

// Retrieve retrieves the serialized form of the key.
func (fs *FileStore) Retrieve(name string, keyOps []jose.KeyOps) (jwk jose.Jwk, err error) {
	return fs.retrieve(name, keyOps)
}

func (fs *FileStore) RetrieveStoreIntKek() (wrappedIntKek []byte, err error) {
	var fullname = filepath.Join(fs.Root, intKekName)
	if wrappedIntKek, err = ioutil.ReadFile(fullname); err != nil {

		return nil, utils.ErrNoSuchKey
	}
	return
}

// API implementation

// Store persists a serialized key.
func (fs *FileStore) Store(name string, jwk jose.Jwk, overwrite bool) (err error) {

	// Check if it exists first..
	var exists bool
	if exists, err = fs.Exists(name); err != nil {
		logrus.Error(err)
		return
	}
	if exists {
		if !overwrite {
			err = status.Error(codes.AlreadyExists, "key already exists, not overwriting")
			return
		}
	}

	// Store the key twice... so we can find by id and name... (it's a filesystem, not a database :) )
	if err = fs.store(name, jwk); err != nil {
		return
	}
	if err = fs.store(jwk.Kid(), jwk); err != nil {
		return
	}
	return
}
func (fs *FileStore) StoreIntKek(wrappedIntKek []byte) (err error) {
	var fullname = filepath.Join(fs.Root, intKekName)
	if err = os.MkdirAll(fs.Root, 0700); err != nil {
		return
	}
	if err = ioutil.WriteFile(fullname, wrappedIntKek, 0600); err != nil {
		return
	}
	return
}

func (fs *FileStore) exists(name string) (exists bool, err error) {
	var fi os.FileInfo
	var fullname string
	if fullname, err = fs.name(name); err != nil {
		return
	}
	if fi, err = os.Stat(fullname); err != nil {
		if err.(*os.PathError).Err == syscall.ENOENT {
			return false, nil
		}
		return false, err
	}
	if fi.IsDir() {
		return false, fmt.Errorf("%s is a directory", fullname)
	}
	return true, nil
}

// Validate a name and return the full path.
func (fs *FileStore) name(name string) (fullname string, err error) {

	if !safeName(name) {
		err = fmt.Errorf("invalid key name '%s'", name)
		return
	}
	fullname = filepath.Join(fs.Root, name)

	return
}

func (fs *FileStore) retrieve(name string, keyOps []jose.KeyOps) (jwk jose.Jwk, err error) {
	var fullname string
	if fullname, err = fs.name(name); err != nil {
		return
	}
	// #nosec G304
	var wrappedIntKekBytes []byte
	if wrappedIntKekBytes, err = ioutil.ReadFile(fullname); err != nil {
		return
	}
	var decryptedAAD, intKekBytes []byte
	if intKekBytes, decryptedAAD, err = fs.decryptor.Decrypt(string(wrappedIntKekBytes)); err != nil {
		return
	}
	if !reflect.DeepEqual(decryptedAAD, wrappedIntKekAAD) {
		err = status.Error(codes.InvalidArgument, "AAD provided doesn't match...")
	}
	return gose.LoadJwk(bytes.NewReader(intKekBytes), utils.AuthenticatedEncryptedKeyOperations)
}

func (fs *FileStore) store(name string, jwk jose.Jwk) (err error) {

	var fullname string
	if fullname, err = fs.name(name); err != nil {
		return
	}
	if err = os.MkdirAll(fs.Root, 0700); err != nil {
		return
	}
	var outstring string
	if outstring, err = gose.JwkToString(jwk); err != nil {
		return
	}

	// Wrapp if there is a loaded wrapper key

	if outstring, err = fs.encryptor.Encrypt([]byte(outstring), wrappedIntKekAAD); err != nil {
		return
	}

	return ioutil.WriteFile(fullname, []byte(outstring), 0600)
}
