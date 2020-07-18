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
	"log"
	"time"

	"github.com/ThalesIgnite/gose/jose"
	"github.com/google/uuid"
)

var _ JwtSigner = (*JwtSignerImpl)(nil)

//JwtSignerImpl JWT implementation
type JwtSignerImpl struct {
	key    SigningKey
	issuer string
}

//Issuer returns issuer of JWT
func (signer *JwtSignerImpl) Issuer() string {
	return signer.issuer
}

//Sign claims to a JWT string
func (signer *JwtSignerImpl) Sign(claims *jose.SettableJwtClaims, untyped map[string]interface{}) (string, error) {
	var encodedUntyped jose.UntypedClaims
	if untyped != nil {
		encodedUntyped = make(jose.UntypedClaims, len(untyped))
		for k, v := range untyped {
			encoded, err := json.Marshal(v)
			if err != nil {
				return "", err
			}
			encodedUntyped[k] = encoded
		}
	}
	jwt := jose.Jwt{
		Header: jose.JwsHeader{
			Alg: signer.key.Algorithm(),
			Kid: signer.key.Kid(),
			Typ: jose.JwtType,
		},
		Claims: jose.JwtClaims{
			AutomaticJwtClaims: jose.AutomaticJwtClaims{
				IssuedAt: time.Now().Unix(),
				Issuer:   signer.issuer,
				JwtID:    uuid.New().String(),
			},
			SettableJwtClaims: *claims,
			UntypedClaims:     encodedUntyped,
		},
	}
	toBeSigned, err := jwt.MarshalBody()
	if err != nil {
		return "", err
	}
	signature, err := signer.key.Sign(jose.KeyOpsSign, []byte(toBeSigned))
	if err != nil {
		return "", err
	}
	jwt.Signature = make([]byte, len(signature))
	if count := copy(jwt.Signature, signature); count != len(signature) {
		// This should never happen!
		log.Panic("failed to copy all signature bytes")
	}
	return jose.MarshalJws(toBeSigned, jwt.Signature), nil
}

//NewJwtSigner returns a JWT Signer for a issuer and jwk
func NewJwtSigner(issuer string, key SigningKey) *JwtSignerImpl {
	return &JwtSignerImpl{key: key, issuer: issuer}
}
