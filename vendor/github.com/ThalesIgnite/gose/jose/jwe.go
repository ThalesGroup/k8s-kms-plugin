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

package jose

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// JweCustomHeaderFields custom JWE defined fields.
type JweCustomHeaderFields struct {
	// Other AAD for transporting AAD around with the JWE...
	OtherAad *Blob `json:"_thales_aad,omitempty"`
}

// JweHeader JWE header fields.
type JweHeader struct {
	JwsHeader
	JweCustomHeaderFields
	Enc Enc `json:"enc"`
	Zip Zip `json:"zip,omitempty"`
}

// Jwe representation of a JWE.
type Jwe struct {
	Header           JweHeader
	MarshalledHeader []byte
	EncryptedKey     []byte
	Iv               []byte
	Ciphertext       []byte
	Plaintext        []byte
	Tag              []byte
}

// MarshalHeader marshal JWE header. Note this is not guaranteed to result in the same marshaled representation across
// invocations.
func (jwe *Jwe) MarshalHeader() (err error) {
	var headerBytes []byte
	if headerBytes, err = json.Marshal(jwe.Header); err != nil {
		return
	}
	jwe.MarshalledHeader = []byte(base64.RawURLEncoding.EncodeToString(headerBytes))
	return
}

//Unmarshal to body string, or error
func (jwe *Jwe) Unmarshal(src string) (err error) {
	/* Compact JWS encoding. */
	parts := strings.Split(src, ".")
	if len(parts) != 5 {
		err = ErrJweFormat
		return
	}
	if jwe.MarshalledHeader, err = base64.RawURLEncoding.DecodeString(parts[0]); err != nil {
		return
	}
	if err = json.Unmarshal(jwe.MarshalledHeader, &jwe.Header); err != nil {
		return
	}
	jwe.MarshalledHeader = []byte(parts[0])
	// JWE Encrypted key can be a zero length key in scenarios such as direct encoding.
	if len(parts[1]) > 0 {
		if jwe.EncryptedKey, err = base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
			return
		}
	}
	if jwe.Iv, err = base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
		return
	}
	if jwe.Ciphertext, err = base64.RawURLEncoding.DecodeString(parts[3]); err != nil {
		return
	}
	if jwe.Tag, err = base64.RawURLEncoding.DecodeString(parts[4]); err != nil {
		return
	}
	return
}

// Marshal marshal a JWE to it's compact representation.
func (jwe *Jwe) Marshal() string {
	stringz := []string{
		string(jwe.MarshalledHeader),
		base64.RawURLEncoding.EncodeToString(jwe.EncryptedKey),
		base64.RawURLEncoding.EncodeToString(jwe.Iv),
		base64.RawURLEncoding.EncodeToString(jwe.Ciphertext),
		base64.RawURLEncoding.EncodeToString(jwe.Tag),
	}
	return strings.Join(stringz, ".")
}
