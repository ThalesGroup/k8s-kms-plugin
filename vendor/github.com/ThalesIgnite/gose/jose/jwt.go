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
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"
)

// Standard JWT claim names that cannot be used as untyped keys.
var reservedJwtClaims = map[string]bool{
	"iss": true,
	"iat": true,
	"jti": true,
	"sub": true,
	"aud": true,
	"exp": true,
	"nbf": true,
}

// AutomaticJwtClaims represent standard JWT claims that should not generally be set by a caller.
// For example the iat (issued-at) claim should only be set by a signer not the caller who requests
// the JWT.
type AutomaticJwtClaims struct {
	Issuer   string `json:"iss,omitempty"`
	IssuedAt int64  `json:"iat,omitempty"`
	JwtID    string `json:"jti,omitempty"`
}

// SettableJwtClaims are claims generally requested by a caller and not a signer.
type SettableJwtClaims struct {
	Subject    string    `json:"sub,omitempty"`
	Audiences  Audiences `json:"aud,omitempty"`
	Expiration int64     `json:"exp,omitempty"`
	NotBefore  int64     `json:"nbf,omitempty"`
}

//UntypedClaims for non-standard clains
type UntypedClaims map[string]json.RawMessage

//JwtClaims claims for a JWT
type JwtClaims struct {
	AutomaticJwtClaims
	SettableJwtClaims
	UntypedClaims
}

// unmarshalClaims unmarshal typed claims into the struct |into|
func unmarshalTypedClaims(claims map[string]json.RawMessage, into interface{}) (err error) {
	/* Loop through known claims extracting values as appropriate. */
	auto := reflect.TypeOf(into).Elem()
	for i := 0; i < auto.NumField(); i++ {
		field := reflect.ValueOf(into).Elem().Field(i)
		// TODO: write a proper json tag parser when needed. All our known claims have a consistent struct tag format.
		if tag, exists := auto.Field(i).Tag.Lookup("json"); exists {
			values := strings.Split(tag, ",")
			if len(values) < 1 {
				// should never happen
				logrus.Fatal("Broken json struct tag")
			}
			name := values[0]
			if value, exists := claims[name]; exists {
				if !field.CanAddr() {
					// should never happen
					logrus.Fatal("Broken json struct type, must be addressable")
				}
				if err = json.Unmarshal(value, field.Addr().Interface()); err != nil {
					return
				}
				// Remove claim we have consumed.
				delete(claims, name)
			}
		}
	}
	return

}

// UnmarshalJSON implements json.Unmarshaler interface method.
func (c *JwtClaims) UnmarshalJSON(data []byte) (err error) {
	claims := make(map[string]json.RawMessage)
	if err = json.Unmarshal(data, &claims); err != nil {
		return
	}
	/* Decode typed claims. */
	if err = unmarshalTypedClaims(claims, &c.AutomaticJwtClaims); err != nil {
		return
	}
	if err = unmarshalTypedClaims(claims, &c.SettableJwtClaims); err != nil {
		return
	}
	// All remaining claims
	c.UntypedClaims = claims
	return
}

// UnmarshalCustomClaim Unmarshals a custom claim. A Claim that do not exist is unset but no error is returned.
func (c *JwtClaims) UnmarshalCustomClaim(name string, claim interface{}) error {
	targetClaim, ok := c.UntypedClaims[name]
	if ok {
		if err := json.Unmarshal(targetClaim, claim); err != nil {
			return err
		}
	}
	return nil
}

// MarshalJSON implements json.Marshaler interface method.
func (c *JwtClaims) MarshalJSON() (dst []byte, err error) {
	// Temporary type and instance. Note the use of references.
	output := struct {
		*AutomaticJwtClaims
		*SettableJwtClaims
	}{
		AutomaticJwtClaims: &c.AutomaticJwtClaims,
		SettableJwtClaims:  &c.SettableJwtClaims,
	}

	// Dynamically generate a struct with typed and untyped fields for marshalling.

	// Copy struct fields from our temporary type
	fields := make([]reflect.StructField, 0, reflect.TypeOf(output).NumField())
	for i := 0; i < reflect.TypeOf(output).NumField(); i++ {
		fields = append(fields, reflect.TypeOf(output).Field(i))
	}
	// Create struct fields for each untyped entry.
	for k := range c.UntypedClaims {
		// Validate untyped fields do not clash with standard JWT claims.
		if _, invalid := reservedJwtClaims[k]; invalid {
			err = ErrJwkReservedClaimName
			return
		}
		field := reflect.StructField{
			Name:      fmt.Sprintf("A%s", k), // Add the "A" to make sure the field is exported.
			Type:      reflect.TypeOf(json.RawMessage{}),
			Tag:       reflect.StructTag(fmt.Sprintf("json:\"%s\"", k)), // Fix the field.
			Index:     []int{len(fields)},
			Anonymous: false,
		}
		fields = append(fields, field)
	}
	// Create instance of our new dynamic type.
	typ := reflect.StructOf(fields)
	inst := reflect.New(typ)
	// Copy the values from our typed fields.
	for i := 0; i < reflect.TypeOf(output).NumField(); i++ {
		inst.Elem().FieldByName(reflect.TypeOf(output).Field(i).Name).Set(reflect.ValueOf(output).Field(i))
	}
	// Copy the values from our untyped fields.
	for k, v := range c.UntypedClaims {
		inst.Elem().FieldByName(fmt.Sprintf("A%s", k)).Set(reflect.ValueOf(v))
	}
	return json.Marshal(inst.Interface())
}

//Jwt defines a Jave web token
type Jwt struct {
	Header    JwsHeader
	Claims    JwtClaims
	Signature []byte
}

//Verify JWT is valid or error
func (jwt *Jwt) Verify() error {
	if jwt.Header.Typ != JwtType {
		/* Not a JWT. */
		return ErrJwtFormat
	}
	if jwt.Header.Cty != "" && jwt.Header.Cty != JwtType {
		return ErrJwtFormat

	}
	for k := range jwt.Claims.UntypedClaims {
		if _, invalid := reservedJwtClaims[k]; invalid {
			return ErrJwkReservedClaimName
		}
	}
	return nil
}

//MarshalBody representation of the JWT Header and Claims.
func (jwt *Jwt) MarshalBody() (body string, err error) {
	if err = jwt.Verify(); err != nil {
		return
	}
	jws := Jws{
		Header:  &jwt.Header,
		Payload: &jwt.Claims,
	}
	return jws.MarshalBody()
}

//Unmarshal string to JWT body, or error
func (jwt *Jwt) Unmarshal(src string) (body string, err error) {
	/* Compact JWT encoding. */
	/* Default Exp field to maximum in case it is not set. */
	jwt.Claims.Expiration = math.MaxInt64
	jws := Jws{
		Header:  &jwt.Header,
		Payload: &jwt.Claims,
	}
	if body, err = jws.Unmarshal(src); err != nil {
		return
	}
	// Ick some copying here but do we really care?
	jwt.Signature = make([]byte, len(jws.Signature))
	_ = copy(jwt.Signature, jws.Signature)
	if err = jwt.Verify(); err != nil {
		body = ""
		return
	}
	return
}
