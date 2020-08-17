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

package kms

import (
	"encoding/json"
	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/go-openapi/validate"
)

/* polymorph cert cert false */

/* polymorph cert fingerprint false */

/* polymorph cert kind false */

/* polymorph cert modified false */

/* polymorph cert name false */

/* polymorph cert parent false */

/* polymorph cert public false */

/* polymorph cert revoked false */

// Validate validates this cert
func (m *Cert) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validateKind(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if err := m.validateName(formats); err != nil {
		// prop
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

var certTypeKindPropEnum []interface{}

func init() {
	var res []string
	if err := json.Unmarshal([]byte(`["client","server","root","intermediate"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		certTypeKindPropEnum = append(certTypeKindPropEnum, v)
	}
}

const (
	// CertKindClient captures enum value "client"
	CertKindClient string = "client"
	// CertKindServer captures enum value "server"
	CertKindServer string = "server"
	// CertKindRoot captures enum value "root"
	CertKindRoot string = "root"
	// CertKindIntermediate captures enum value "intermediate"
	CertKindIntermediate string = "intermediate"
)

// prop value enum
func (m *Cert) validateKindEnum(path, location string, value string) error {
	if err := validate.Enum(path, location, value, certTypeKindPropEnum); err != nil {
		return err
	}
	return nil
}

func (m *Cert) validateKind(formats strfmt.Registry) error {

	if swag.IsZero(m.Kind) { // not required
		return nil
	}

	// value enum
	if err := m.validateKindEnum("kind", "body", m.Kind.String()); err != nil {
		return err
	}

	return nil
}

func (m *Cert) validateName(formats strfmt.Registry) error {

	if swag.IsZero(m.Name) { // not required
		return nil
	}

	if err := validate.MinLength("name", "body", string(m.Name), 1); err != nil {
		return err
	}

	return nil
}

// MarshalBinary interface implementation
func (m *Cert) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *Cert) UnmarshalBinary(b []byte) error {
	var res Cert
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
