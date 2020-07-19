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

package ca

import (
	"github.com/ThalesIgnite/crypto11"
	"github.com/ThalesIgnite/gose/jose"
	"github.com/go-openapi/runtime/middleware"
	"github.com/golang/glog"
	"github.com/thalescpl-io/k8s-kms-plugin/pkg/est/restapi/operations/operation"
	"os"
)

// P11 CA for RFC7030 based enrollment/registration of services/machines/devices
type P11 struct {
	key    string
	cert   string
	ctxt11 *crypto11.Context
	config *crypto11.Config
	rootCA jose.Jwk
	intCA  jose.Jwk
}

func (e *P11) GetCACerts(params operation.GetCACertsParams) middleware.Responder {
	panic("implement me")
}

func (e *P11) SimpleEnroll(params operation.SimpleenrollParams, principal interface{}) middleware.Responder {
	panic("implement me")
}

func (e *P11) SimpleReenroll(params operation.SimplereenrollParams) middleware.Responder {
	panic("implement me")
}

func NewEST(key, cert string, config *crypto11.Config) (e *P11, err error) {

	e = &P11{
		key:    key,
		cert:   cert,
		config: config,
	}
	if e.ctxt11, err = crypto11.Configure(e.config); err != nil {
		return
	}
	// se if our local TLS key is here so we can load or bootstrap the TLS
	var i os.FileInfo
	if i, err = os.Stat(e.key); err != nil {
		glog.Fatalln(err)
		return
	}
	glog.Info(i)
	return
}
