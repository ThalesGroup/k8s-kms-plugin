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

package consumers

import (
	b64 "encoding/base64"
	"github.com/fullsailor/pkcs7"
	"github.com/go-openapi/runtime"
	"io"
	"io/ioutil"
)

//PKCS10Consumer reads the response into a DER formatted output
func PKCS10Consumer() runtime.ConsumerFunc {

	return func(reader io.Reader, i interface{}) (err error) {

		var src, data []byte
		if src, err = ioutil.ReadAll(reader); err != nil {
			return
		}
		_, err = b64.StdEncoding.Decode(data, src)
		i = data
		return
	}
}

//PKCS7Consumer puts the product into a PKCS7 Object decode
func PKCS7Consumer() runtime.ConsumerFunc {
	return func(reader io.Reader, i interface{}) (err error) {

		//Convert "i" from base64 to pkcs7 object to then

		var src,dst []byte
		if src, err = ioutil.ReadAll(reader); err != nil {
			return
		}
		_, err = b64.StdEncoding.Decode(dst,src)
		if err != nil {
			panic(err)
		}

		i, err = pkcs7.Parse(dst)
		if err != nil {
			panic(err)
		}
		return
	}
}
