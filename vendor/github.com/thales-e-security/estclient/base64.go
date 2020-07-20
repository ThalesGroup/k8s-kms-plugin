// Copyright 2019 Thales eSecurity
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package estclient

import (
	"encoding/base64"
	"strings"
)

const (
	base64LineLength = 64
)

// minInt returns the smallest value of x and y.
func minInt(x, y int) int {
	if x < y {
		return x
	}
	return y
}

// hardWrap wraps a string precisely to the limit, breaking words
// as necessary. The resulting string will always end with a line
// break.
func hardWrap(text string, limit int) string {
	var b strings.Builder

	for j := 0; j < len(text)-1; j += limit {
		upperBound := minInt(j+limit, len(text))
		b.WriteString(text[j:upperBound])
		b.WriteString("\n")
	}

	return b.String()
}

// toBase64 converts bytes to base64, wrapped at 64 chars
func toBase64(data []byte) string {
	return hardWrap(base64.StdEncoding.EncodeToString(data), base64LineLength)
}
