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

package k8s

import (
	"context"
	"fmt"
	"google.golang.org/grpc"
	"time"
)

func GetClientTCP(host string, port int64) (ctx context.Context, cancel context.CancelFunc, c KeyManagementServiceClient, err error) {
	// Get Client
	options := []grpc.DialOption{grpc.WithInsecure()}
	var conn *grpc.ClientConn
	if conn, err = grpc.Dial(fmt.Sprintf("dns:///%s:%d", host, port), options...); err != nil {
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	c = NewKeyManagementServiceClient(conn)
	return
}

func GetClientSocket(socket string) (ctx context.Context, cancel context.CancelFunc, c KeyManagementServiceClient, err error) {
	// Get Client
	options := []grpc.DialOption{grpc.WithInsecure()}
	var conn *grpc.ClientConn
	if conn, err = grpc.Dial(fmt.Sprintf("unix:///%s", socket), options...); err != nil {
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	c = NewKeyManagementServiceClient(conn)
	return
}
