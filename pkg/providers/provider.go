/*
 * Copyright 2025 Thales Group
 * SPDX-License-Identifier: MIT
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package providers

import (
	"context"
	"errors"

	"github.com/ThalesGroup/gose/jose"
	"google.golang.org/grpc"

	istio "github.com/ThalesGroup/k8s-kms-plugin/apis/istio/v1"
	k8skmsv2 "k8s.io/kms/apis/v2"
)

var (
	kekKeyOps     = []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}
	dekKeyOps     = []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}
	sKeyKeyOps    = []jose.KeyOps{jose.KeyOpsSign, jose.KeyOpsVerify}
	ErrNoSuchKey  = errors.New("no such key")
	ErrNoSuchCert = errors.New("no such cert")
)

type Config struct {
	CaKid  []byte
	KekKid []byte
}
type Provider interface {
	k8skmsv2.KeyManagementServiceServer
	istio.KeyManagementServiceServer
	// Ad
	UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error)
}
