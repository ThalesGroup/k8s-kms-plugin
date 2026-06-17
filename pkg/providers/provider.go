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

	"github.com/ThalesGroup/gose/jose"
	"google.golang.org/grpc"

	k8skmsv2 "k8s.io/kms/apis/v2"
)

var (
	kekKeyOps = []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}
)

type Provider interface {
	k8skmsv2.KeyManagementServiceServer
	UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error)
}
