// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

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
