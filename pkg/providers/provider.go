// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

// Package providers implements Kubernetes KMS v2 backends for k8s-kms-plugin,
// including the PKCS#11/HSM-backed Provider in p11.go.
package providers

import (
	"context"

	"github.com/eclipse-keypont/gose/jose"
	"google.golang.org/grpc"

	k8skmsv2 "k8s.io/kms/apis/v2"
)

var (
	kekKeyOps = []jose.KeyOps{jose.KeyOpsDecrypt, jose.KeyOpsEncrypt}
)

// Provider is a Kubernetes KMS v2 backend (e.g. PKCS#11/HSM) that serves
// EncryptRequest/DecryptRequest/StatusRequest and can be wired into a gRPC
// server via UnaryInterceptor.
type Provider interface {
	k8skmsv2.KeyManagementServiceServer
	UnaryInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error)
}
