// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

// Package main is the entry point for the k8s-kms-plugin binary.
package main

import "github.com/eclipse-keysealer/k8s-kms-plugin/cmd/k8s-kms-plugin/cmd"

func main() {
	cmd.Execute()
}
