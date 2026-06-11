/*
 * Copyright 2026 Thales Group
 * SPDX-License-Identifier: MIT
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSanitizeViperFlagsRotation_Valid(t *testing.T) {
	f := &ViperFlagsRotation{OldAlgorithmFamily: "aes-gcm"}
	assert.NoError(t, sanitizeViperFlagsRotation(f))
}

func TestSanitizeViperFlagsRotation_InvalidAlgorithm(t *testing.T) {
	f := &ViperFlagsRotation{OldAlgorithmFamily: "unknown"}
	err := sanitizeViperFlagsRotation(f)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--old-algorithm-family")
}

// TestSanitizeViperFlagsRotation_LabelLimits verifies that oversized old-KEK labels
// are rejected with flag-prefixed error messages.
func TestSanitizeViperFlagsRotation_LabelLimits(t *testing.T) {
	atLimit := strings.Repeat("a", maxCkaLabelBytes)
	overLimit := strings.Repeat("a", maxCkaLabelBytes+1)

	cases := []struct {
		name    string
		flags   ViperFlagsRotation
		wantErr string
	}{
		{
			"labels at limit",
			ViperFlagsRotation{
				OldAlgorithmFamily: "aes-gcm",
				OldP11Label:        atLimit,
				OldDekKeyLabel:     atLimit,
				OldHmacKeyLabel:    atLimit,
			},
			"",
		},
		{
			"old-p11-label over limit",
			ViperFlagsRotation{OldAlgorithmFamily: "aes-gcm", OldP11Label: overLimit},
			"--old-p11-label",
		},
		{
			"old-p11-key-label over limit",
			ViperFlagsRotation{OldAlgorithmFamily: "aes-gcm", OldDekKeyLabel: overLimit},
			"--old-p11-key-label",
		},
		{
			"old-p11-hmac-label over limit",
			ViperFlagsRotation{OldAlgorithmFamily: "aes-gcm", OldHmacKeyLabel: overLimit},
			"--old-p11-hmac-label",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := sanitizeViperFlagsRotation(&tc.flags)
			if tc.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
			}
		})
	}
}
