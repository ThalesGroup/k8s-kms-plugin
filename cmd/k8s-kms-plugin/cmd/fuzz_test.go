// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// FuzzAlgorithmFamilySet drives the --algorithm-family flag parser with arbitrary strings.
//
// This value crosses into the PKCS#11 stack, which is cgo, so a value that slips past
// validation does not stay in Go. The property asserted is that AlgorithmFamily.Set is a gate,
// not a filter: it either rejects the input or stores it verbatim, never silently coercing a
// near-miss like "AES-GCM" or "aes-gcm\n" into a supported family.
func FuzzAlgorithmFamilySet(f *testing.F) {
	f.Add("aes-gcm")
	f.Add("AES-GCM")
	f.Add("ml-kem")
	f.Add("ml-kem\n")
	f.Add(" rsa-oaep ")
	f.Add("")

	supported := map[string]bool{
		string(AlgorithmFamilyAESGCM):  true,
		string(AlgorithmFamilyAESCBC):  true,
		string(AlgorithmFamilyRSAOAEP): true,
		string(AlgorithmFamilyMLKEM):   true,
	}

	f.Fuzz(func(t *testing.T, value string) {
		var alg AlgorithmFamily
		err := alg.Set(value)

		if supported[value] != (err == nil) {
			t.Fatalf("AlgorithmFamily.Set(%q) returned err=%v, but supported=%v", value, err, supported[value])
		}
		if err != nil {
			if alg != "" {
				t.Fatalf("AlgorithmFamily.Set(%q) failed but still stored %q", value, alg)
			}
			return
		}
		if alg.String() != value {
			t.Fatalf("AlgorithmFamily.Set(%q) stored %q; the flag value must round-trip verbatim", value, alg.String())
		}
	})
}

// FuzzUnmarshalSubMergedE drives the config-file path with arbitrary YAML.
//
// UnmarshalSubMergedE reimplements part of viper's priority chain by hand (GetStringMap →
// MergeConfigMap → Unmarshal), so it handles config shapes viper's own Sub() never sees:
// a "serve" key that is a scalar rather than a map, deeply nested maps, non-string keys,
// duplicate keys. Any of those reaching MergeConfigMap is a plausible panic source, and a
// malformed config file must produce an error rather than take the process down.
//
// The target asserts the crash-freedom contract only. Which config wins is a priority-chain
// question the table tests in serve_test.go already cover with realistic inputs.
func FuzzUnmarshalSubMergedE(f *testing.F) {
	f.Add("serve:\n  p11-lib: /usr/lib/softhsm/libsofthsm2.so\n  p11-slot: 0\n")
	f.Add("serve:\n  algorithm-family: ml-kem\n  p11-key-id: dca85912cc5e712d\n")
	f.Add("serve: not-a-map\n")               // section is a scalar
	f.Add("serve:\n  p11-slot: not-an-int\n") // type mismatch against ViperFlagsServe
	f.Add("serve:\n  serve:\n    serve: {}\n")
	f.Add("serve: {}\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, config string) {
		v := viper.New()
		v.SetConfigType("yaml")
		if err := v.ReadConfig(strings.NewReader(config)); err != nil {
			return // not valid YAML; the CLI rejects it before UnmarshalSubMergedE is reached
		}

		// ConfigFileUsed() is empty for ReadConfig, which short-circuits UnmarshalSubMergedE at
		// step 1. Set a path so the fuzzer reaches the GetStringMap/MergeConfigMap logic that is
		// the point of this target.
		v.SetConfigFile("fuzz.yaml")

		var target ViperFlagsServe
		// An error is a valid outcome for malformed config; a panic is not.
		_ = UnmarshalSubMergedE(v, "serve", &target)
	})
}
