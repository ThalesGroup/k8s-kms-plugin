/*
 * Copyright 2025 Thales Group
 * SPDX-License-Identifier: MIT
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package version

import (
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Reset global vars before each test if needed
func resetGlobals() {
	RawGitDescribe = ""
	GitDirtyStr = ""
	GitCommitIdShort = ""
	GitCommitIdLong = ""
	GitCommitTimestamp = ""
	GoVersion = ""
	BuildDate = ""
	BuildPlatform = ""
}

// TestNewVersionData tests the NewVersionData function by providing a set of
// raw Git describe strings and verifying the parsed major, minor, and patch
// version numbers. It handles both valid semantic versions and non-semantic
// or invalid versions, checking for expected parsing errors where applicable.

func TestNewVersionData(t *testing.T) {
	tests := []struct {
		rawGitDescribe string
		expectedMajor  uint64
		expectedMinor  uint64
		expectedPatch  uint64
		expectError    bool
	}{
		// Standard semantic versions
		{
			rawGitDescribe: "1.2.3",
			expectedMajor:  1,
			expectedMinor:  2,
			expectedPatch:  3,
			expectError:    false,
		},
		{
			rawGitDescribe: "1.2",
			expectedMajor:  1,
			expectedMinor:  2,
			expectedPatch:  0,
			expectError:    false,
		},
		{
			rawGitDescribe: "1.2.3-e9a0516",
			expectedMajor:  1,
			expectedMinor:  2,
			expectedPatch:  3,
			expectError:    false,
		},
		{
			rawGitDescribe: "1.2.3-rc1",
			expectedMajor:  1,
			expectedMinor:  2,
			expectedPatch:  3,
			expectError:    false,
		},
		{
			rawGitDescribe: "1.2.3-rc.1",
			expectedMajor:  1,
			expectedMinor:  2,
			expectedPatch:  3,
			expectError:    false,
		},
		{
			rawGitDescribe: "1.2.3-alpha.1",
			expectedMajor:  1,
			expectedMinor:  2,
			expectedPatch:  3,
			expectError:    false,
		},
		{
			rawGitDescribe: "1.2.3-beta",
			expectedMajor:  1,
			expectedMinor:  2,
			expectedPatch:  3,
			expectError:    false,
		},
		{
			rawGitDescribe: "1.2.3-beta.2",
			expectedMajor:  1,
			expectedMinor:  2,
			expectedPatch:  3,
			expectError:    false,
		},

		// Invalid or non-semantic versions
		{
			rawGitDescribe: "e9a0516",
			expectedMajor:  0,
			expectedMinor:  0,
			expectedPatch:  0,
			expectError:    false,
		},
		{
			rawGitDescribe: "9a05166",
			expectedMajor:  0,
			expectedMinor:  0,
			expectedPatch:  0,
			expectError:    false,
		},
		{
			rawGitDescribe: "1.2.3+build5678",
			expectedMajor:  1,
			expectedMinor:  2,
			expectedPatch:  3,
			expectError:    false,
		},
		{
			rawGitDescribe: "1.2.3-beta+build5678",
			expectedMajor:  1,
			expectedMinor:  2,
			expectedPatch:  3,
			expectError:    false,
		},
		{
			rawGitDescribe: "1.2.3-beta.2+build5678",
			expectedMajor:  1,
			expectedMinor:  2,
			expectedPatch:  3,
			expectError:    false,
		},
		{
			rawGitDescribe: "1.2.3+build5678-beta.2",
			expectedMajor:  1,
			expectedMinor:  2,
			expectedPatch:  3,
			expectError:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.rawGitDescribe, func(t *testing.T) {
			RawGitDescribe = test.rawGitDescribe

			// Call the function
			versionData, err := NewVersionData()

			// Check for error
			if test.expectError {
				assert.NotNil(t, err, "Expected error for RawGitDescribe: "+test.rawGitDescribe)
			} else {
				assert.Nil(t, err, "Unexpected error for RawGitDescribe: "+test.rawGitDescribe)
			}

			// Validate version
			assert.Equal(t, test.expectedMajor, versionData.Major)
			assert.Equal(t, test.expectedMinor, versionData.Minor)
			assert.Equal(t, test.expectedPatch, versionData.Patch)
		})
	}
}

// TestIsDirty exercises the IsDirty function against a set of test cases.
// It checks that the correct boolean value is returned and that an error is
// returned when the input string is neither "true" nor "false".
func TestIsDirty(t *testing.T) {
	cases := []struct {
		input    string
		expected bool
		hasError bool
	}{
		{"true", true, false},
		{"false", false, false},
		{"maybe", false, true}, // default fallback
	}

	for _, c := range cases {
		result, err := IsDirty(c.input)
		if result != c.expected || (err != nil) != c.hasError {
			t.Errorf("IsDirty(%q) = %v, err = %v, expected %v, error? %v",
				c.input, result, err, c.expected, c.hasError)
		}
	}
}

// TestNewVersionData_Defaults tests the NewVersionData function with all global
// variables set to zero values. The test ensures that the function does not
// return an error and that the IsGitDirty flag is set to false when the dirty
// string is empty or invalid.
func TestNewVersionData_Defaults(t *testing.T) {
	resetGlobals()

	data, err := NewVersionData()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if data.IsGitDirty != false {
		t.Errorf("Expected IsGitDirty to be false when dirty string is empty or invalid")
	}
}

// TestVersionOutput_JSON tests the VersionOutputToString function with a full
// set of non-zero global variables. The test ensures that the function returns
// a JSON object with all the expected fields.
func TestVersionOutput_JSON(t *testing.T) {
	resetGlobals()

	RawGitDescribe = "v0.1.2"
	GitDirtyStr = "false"
	GitCommitIdLong = "abc123"
	GitCommitIdShort = "abc"
	GitCommitTimestamp = "2025-01-01T00:00:00Z"
	GoVersion = "go1.23"
	BuildDate = "2025-01-01T01:00:00Z"
	BuildPlatform = "amd64"

	out := VersionOutputToString("json", true)
	if !strings.Contains(out, `"version": "v0.1.2"`) {
		t.Errorf("Output missing version: %s", out)
	}
}

// TestVersionOutput_YAML tests the VersionOutputToString function with a full
// set of non-zero global variables and output format set to "yaml". The test
// ensures that the function returns a YAML object with all the expected fields.
func TestVersionOutput_YAML(t *testing.T) {
	resetGlobals()

	GitDirtyStr = "true"
	RawGitDescribe = "v0.1.2"
	out := VersionOutputToString("yaml", false)

	if !strings.Contains(out, "version: v0.1.2") {
		t.Errorf("Expected YAML output to include version, got: %s", out)
	}
}

// TestReturnJsonVersion_Valid tests the returnJsonVersion function with a valid
// set of global variables (version, dirty string). The test ensures that the
// function returns a valid JSON object without any error.
func TestReturnJsonVersion_Valid(t *testing.T) {
	resetGlobals()
	RawGitDescribe = "v1.2.3"
	GitDirtyStr = "false"

	out, err := returnJsonVersion(false)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	var v VersionDetails
	err = json.Unmarshal(out, &v)
	if err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}
}

// Ensure the JSON output starts with k8s-kms-plugin as a top-level key
func TestTopLevelKey_JSON(t *testing.T) {
	resetGlobals()
	RawGitDescribe = "v0.3.0"
	GitDirtyStr = "true"

	data, err := returnJsonVersion(false)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.Contains(string(data), `"k8s-kms-plugin":`) {
		t.Errorf("Expected top-level key 'k8s-kms-plugin' in JSON: %s", data)
	}
}

// Ensure the YAML output starts with k8s-kms-plugin as a top-level key
func TestTopLevelKey_YAML(t *testing.T) {
	resetGlobals()
	RawGitDescribe = "v0.3.0"
	GitDirtyStr = "true"

	data, err := returnYamlVersion()
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !strings.Contains(string(data), "k8s-kms-plugin:\n") {
		t.Errorf("Expected top-level key 'k8s-kms-plugin' in YAML: %s", data)
	}
}

// Validate that VersionDetails can be marshaled and unmarshaled without data loss
func TestVersionDetailsRoundTrip(t *testing.T) {
	resetGlobals()
	RawGitDescribe = "v0.3.0"
	GitDirtyStr = "true"
	GitCommitIdShort = "abc123"
	GitCommitIdLong = "abc123456"
	GitCommitTimestamp = "2025-04-15T00:00:00Z"
	GoVersion = "go1.23"
	BuildDate = "2025-04-15T01:00:00Z"
	BuildPlatform = "x86_64"

	jsonData, err := returnJsonVersion(false)
	if err != nil {
		t.Fatalf("Error generating JSON: %v", err)
	}

	var details VersionDetails
	if err := json.Unmarshal(jsonData, &details); err != nil {
		t.Fatalf("Error parsing JSON: %v", err)
	}

	if details.VersionData.Version != "v0.3.0" {
		t.Errorf("Expected version v0.3.0, got %s", details.VersionData.Version)
	}
	if !details.VersionData.IsGitDirty {
		t.Errorf("Expected GitDirty true, got false")
	}
}

func TestIsPopulated(t *testing.T) {
	resetGlobals()
	if IsPopulated() {
		t.Error("Expected IsPopulated to be false when RawGitDescribe is empty")
	}

	RawGitDescribe = "v1.0.0"
	if !IsPopulated() {
		t.Error("Expected IsPopulated to be true when RawGitDescribe is set")
	}
}

func init() {
	// Discard slog output during tests
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
}
