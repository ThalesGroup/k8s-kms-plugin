package version

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestGetVersionData(t *testing.T) {
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
			versionData, err := getVersionData()

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

func init() {
	// Disable logrus output for testing purposes
	logrus.SetOutput(logrus.New().Writer())
}
