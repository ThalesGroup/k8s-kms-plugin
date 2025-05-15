/*
 * Copyright 2025 Thales
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package version

import (
	"encoding/json"
	"fmt"

	go_version "github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// populated by the Go LDFLAGS at build
var (
	RawGitDescribe     string
	GitDirtyStr        string // "true" or "false" but as strings as they are retrieved from git bash
	GitCommitIdShort   string
	GitCommitIdLong    string
	GitCommitTimestamp string
	GoVersion          string
	BuildPlatform      string
	BuildDate          string
)

// VersionDetails represents the JSON & YAML output structure.
type VersionDetails struct {
	VersionData VersionData `json:"cobravsviper" yaml:"cobravsviper"`
}

// VersionData holds structured versioning details.
type VersionData struct {
	Major              uint64 `json:"major" yaml:"major"`
	Minor              uint64 `json:"minor" yaml:"minor"`
	Patch              uint64 `json:"patch" yaml:"patch"`
	Version            string `json:"version" yaml:"version"` // raw git describe
	IsGitDirty         bool   `json:"isGitDirty" yaml:"isGitDirty"`
	GitCommitIdLong    string `json:"gitCommitIdLong" yaml:"gitCommitIdLong"`
	GitCommitIdShort   string `json:"gitCommitIdShort" yaml:"gitCommitIdShort"`
	GitCommitTimestamp string `json:"gitCommitTimestamp" yaml:"gitCommitTimestamp"`
	GoVersion          string `json:"goVersion" yaml:"goVersion"`
	BuildDate          string `json:"buildDate" yaml:"buildDate"`
	BuildPlatform      string `json:"buildPlatform" yaml:"buildPlatform"`
}

// IsPopulated checks if the global variables for version information are populated.
// Returns true if at least RawGitDescribe is not empty, false otherwise.
// If false, most probably this is an issue with LDFLAGS.
func IsPopulated() bool {
	return RawGitDescribe != ""
}

// IsDirty takes a string from a build flag and returns a boolean indicating whether
// the build is from a dirty git tree.
func IsDirty(isDirtyStr string) (bool, error) {
	switch isDirtyStr {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		logrus.WithField("GitDirtyStr", isDirtyStr).Warn("Unexpected Git dirty string, assuming clean")
		return false, fmt.Errorf("invalid dirty information: %s", GitDirtyStr)
	}
}

// unset (zero v0.0.0).
func NewVersionData() (VersionData, error) {
	// this is a minimal content of the VersionData information
	versionData := VersionData{
		Version:            RawGitDescribe,
		GitCommitIdLong:    GitCommitIdLong,
		GitCommitIdShort:   GitCommitIdShort,
		GitCommitTimestamp: GitCommitTimestamp,
		GoVersion:          GoVersion,
		BuildDate:          BuildDate,
		BuildPlatform:      BuildPlatform,
	}

	// add the git state dirty true or false
	isDirty, err := IsDirty(GitDirtyStr)
	if err != nil {
		// only do a warning, do not return an error
		logrus.WithError(err).Warning("Failed to parse Git dirty status")
	}
	versionData.IsGitDirty = isDirty

	// Check if RawGitDescribe is a valid semantic version or a commit hash
	version, err := go_version.NewSemver(RawGitDescribe)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"raw_git_describe": RawGitDescribe,
			"error":            err,
		}).Debug("Invalid semantic versioning, falling back to snapshot version")
		return versionData, nil
	}

	// If version parsing is successful, populate the major, minor, and patch fields
	versionSegments := version.Segments()
	if len(versionSegments) < 3 {
		err = fmt.Errorf("raw git describe --tags --always version %s is not parsable as "+
			"semantic versioning. Expected 3 segments (major, minor, patch) but got %d",
			RawGitDescribe, len(versionSegments))
		return versionData, err
	}

	// set major, minor and patch to values that have been parsed by go_version
	versionData.Major = uint64(versionSegments[0])
	versionData.Minor = uint64(versionSegments[1])
	versionData.Patch = uint64(versionSegments[2])

	return versionData, nil
}

// NewVersionDetails creates a new VersionDetails object using NewVersionData.
func NewVersionDetails() (VersionDetails, error) {
	versionData, err := NewVersionData()
	if err != nil {
		return VersionDetails{}, err
	}
	return VersionDetails{VersionData: versionData}, nil
}

// returnJsonVersion returns the version as a JSON object.
func returnJsonVersion(prettyPrint bool) ([]byte, error) {
	versionDetails, err := NewVersionDetails()
	if err != nil {
		return nil, err
	}

	if prettyPrint {
		return json.MarshalIndent(versionDetails, "", "  ")
	}
	return json.Marshal(versionDetails)
}

// returnYamlVersion returns the version as a YAML object.
func returnYamlVersion() ([]byte, error) {
	versionDetails, err := NewVersionDetails()
	if err != nil {
		return nil, err
	}

	yamlData, err := yaml.Marshal(versionDetails)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal YAML")
		return nil, err
	}
	return yamlData, nil
}

// LogrusOutputVersion logs the version details at server startup. For server logging.
func LogrusOutputVersion() {
	versionData, err := NewVersionData()
	if err != nil {
		logrus.WithError(err).Error("Failed to fetch version data")
		return
	}

	logrus.Infof("cobravsviper version: %s", versionData.Version)
	logrus.WithFields(logrus.Fields{
		"build-date":       versionData.BuildDate,
		"build-platform":   versionData.BuildPlatform,
		"commit":           versionData.GitCommitIdLong,
		"go-version":       versionData.GoVersion,
		"raw-git-describe": versionData.Version,
		"is-git-dirty":     versionData.IsGitDirty,
		"short-commit":     versionData.GitCommitIdShort,
	}).Debug("cobravsviper version details")
}

// VersionOutputToString returns the version as a formatted string.
func VersionOutputToString(outputFormat string, prettyPrint bool) string {
	switch outputFormat {
	case "json":
		data, err := returnJsonVersion(prettyPrint)
		if err != nil {
			logrus.WithError(err).Error("Failed to generate JSON version output")
			return "Error generating JSON output"
		}
		return string(data)
	case "yaml":
		data, err := returnYamlVersion()
		if err != nil {
			logrus.WithError(err).Error("Failed to generate YAML version output")
			return "Error generating YAML output"
		}
		return string(data)
	default:
		version, err := go_version.NewSemver(RawGitDescribe)
		if err != nil {
			logrus.WithError(err).Debug("Invalid semantic versioning, falling back to snapshot version")
			return fmt.Sprintf("cobravsviper: (snapshot) %s", RawGitDescribe)
		}

		return fmt.Sprintf("cobravsviper: %s", version.String())
	}
}
