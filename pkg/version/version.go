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
	"fmt"

	go_version "github.com/hashicorp/go-version"
	"log/slog"
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
	VersionData VersionData `json:"k8s-kms-plugin" yaml:"k8s-kms-plugin"`
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
		slog.Warn("Unexpected Git dirty string, assuming clean", "GitDirtyStr", isDirtyStr)
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
		slog.Warn("Failed to parse Git dirty status", "error", err)
	}
	versionData.IsGitDirty = isDirty

	// Check if RawGitDescribe is a valid semantic version or a commit hash
	version, err := go_version.NewSemver(RawGitDescribe)
	if err != nil {
		slog.Debug("Invalid semantic versioning, falling back to snapshot version", "raw_git_describe", RawGitDescribe, "error", err)
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
		slog.Error("Failed to marshal YAML", "error", err)
		return nil, err
	}
	return yamlData, nil
}

// LogVersion logs the version details at server startup.
func LogVersion() {
	versionData, err := NewVersionData()
	if err != nil {
		slog.Error("Failed to fetch version data", "error", err)
		return
	}

	slog.Info(fmt.Sprintf("k8s-kms-plugin version: %s", versionData.Version))
	slog.Debug("k8s-kms-plugin version details",
		"build-date", versionData.BuildDate,
		"build-platform", versionData.BuildPlatform,
		"commit", versionData.GitCommitIdLong,
		"go-version", versionData.GoVersion,
		"raw-git-describe", versionData.Version,
		"is-git-dirty", versionData.IsGitDirty,
		"short-commit", versionData.GitCommitIdShort,
	)
}

// VersionOutputToString returns the version as a formatted string.
func VersionOutputToString(outputFormat string, prettyPrint bool) string {
	switch outputFormat {
	case "json":
		data, err := returnJsonVersion(prettyPrint)
		if err != nil {
			slog.Error("Failed to generate JSON version output", "error", err)
			return "Error generating JSON output"
		}
		return string(data)
	case "yaml":
		data, err := returnYamlVersion()
		if err != nil {
			slog.Error("Failed to generate YAML version output", "error", err)
			return "Error generating YAML output"
		}
		return string(data)
	default:
		version, err := go_version.NewSemver(RawGitDescribe)
		if err != nil {
			slog.Debug("Invalid semantic versioning, falling back to snapshot version", "error", err)
			return fmt.Sprintf("k8s-kms-plugin: (snapshot) %s", RawGitDescribe)
		}

		return fmt.Sprintf("k8s-kms-plugin: %s", version.String())
	}
}
