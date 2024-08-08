// MIT License
//
// Copyright (c) 2024 Thales. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

package version

import (
	"encoding/json"
	"fmt"

	go_version "github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

// populated by the LDFLAGS at build
var (
	RawGitDescribe     string
	GitCommitIdShort   string
	GitCommitIdLong    string
	GitCommitTimestamp string
	GoVersion          string
	BuildPlatform      string
	BuildDate          string
)

// VersionOutput represents the JSON output structure.
type VersionOutput struct {
	VersionData VersionData `json:"k8s-kms-plugin-cli"`
}

// VersionData holds structured versioning details.
type VersionData struct {
	Major              uint64 `json:"major"`
	Minor              uint64 `json:"minor"`
	Patch              uint64 `json:"patch"`
	Version            string `json:"version"`
	GitCommitIdLong    string `json:"gitCommitIdLong"`
	GitCommitIdShort   string `json:"gitCommitIdShort"`
	GitCommitTimestamp string `json:"gitCommitTimestamp"`
	GoVersion          string `json:"goVersion"`
	BuildDate          string `json:"buildDate"`
	BuildPlatform      string `json:"buildPlatform"`
}

// getVersionData returns a VersionData struct with information from git
// from LDFLAGS such as the raw git describe output, git commit ID (long and
// short) and commit timestamp, Go version, build date, and build platform. It parses
// the raw git describe output and converts it into semantic versioning (major,
// minor, patch) and stores it in the VersionData struct. If the raw git describe
// output is not parsable as semantic versioning, it sets the major, minor, and
// patch fields to 0 and returns an error.
func getVersionData() (VersionData, error) {
	logrus.WithFields(logrus.Fields{
		"raw-git-describe":     RawGitDescribe,
		"git-commit-id-long":   GitCommitIdLong,
		"git-commit-id-short":  GitCommitIdShort,
		"git-commit-timestamp": GitCommitTimestamp,
		"go-version":           GoVersion,
		"build-date":           BuildDate,
		"build-platform":       BuildPlatform,
	}).Debug("check LDFLAGS values")

	// Initialize VersionData to hold information from git from LDFLAGS
	versionData := VersionData{
		Version:            RawGitDescribe,
		GitCommitIdLong:    GitCommitIdLong,
		GitCommitIdShort:   GitCommitIdShort,
		GitCommitTimestamp: GitCommitTimestamp,
		GoVersion:          GoVersion,
		BuildDate:          BuildDate,
		BuildPlatform:      BuildPlatform,
	}

	// Check if RawGitDescribe is a valid semantic version or a commit hash
	version, err := go_version.NewSemver(RawGitDescribe)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"raw_git_describe": RawGitDescribe,
			"error":            err,
		}).Debug("Invalid semantic versioning, falling back to snapshot version and setting major.minor.patch to 0.0.0")
		versionData.Major = uint64(0)
		versionData.Minor = uint64(0)
		versionData.Patch = uint64(0)
		return versionData, nil // Return nil error because we are treating it as a "snapshot" version
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

// returnJsonVersion returns the version as a JSON object.
func returnJsonVersion(prettyPrint bool) ([]byte, error) {
	versionOutput, err := getVersionData()
	if err != nil {
		return nil, err
	}

	if prettyPrint {
		return json.MarshalIndent(versionOutput, "", "  ")
	}
	return json.Marshal(versionOutput)
}

// returnYamlVersion returns the version as a YAML object.
func returnYamlVersion() ([]byte, error) {
	jsonData, err := returnJsonVersion(false)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal JSON for YAML conversion")
		return nil, err
	}

	var data map[string]interface{}
	if err := json.Unmarshal(jsonData, &data); err != nil {
		logrus.WithError(err).Error("Failed to unmarshal JSON for YAML conversion")
		return nil, err
	}

	yamlData, err := yaml.Marshal(data)
	if err != nil {
		logrus.WithError(err).Error("Failed to marshal YAML")
		return nil, err
	}
	return yamlData, nil
}

// LogrusOutput logs the version details at startup. For server logging.
func LogrusOutput() {
	versionData, err := getVersionData()
	if err != nil {
		logrus.WithError(err).Error("Failed to fetch version data")
		return
	}

	logrus.Infof("k8s-kms-plugin version: %s", versionData.Version)
	logrus.WithFields(logrus.Fields{
		"commit":         versionData.GitCommitIdLong,
		"short-commit":   versionData.GitCommitIdShort,
		"build-date":     versionData.BuildDate,
		"build-platform": versionData.BuildPlatform,
		"go-version":     versionData.GoVersion,
	}).Debug("k8s-kms-plugin version details")
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
			return fmt.Sprintf("k8s-kms-plugin: (snapshot) %s", RawGitDescribe)
		}

		return fmt.Sprintf("k8s-kms-plugin: %s", version.String())
	}
}
