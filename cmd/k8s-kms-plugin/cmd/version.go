/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	RawGitVersion        string
	CommitVersionIdShort string
	CommitVersionIdLong  string
	OutputFormat         string
	GoVersion            string
	BuildPlatform        string
	BuildDate            string
)

type JsonVersion struct {
	Major         string `json:"major"`
	Minor         string `json:"minor"`
	Version       string `json:"version"`
	CommitIdLong  string `json:"commitIdLong"`
	CommitIdShort string `json:"commitIdShort"`
	GoVersion     string `json:"goVersion"`
	Date          string `json:"date"`
	Platorm       string `json:"plaform"`
}
type YamlVersion struct {
	Major         string `yaml:"major"`
	Minor         string `yaml:"minor"`
	Version       string `yaml:"version"`
	CommitIdLong  string `yaml:"commitIdLong"`
	CommitIdShort string `yaml:"commitIdShort"`
	GoVersion     string `yaml:"goVersion"`
	Date          string `yaml:"date"`
	Platorm       string `yaml:"plaform"`
}

func splitVersion() (major, minor string) {
	if len(RawGitVersion) != 0 {
		versionArray := strings.Split(RawGitVersion[1:], ".")

		return versionArray[0], versionArray[1]
	} else {
		return "", ""
	}

}
func validateInputs() {
	if OutputFormat != "" && OutputFormat != "Json" && OutputFormat != "Yaml" {
		OutputFormat = ""
	}
}
func CreateJsonVersion() []byte {
	major, minor := splitVersion()
	jsonFormat := &JsonVersion{
		Major:         major,
		Minor:         minor,
		Version:       RawGitVersion,
		CommitIdLong:  CommitVersionIdLong,
		CommitIdShort: CommitVersionIdShort,
		GoVersion:     GoVersion,
		Date:          BuildDate,
		Platorm:       BuildPlatform,
	}
	data, err := json.MarshalIndent(&jsonFormat, "", "  ")
	if err != nil {

		fmt.Println(err)
	}
	return data
}
func CreateYamlVersion() []byte {
	major, minor := splitVersion()
	yamlFormat := &YamlVersion{
		Major:         major,
		Minor:         minor,
		Version:       RawGitVersion,
		CommitIdLong:  CommitVersionIdLong,
		CommitIdShort: CommitVersionIdShort,
		GoVersion:     GoVersion,
		Date:          BuildDate,
		Platorm:       BuildPlatform,
	}
	data, err := yaml.Marshal(&yamlFormat)
	if err != nil {

		fmt.Println(err)
	}
	return data
}

func generateOutput() {
	if OutputFormat == "Json" {
		fmt.Println(string(CreateJsonVersion()))
	} else if OutputFormat == "Yaml" {
		fmt.Println(string(CreateYamlVersion()))
	} else {
		fmt.Println(RawGitVersion)
	}
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show the version of the application with the short commit sha associated",
	Run: func(cmd *cobra.Command, args []string) {
		if OutputFormat == "" {
			fmt.Println(RawGitVersion)
		} else {
			validateInputs()
			generateOutput()
		}

	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	versionCmd.Flags().StringVar(&OutputFormat, "output", "", "'Json' or 'Yaml'")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// versionCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// versionCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
