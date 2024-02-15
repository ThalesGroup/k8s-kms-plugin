/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	RawGitVersion         string
	CommitVersionShaShort string
	CommitVersionShaLong  string
	CommitType            string
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show the version of the application with the short commit sha associated",
	Run: func(cmd *cobra.Command, args []string) {
		if CommitType == "Long" {
			fmt.Println(RawGitVersion + " " + CommitVersionShaLong)

		} else if CommitType == "Short" {
			fmt.Println(RawGitVersion + " " + CommitVersionShaShort)
		} else {
			fmt.Println(RawGitVersion)
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
	versionCmd.Flags().StringVar(&CommitType, "commit-sha-type", "", "'Long' or 'Short'")
	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// versionCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// versionCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
