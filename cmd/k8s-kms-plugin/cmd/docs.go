/*
 * Copyright 2025 Thales
 * SPDX-License-Identifier: MIT
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ThalesGroup/k8s-kms-plugin/pkg/version"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

// ViperFlagsServe defines a struct to hold the values of cobra CLI flags and use viper to populate them
type ViperFlagsDocs struct {
	Format    string `mapstructure:"format"`
	OutputDir string `mapstructure:"output-dir"`
}

// Declare the viper CLI flag values buffer
var vprFlgsDocs ViperFlagsDocs

// docsCmd represents the docs command
var docsCmd = &cobra.Command{
	Use:   "docs",
	Short: "Generate CLI documentation",
	Long:  `Generate CLI documentation (markdown, man, rst, html)"`,
	// Initialize and populate cobra CLI flags values with viper during the Persistent pre-run
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if err := InitViperSubCmdE(viper.GetViper(), cmd, &vprFlgsDocs); err != nil {
			logrus.WithField("cobra-cmd", cmd.Use).WithError(err).Error("Error initializing Viper")
			return err
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		err := generateDocs(vprFlgsDocs.Format, vprFlgsDocs.OutputDir)
		if err != nil {
			logrus.WithError(err).Errorf("Error generating docs in format %s at %s", vprFlgsDocs.Format, vprFlgsDocs.OutputDir)
		}
		return err
	},
}

func init() {
	rootCmd.AddCommand(docsCmd)

	docsCmd.Flags().StringP("format", "f", "markdown", "Output format: markdown, man, rst, html")
	docsCmd.RegisterFlagCompletionFunc("format", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"markdown", "man", "rst", "yaml", "table", "all"}, cobra.ShellCompDirectiveNoFileComp
	})

	docsCmd.Flags().StringP("output-dir", "o", filepath.Join(os.TempDir(), fmt.Sprintf("k8s-kms-plugin-docs-%s", time.Now().Format(time.RFC3339))), "Output directory")
}

// Print a Markdown table of flag -> env var -> viper key
func printFlagTable(c *cobra.Command) {
	w := tabwriter.NewWriter(os.Stdout, 2, 8, 2, ' ', 0)

	fmt.Fprintln(w, "| Command | Flag | Environment Variable | Config Key |")
	fmt.Fprintln(w, "|---------|------|----------------------|------------|")

	walk(c, w)

	w.Flush()
}

func walk(c *cobra.Command, w *tabwriter.Writer) {
	section := strings.ReplaceAll(c.CommandPath(), " ", ".") // viper config path

	c.Flags().VisitAll(func(f *pflag.Flag) {
		if f.Name == "no-descriptions" {
			return
		}
		env := strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(fmt.Sprintf("%s_%s", section, f.Name)))
		fmt.Fprintf(w, "| %s | --%s | %s | %s |\n", c.CommandPath(), f.Name, env, section+"."+f.Name)
	})

	// Also include persistent flags
	c.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if f.Name == "no-descriptions" {
			return
		}
		env := strings.ToUpper(strings.NewReplacer(".", "_", "-", "_").Replace(fmt.Sprintf("%s_%s", section, f.Name)))
		fmt.Fprintf(w, "| %s | --%s (persistent flag) | %s | %s |\n", c.CommandPath(), f.Name, env, section+"."+f.Name)
	})

	for _, sub := range c.Commands() {
		walk(sub, w)
	}
}

func generateDocs(format, out string) error {
	// Create the output directory if it doesn't already exist
	if _, err := os.Stat(out); os.IsNotExist(err) {
		logrus.Tracef("Creating output directory %s", out)
		if err := os.MkdirAll(out, 0755); err != nil {
			return fmt.Errorf("error creating output directory %s: %w", out, err)
		}
	} else if err != nil {
		return fmt.Errorf("error verifying output directory %s: %w", out, err)
	}

	manHeader := &doc.GenManHeader{
		Title:   "K8S-KMS-PLUGIN",
		Section: "1",
		Manual:  version.RawGitDescribe,
	}

	switch format {
	case "markdown":
		logrus.Tracef("Generating markdown documentation at %s", out)
		return doc.GenMarkdownTree(rootCmd, out)
	case "man":
		logrus.Tracef("Generating man documentation at %s", out)
		return doc.GenManTree(rootCmd, manHeader, out)
	case "rst":
		logrus.Tracef("Generating rst documentation at %s", out)
		return doc.GenReSTTree(rootCmd, out)
	case "yaml":
		logrus.Tracef("Generating yaml documentation at %s", out)
		return doc.GenYamlTree(rootCmd, out)
	case "table":
		logrus.Tracef("Generating table documentation at %s", out)
		printFlagTable(rootCmd)
		return nil
	case "all":
		for _, dir := range []string{"rst", "markdown", "man", "yaml"} {
			if _, err := os.Stat(filepath.Join(out, dir)); os.IsNotExist(err) {
				logrus.Tracef("Creating output directory %s", filepath.Join(out, dir))
				if err := os.MkdirAll(filepath.Join(out, dir), 0755); err != nil {
					return fmt.Errorf("error creating output directory %s: %w", filepath.Join(out, dir), err)
				}
			} else if err != nil {
				return fmt.Errorf("error verifying output directory %s: %w", filepath.Join(out, dir), err)
			}
		}

		logrus.Tracef("Generating all documentation at %s", out)
		if err := doc.GenMarkdownTree(rootCmd, filepath.Join(out, "markdown")); err != nil {
			return fmt.Errorf("error generating markdown documentation: %w", err)
		}
		if err := doc.GenManTree(rootCmd, manHeader, filepath.Join(out, "man")); err != nil {
			return fmt.Errorf("error generating man documentation: %w", err)
		}
		if err := doc.GenReSTTree(rootCmd, filepath.Join(out, "rst")); err != nil {
			return fmt.Errorf("error generating rst documentation: %w", err)
		}
		if err := doc.GenYamlTree(rootCmd, filepath.Join(out, "yaml")); err != nil {
			return fmt.Errorf("error generating yaml documentation: %w", err)
		}

		return nil
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}
