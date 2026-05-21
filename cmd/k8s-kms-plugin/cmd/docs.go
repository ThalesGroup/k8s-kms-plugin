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
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ThalesGroup/k8s-kms-plugin/pkg/logging"
	"github.com/ThalesGroup/k8s-kms-plugin/pkg/version"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/jedib0t/go-pretty/v6/table"
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
			slog.Error("Error initializing Viper", "cobra_cmd", cmd.Use, "error", err)
			return err
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		err := generateCobraDocs(vprFlgsDocs.Format, vprFlgsDocs.OutputDir)
		if err != nil {
			slog.Error("error generating docs", "format", vprFlgsDocs.Format, "output_dir", vprFlgsDocs.OutputDir, "error", err)
		}
		return err
	},
}

func init() {
	rootCmd.AddCommand(docsCmd)

	docsCmd.Flags().StringP("format", "f", "markdown", "Docs Output format. Prefered is markdown. Supported formats: markdown, man, rst, yaml, cli-table-csv, cli-table-pretty, cli-table-html, all.")
	docsCmd.RegisterFlagCompletionFunc("format", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"markdown", "man", "rst", "yaml", "cli-table-csv", "cli-table-pretty", "cli-table-html", "all"}, cobra.ShellCompDirectiveNoFileComp
	})

	docsCmd.Flags().StringP("output-dir", "o", filepath.Join(os.TempDir(), fmt.Sprintf("k8s-kms-plugin-docs-%s", time.Now().Format(time.RFC3339))), "Output directory")
}

// getFlagTable takes a cobra command and a format string and returns a table
// displaying the command's flags, their properties and default values in the
// requested format.
//
// The table columns are:
//   - Command: the name of the command
//   - Flag: the flag name
//   - Short Flag: the short flag name
//   - Env Var: the environment variable name for the flag
//   - Viper Key: the viper key for the flag
//   - Default: the default value for the flag
//   - Type: the type of the flag
//   - Persistent Flag: whether the flag is persistent
//   - Usage: the usage string for the flag
//
// The formats supported are:
//   - markdown: renders the table in markdown format
//   - html: renders the table in html format
//   - csv: renders the table in comma-separated values format
//   - (default): renders the table in a human-readable "pretty" format
func getFlagTable(c *cobra.Command, format string) string {
	// Initialize the table
	t := table.NewWriter()
	//t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight)
	// Create the header with the columns
	t.AppendHeader(table.Row{
		"Command",
		"Flags (long)",
		"Flags (short)",
		"Env Var",
		"Config File Keys",
		"Default Value",
		"Type",
		"Persistent Flag",
		"Usage",
	})

	t.AppendFooter(table.Row{
		"Command",
		"Flags (long)",
		"Flags (short)",
		"Env Var",
		"Config File Keys",
		"Default Value",
		"Type",
		"Persistent Flag",
		"Usage",
	})

	walkCobraFlagsPretty(c, t)

	// render the table in the given format
	switch format {
	case "markdown":
		return t.RenderMarkdown()
	case "html":
		return t.RenderHTML()
	case "csv":
		return t.RenderCSV()
	}
	// Default renders the Table in a human-readable "pretty" format
	return t.Render()
}

func writeFlagTableToFile(c *cobra.Command, format string, filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(getFlagTable(c, format))
	return err
}

// walkCobraFlagsPretty traverses the cobra command tree and prints a pretty table of flags -> env vars -> viper keys
// Only local and non-persistent flags are printed. Local persistent flags are printed as well, but only for the local commands
// and not its subcommands.
// The table is printed to t, which is a table.Writer
// The section is the path for a flag in a Viper configuration file, obtained by replacing spaces with dots in the command path
func walkCobraFlagsPretty(cmd *cobra.Command, t table.Writer) {
	// section is the path (JSON, YAML) for a flag in a Viper configuration file
	section := strings.ReplaceAll(cmd.CommandPath(), " ", ".")

	// Add only flags that are local and do not add persistent flags
	cmd.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) {
		if f.Name != "no-descriptions" {
			t.AppendRow(buildTableRow(cmd, f, section, false))
		}
	})

	// Add the persistent flags of the current but not its subcommands
	cmd.PersistentFlags().VisitAll(func(f *pflag.Flag) {
		if f.Name != "no-descriptions" {
			t.AppendRow(buildTableRow(cmd, f, section, true))
		}
	})

	// Iterate recurssively on sub command but ignore inherited flags from parent commands to prevent duplication of
	// flags and persistent flags in the documentation
	for _, sub := range cmd.Commands() {
		// Add separator between different commands. This has no effect if the table is rendered as markdown
		t.AppendSeparator()
		walkCobraFlagsPretty(sub, t)
	}
}

// buildTableRow returns a table.Row representing a cobra flag as a row in a table.
// Inputs:
// - cmd: the cobra command that contains the flag
// - f: the flag
// - section: the path (JSON, YAML) for a flag in a Viper configuration file
// - persistent: whether the flag is a persistent flag or not
//
// The columns of the table are:
// - Command: the path of the command. Example "k8s-kms-plugin serve"
// - Flag: the flag name. Example: --host
// - Short Flag: the short flag name. Example: -p
// - Env Var: the environment variable name that can be used to override the flag. Example: K8S_KMS_PLUGIN_SERVE_HOST.
// - Viper Key: the full key path in a Viper configuration file (JSON or YAML). Example: k8s-kms-plugin.serve.host
// - Default: the default value of the flag. Example: host => 0.0.0.0
// - Type: the type of the flag. Example: string
// - Persistent Flag: whether the flag is a persistent flag
// - Usage: the usage string for the flag
func buildTableRow(cmd *cobra.Command, f *pflag.Flag, section string, persistent bool) table.Row {
	// envVarPrefix include the name of the binary and the section of the cli command.
	// Example: K8S_KMS_PLUGIN_SERVE_* for the command k8s-kms-plugin serve
	envVarPrefix := strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(section))

	// envVar is the environment variable name that can be used to override the flag. Ex.: K8S_KMS_PLUGIN_SERVE_HOST
	envVar := envVarPrefix + "_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))

	// viperKey is the keyname and fullpath for the viper configuration file (JSON or YAML)
	// Example: k8s-kms-plugin.serve.host for the command k8s-kms-plugin serve --host
	viperKey := section + "." + f.Name

	return table.Row{
		cmd.CommandPath(),
		"--" + f.Name,
		// if f.Shorthand short flag is empty, then leave cell empty
		func() string {
			if f.Shorthand != "" {
				return "-" + f.Shorthand
			}
			return ""
		}(),
		envVar,
		viperKey,
		f.DefValue,
		f.Value.Type(),
		persistent,
		f.Usage,
	}
}

func writeMarkdownReadme(dir string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("unable to read markdown output directory: %w", err)
	}

	readme := strings.Builder{}
	readme.WriteString("# k8s-kms-plugin CLI Documentation\n\n")
	readme.WriteString("This documentation is auto-generated from `k8s-kms-plugin`:\n\n")
	readme.WriteString(fmt.Sprintf("- version `%s`\n- commit `%s`\n- build date %s.\n\n",
		version.RawGitDescribe, version.GitCommitIdLong, version.BuildDate))

	readme.WriteString("## Available Command Documentation\n\n")
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".md") {
			readme.WriteString(fmt.Sprintf("- [%s](%s)\n", strings.TrimSuffix(f.Name(), ".md"), f.Name()))
		}
	}

	readme.WriteString("##### Auto Generated README.md file using `k8s-kms-plugin docs -f markdown`\n")

	return os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme.String()), 0644)
}

// generateCobraDocs generates CLI documentation for the k8s-kms-plugin in the specified format.
// It supports generating documentation in "markdown", "man", "rst", "yaml", "table", or "all" formats.
// The output directory is created if it does not exist. If the format is "all",
// documentation is generated in multiple subdirectories within the given output directory.
// Returns an error if the format is unsupported or if any I/O operation fails.
//
// Parameters:
//   - format: The output format for the documentation (e.g., "markdown", "man", "rst", "yaml", "table", "all").
//   - out: The directory where the generated documentation files will be saved.
//
// Returns:
//   - error: An error object if any step of the documentation generation fails.
func generateCobraDocs(format, out string) error {
	// Create the output directory if it doesn't already exist
	if _, err := os.Stat(out); os.IsNotExist(err) {
		slog.Log(context.Background(), logging.LevelTrace, "creating output directory", "path", out)
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

	// TODO: improve and clean this switch case
	switch format {
	case "markdown":
		slog.Log(context.Background(), logging.LevelTrace, "generating markdown documentation", "path", out)
		if err := writeFlagTableToFile(rootCmd, format, filepath.Join(out, "cli-env-var-table.md")); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}

		if err := doc.GenMarkdownTree(rootCmd, out); err != nil {
			return fmt.Errorf("error generating markdown documentation at %s: %w", out, err)
		}
		if err := writeMarkdownReadme(out); err != nil {
			return fmt.Errorf("error generating markdown readme at %s: %w", out, err)
		}
		return nil
	case "man":
		slog.Log(context.Background(), logging.LevelTrace, "generating man documentation", "path", out)
		if err := writeFlagTableToFile(rootCmd, "", filepath.Join(out, "cli-env-var-table.txt")); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}

		if err := doc.GenManTree(rootCmd, manHeader, out); err != nil {
			return fmt.Errorf("error generating man documentation at %s: %w", out, err)
		}
		return nil
	case "rst":
		slog.Log(context.Background(), logging.LevelTrace, "generating rst documentation", "path", out)
		if err := writeFlagTableToFile(rootCmd, "", filepath.Join(out, "cli-env-var-table.txt")); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		if err := doc.GenReSTTree(rootCmd, out); err != nil {
			return fmt.Errorf("error generating rst documentation at %s: %w", out, err)
		}
		return nil
	case "yaml":
		slog.Log(context.Background(), logging.LevelTrace, "generating yaml documentation", "path", out)
		if err := writeFlagTableToFile(rootCmd, "", filepath.Join(out, "cli-env-var-table.txt")); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		if err := doc.GenYamlTree(rootCmd, out); err != nil {
			return fmt.Errorf("error generating yaml documentation at %s: %w", out, err)
		}
		return nil
	case "cli-table-csv":
		slog.Log(context.Background(), logging.LevelTrace, "generating table documentation", "path", out)
		if err := writeFlagTableToFile(rootCmd, "csv", filepath.Join(out, "cli-env-var-table.csv")); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		return nil
	case "cli-table-pretty":
		slog.Log(context.Background(), logging.LevelTrace, "generating table documentation", "path", out)
		if err := writeFlagTableToFile(rootCmd, "", filepath.Join(out, "cli-env-var-table.txt")); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		return nil
	case "cli-table-html":
		slog.Log(context.Background(), logging.LevelTrace, "generating table documentation", "path", out)
		if err := writeFlagTableToFile(rootCmd, "html", filepath.Join(out, "cli-env-var-table.html")); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		return nil
	case "all":
		for _, dir := range []string{"rst", "markdown", "man", "yaml", "csv", "html", "txt"} {
			if _, err := os.Stat(filepath.Join(out, dir)); os.IsNotExist(err) {
				slog.Log(context.Background(), logging.LevelTrace, "creating output directory", "path", filepath.Join(out, dir))
				if err := os.MkdirAll(filepath.Join(out, dir), 0755); err != nil {
					return fmt.Errorf("error creating output directory %s: %w", filepath.Join(out, dir), err)
				}
			} else if err != nil {
				return fmt.Errorf("error verifying output directory %s: %w", filepath.Join(out, dir), err)
			}
		}

		slog.Log(context.Background(), logging.LevelTrace, "generating all documentation", "path", out)
		// markdown
		if err := doc.GenMarkdownTree(rootCmd, filepath.Join(out, "markdown")); err != nil {
			return fmt.Errorf("error generating markdown documentation: %w", err)
		}
		if err := writeFlagTableToFile(rootCmd, "markdown", filepath.Join(out, "markdown", "cli-env-var-table.md")); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		if err := writeMarkdownReadme(filepath.Join(out, "markdown")); err != nil {
			return fmt.Errorf("error generating markdown readme at %s: %w", filepath.Join(out, "markdown"), err)
		}
		// man
		if err := doc.GenManTree(rootCmd, manHeader, filepath.Join(out, "man")); err != nil {
			return fmt.Errorf("error generating man documentation: %w", err)
		}
		// rst
		if err := doc.GenReSTTree(rootCmd, filepath.Join(out, "rst")); err != nil {
			return fmt.Errorf("error generating rst documentation: %w", err)
		}
		// yaml
		if err := doc.GenYamlTree(rootCmd, filepath.Join(out, "yaml")); err != nil {
			return fmt.Errorf("error generating yaml documentation: %w", err)
		}

		// CLI table
		if err := writeFlagTableToFile(rootCmd, "csv", filepath.Join(out, "csv", "cli-env-var-table.csv")); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		if err := writeFlagTableToFile(rootCmd, "html", filepath.Join(out, "html", "cli-env-var-table.html")); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		if err := writeFlagTableToFile(rootCmd, "", filepath.Join(out, "txt", "cli-env-var-table.txt")); err != nil {
			return fmt.Errorf("error writing flag table to file: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}
