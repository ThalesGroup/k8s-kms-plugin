// SPDX-FileCopyrightText: 2026 Thales Group and the k8s-kms-plugin Contributors
// SPDX-License-Identifier: MIT

package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// ANSI styling used only for the interactive --help/-h terminal output. Kept
// minimal and applied exclusively to section headers (never to command names,
// flag lines, or Short/Long text) so column alignment done by cobra's `rpad`
// template func, shell completion (which reads .Short/.Long verbatim), and the
// `docs` command (which renders Long/Short/flags directly, bypassing the usage
// template entirely, see doc.GenMarkdownTree) all stay unaffected.
const (
	ansiReset   = "\033[0m"
	ansiHeading = "\033[1;36m" // bold cyan
)

// colorEnabled reports whether ANSI styling should be applied. It is
// re-evaluated on every call (cheap) rather than cached, so redirecting
// stdout or toggling NO_COLOR between invocations is honored, and colors
// are automatically off for any non-interactive output (`--help > file`,
// CI logs, etc.).
func colorEnabled() bool {
	if _, noColor := os.LookupEnv("NO_COLOR"); noColor {
		return false
	}
	if v, forced := os.LookupEnv("CLICOLOR_FORCE"); forced && v != "0" {
		return true
	}
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// heading bolds and colorizes a help/usage section header such as "Usage:" or
// "Main KMS Commands:". Registered as the cobra template func "heading".
func heading(s string) string {
	if !colorEnabled() {
		return s
	}
	return ansiHeading + s + ansiReset
}

// coloredUsageTemplate mirrors cobra's defaultUsageTemplate, wrapping every
// section header with {{heading}}. Only used for terminal --help/-h output.
const coloredUsageTemplate = `{{heading "Usage:"}}{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

{{heading "Aliases:"}}
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

{{heading "Examples:"}}
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}{{$cmds := .Commands}}{{if eq (len .Groups) 0}}

{{heading "Available Commands:"}}{{range $cmds}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{else}}{{range $group := .Groups}}

{{heading .Title}}{{range $cmds}}{{if (and (eq .GroupID $group.ID) (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if not .AllChildCommandsHaveGroup}}

{{heading "Additional Commands:"}}{{range $cmds}}{{if (and (eq .GroupID "") (or .IsAvailableCommand (eq .Name "help")))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

{{heading "Flags:"}}
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

{{heading "Global Flags:"}}
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

{{heading "Additional help topics:"}}{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`

func init() {
	cobra.AddTemplateFunc("heading", heading)
	// Setting it on rootCmd applies to every subcommand: cobra's
	// Command.UsageTemplate() walks up to the nearest ancestor that has one set.
	rootCmd.SetUsageTemplate(coloredUsageTemplate)
}
