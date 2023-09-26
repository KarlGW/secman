package secman

import (
	"os"

	"github.com/KarlGW/secman/command"
	"github.com/KarlGW/secman/output"
	"github.com/KarlGW/secman/version"
	"github.com/urfave/cli/v2"
)

const (
	name = "secman"
)

// CLI is the entrypoint for the program.
func CLI(args []string) int {
	app := &cli.App{
		Name:                 name,
		Usage:                "Tool for managing secrets",
		Version:              version.Version(),
		EnableBashCompletion: true,
		HideHelpCommand:      true,
		Commands: []*cli.Command{
			command.SecretGenerate(),
			command.SecretList(),
			command.SecretGet(),
			command.SecretCreate(),
			command.SecretUpdate(),
			command.SecretDelete(),
			command.Profile(),
			command.Completion(),
		},
	}

	if err := app.Run(os.Args); err != nil {
		output.PrintErrorln(err)
		return 1
	}
	return 0
}
