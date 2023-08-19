package secman

import (
	"os"

	"github.com/KarlGW/secman/command"
	"github.com/urfave/cli/v2"
)

const (
	name = "secman"
)

// CLI is the entrypoint for the program.
func CLI(args []string) int {
	app := &cli.App{
		Name:  name,
		Usage: "",
		Commands: []*cli.Command{
			command.Secret(),
			command.Profile(),
		},
	}

	if err := app.Run(os.Args); err != nil {
		return 1
	}
	return 0
}
