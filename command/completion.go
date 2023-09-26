package command

import (
	"github.com/KarlGW/secman/completion"
	"github.com/KarlGW/secman/output"
	"github.com/urfave/cli/v2"
)

func Completion() *cli.Command {
	return &cli.Command{
		Name:     "completion",
		Category: "Subcommands",
		Usage:    "Generate completion script",
		Subcommands: []*cli.Command{
			{
				Name:  "bash",
				Usage: "Generate bash completion script",
				Action: func(ctx *cli.Context) error {
					output.Println(completion.Bash())
					return nil
				},
			},
			{
				Name:  "zsh",
				Usage: "Generate zsh completion script",
				Action: func(ctx *cli.Context) error {
					output.Println(completion.Zsh())
					return nil
				},
			},
			{
				Name:  "powershell",
				Usage: "Generate PowerShell completion script",
				Action: func(ctx *cli.Context) error {
					output.Println(completion.PowerShell())
					return nil
				},
			},
		},
	}
}
