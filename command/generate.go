package command

import (
	"github.com/KarlGW/secman/output"
	"github.com/KarlGW/secman/secret"
	"github.com/urfave/cli/v2"
)

// Generate is the command for generating secrets.
func Generate() *cli.Command {
	return &cli.Command{
		Name:  "generate",
		Usage: "Generate a secret",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "length",
				Usage:   "Length (amount of characters) in secret",
				Aliases: []string{"l"},
				Value:   16,
			},
			&cli.BoolFlag{
				Name:    "no-special-characters",
				Usage:   "Include special characters in secret",
				Aliases: []string{"n"},
				Value:   false,
			},
		},
		Action: func(ctx *cli.Context) error {
			l := ctx.Int("length")
			var sc bool
			if !ctx.IsSet("no-special-characters") {
				sc = true
			}

			output.Println(secret.Generate(l, sc))
			return nil
		},
	}
}
