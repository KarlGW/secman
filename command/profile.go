package command

import (
	"syscall"

	"github.com/KarlGW/secman/internal/security"
	"github.com/KarlGW/secman/output"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

// Profile is the command containing subcommands for handling
// profiles.
func Profile() *cli.Command {
	return &cli.Command{
		Name: "profile",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "password",
				Aliases: []string{"p"},
			},
		},
		Before: func(ctx *cli.Context) error {
			return configure(ctx)
		},
		Action: func(ctx *cli.Context) error {
			cfg, err := configuration(ctx)
			if err != nil {
				return err
			}

			if ctx.IsSet("password") {
				output.Print("Enter password: ")
				password, err := term.ReadPassword(int(syscall.Stdin))
				if err != nil {
					return err
				}
				key, err := security.NewKeyFromPassword(password)
				if err != nil {
					return err
				}
				if err := cfg.SetKey(key); err != nil {
					return err
				}
				output.PrintEmptyln()
			}
			return nil
		},
	}
}
