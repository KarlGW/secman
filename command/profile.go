package command

import (
	"github.com/KarlGW/secman/internal/security"
	"github.com/urfave/cli/v2"
)

// Profile is the command containing subcommands for handling
// profiles.
func Profile() *cli.Command {
	return &cli.Command{
		Name: "profile",
		Subcommands: []*cli.Command{
			ProfileUpdate(),
		},
		Before: func(ctx *cli.Context) error {
			return configure(ctx)
		},
	}
}

// ProfileGet is a subcommand for getting profiles.
func ProfileGet() *cli.Command {
	return &cli.Command{}
}

// ProfileUpdate is a subcommand for updating profiles.
func ProfileUpdate() *cli.Command {
	return &cli.Command{
		Name:    "update",
		Aliases: []string{"set"},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "password",
				Aliases: []string{"p"},
			},
		},
		Action: func(ctx *cli.Context) error {
			if ctx.IsSet("password") {
				if err := setPassword(ctx); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

// setPassword takes the provided password and creates a new key from it
// and sets it to the provided configuration and updates all
// the secrets contained in the handler.
func setPassword(ctx *cli.Context) error {
	password, err := passwordPrompt()
	if err != nil {
		return err
	}

	key, err := security.NewKeyFromPassword(password)
	if err != nil {
		return err
	}

	cfg, err := configuration(ctx)
	if err != nil {
		return err
	}

	if cfg.Key().Valid() {
		if err := initHandler(ctx); err != nil {
			return err
		}
		handler, err := handler(ctx)
		if err != nil {
			return err
		}
		if err := handler.UpdateKey(key); err != nil {
			return err
		}
	}

	if err := cfg.SetKey(key); err != nil {
		return err
	}

	return nil
}
