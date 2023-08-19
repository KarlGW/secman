package command

import (
	"errors"

	"github.com/KarlGW/secman/output"
	"github.com/KarlGW/secman/secret"
	"github.com/atotto/clipboard"
	"github.com/urfave/cli/v2"
)

// Secret is the command containing subcommands for handling
// get, create, update and delete secrets.
func Secret() *cli.Command {
	return &cli.Command{
		Name: "secret",
		Subcommands: []*cli.Command{
			secretGet(),
			secretCreate(),
		},
		Before: func(ctx *cli.Context) error {
			configure(ctx)
			initHandler(ctx)
			return nil
		},
	}
}

// secretGet is a subcommand for getting secrets.
func secretGet() *cli.Command {
	return &cli.Command{
		Name:    "get",
		Aliases: []string{"show"},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "id",
				Usage: "id of secret to retrieve",
			},
			&cli.StringFlag{
				Name:  "name",
				Usage: "name of secret to retrieve",
			},
			&cli.BoolFlag{
				Name:    "decrypt",
				Aliases: []string{"d"},
				Usage:   "decrypt the value of the secret",
			},
			&cli.BoolFlag{
				Aliases: []string{"c"},
				Name:    "clipboard",
				Usage:   "copy the secret value to the clipboard",
			},
		},
		Action: func(ctx *cli.Context) error {
			handler, err := handler(ctx)
			if err != nil {
				return err
			}

			// Retrieve the secret.
			var secret secret.Secret
			if ctx.IsSet("id") && !ctx.IsSet("name") {
				secret, err = handler.GetSecretByID(ctx.String("id"))
			} else if ctx.IsSet("name") && !ctx.IsSet("id") {
				secret, err = handler.GetSecretByName(ctx.String("name"))
			} else {
				return errors.New("id or name must be provided")
			}
			if err != nil {
				return err
			}

			// Handle the secret.
			if ctx.IsSet("clipboard") {
				decrypted, err := secret.Decrypt()
				if err != nil {
					return err
				}
				return clipboard.WriteAll(string(decrypted))
			}
			if ctx.IsSet("decrypt") {
				decrypted, err := secret.Decrypt()
				if err != nil {
					return err
				}
				output.Print([]byte(string(decrypted)))
				return nil
			}
			output.Print(secret.JSON())

			return nil
		},
	}
}

// secretCreate is a subcommand for creating secrets.
func secretCreate() *cli.Command {
	return &cli.Command{
		Name:    "create",
		Aliases: []string{},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "name",
				Usage: "name of secret to create",
			},
			&cli.StringFlag{
				Name:  "value",
				Usage: "value of the secret",
			},
			&cli.BoolFlag{
				Name:  "clipboard",
				Usage: "get the secret value from clipboard",
			},
		},
		Action: func(ctx *cli.Context) error {
			handler, err := handler(ctx)
			if err != nil {
				return err
			}

			var value string
			if ctx.IsSet("value") {
				value = ctx.String(value)
			} else if ctx.IsSet("clipboard") {
				value, err = clipboard.ReadAll()
				if err != nil {
					return err
				}
			}

			_, err = handler.AddSecret(ctx.String("name"), value)
			return nil
		},
	}
}

// secretUpdate is a subcommand for updating secrets.
func secretUpdate() *cli.Command {
	return nil
}

// secretDelete is a subcommand for updating secrets.
func secretDelete() *cli.Command {
	return nil
}
