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
		Name:  "secret",
		Usage: "Manage secrets",
		Subcommands: []*cli.Command{
			SecretGet(),
			SecretList(),
			SecretCreate(),
			SecretUpdate(),
			SecretDelete(),
		},
		Before: func(ctx *cli.Context) error {
			if err := configure(ctx); err != nil {
				return err
			}
			if err := initHandler(ctx); err != nil {
				return err
			}
			return nil
		},
	}
}

// SecretGet is a subcommand for getting secrets.
func SecretGet() *cli.Command {
	return &cli.Command{
		Name:    "get",
		Usage:   "Get a secret",
		Aliases: []string{"show"},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "id",
				Aliases: []string{"i"},
				Usage:   "ID of secret to retrieve",
			},
			&cli.StringFlag{
				Name:    "name",
				Aliases: []string{"n"},
				Usage:   "Name of secret to retrieve",
			},
			&cli.BoolFlag{
				Name:    "decrypt",
				Aliases: []string{"d"},
				Usage:   "Decrypt the value of the secret",
			},
			&cli.BoolFlag{
				Aliases: []string{"c"},
				Name:    "clipboard",
				Usage:   "Copy the secret value to the clipboard",
			},
		},
		Action: func(ctx *cli.Context) error {
			handler, err := handler(ctx)
			if err != nil {
				return err
			}
			s, err := getSecret(handler, ctx.String("id"), ctx.String("name"))
			if err != nil {
				return err
			}

			if ctx.IsSet("decrypt") {
				decrypted, err := s.Decrypt()
				if err != nil {
					return err
				}
				if ctx.IsSet("clipboard") {
					return clipboard.WriteAll(string(decrypted))
				}
				output.Println(string(decrypted))
				return nil
			}

			output.Println(string(s.JSON()))
			return nil
		},
	}
}

// SecretList is a subcommand for listing secrets.
func SecretList() *cli.Command {
	return &cli.Command{
		Name:  "list",
		Usage: "List secrets",
		Action: func(ctx *cli.Context) error {
			handler, err := handler(ctx)
			if err != nil {
				return err
			}
			secrets, err := handler.ListSecrets()
			if err != nil {
				return err
			}
			output.Println(string(secrets.JSON()))
			return nil
		},
	}
}

// SecretCreate is a subcommand for creating secrets.
func SecretCreate() *cli.Command {
	return &cli.Command{
		Name:    "create",
		Usage:   "Create a secret",
		Aliases: []string{"add"},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "name",
				Aliases: []string{"n"},
				Usage:   "Name of secret to create",
			},
			&cli.StringFlag{
				Name:    "value",
				Aliases: []string{"v"},
				Usage:   "Value of the secret",
			},
			&cli.BoolFlag{
				Name:    "clipboard",
				Aliases: []string{"c"},
				Usage:   "Get the secret value from clipboard",
			},
		},
		Action: func(ctx *cli.Context) error {
			handler, err := handler(ctx)
			if err != nil {
				return err
			}

			if !ctx.IsSet("name") {
				return errors.New("a name must be provided")
			}

			var value string
			if ctx.IsSet("value") {
				value = ctx.String("value")
			} else if ctx.IsSet("clipboard") {
				value, err = clipboard.ReadAll()
				if err != nil {
					return err
				}
			} else {
				return errors.New("no value provided")
			}

			_, err = handler.AddSecret(ctx.String("name"), value)
			return err
		},
	}
}

// SecretUpdate is a subcommand for updating secrets.
func SecretUpdate() *cli.Command {
	return &cli.Command{
		Name:    "update",
		Usage:   "Update a secret",
		Aliases: []string{"set"},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "id",
				Aliases: []string{"i"},
				Usage:   "ID of secret to retrieve",
			},
			&cli.StringFlag{
				Name:    "name",
				Aliases: []string{"n"},
				Usage:   "Name of secret to retrieve",
			},
			&cli.StringFlag{
				Name:    "value",
				Aliases: []string{"v"},
				Usage:   "Value of the secret",
			},
			&cli.BoolFlag{
				Name:    "clipboard",
				Aliases: []string{"c"},
				Usage:   "Get the secret value from clipboard",
			},
		},
		Action: func(ctx *cli.Context) error {
			handler, err := handler(ctx)
			if err != nil {
				return err
			}
			s, err := getSecret(handler, ctx.String("id"), ctx.String("name"))
			if err != nil {
				return err
			}

			// Check if value is set.
			var value string
			if ctx.IsSet("value") {
				value = ctx.String("value")
			} else if ctx.IsSet("clipboard") {
				value, err = clipboard.ReadAll()
				if err != nil {
					return err
				}
			}

			var options []secret.SecretOption
			if len(value) > 0 {
				options = append(options, secret.WithValue([]byte(value)))
			}

			_, err = handler.UpdateSecretByID(s.ID, options...)
			if err != nil {
				return err
			}

			return nil
		},
	}
}

// SecretDelete is a subcommand for updating secrets.
func SecretDelete() *cli.Command {
	return &cli.Command{
		Name:    "delete",
		Usage:   "Delete a secret",
		Aliases: []string{"remove"},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "id",
				Aliases: []string{"i"},
				Usage:   "ID of secret to delete",
			},
			&cli.StringFlag{
				Name:    "name",
				Aliases: []string{"n"},
				Usage:   "Name of secret to delete",
			},
		},
		Action: func(ctx *cli.Context) error {
			handler, err := handler(ctx)
			if err != nil {
				return err
			}
			s, err := getSecret(handler, ctx.String("id"), ctx.String("name"))
			if err != nil {
				return err
			}

			return handler.DeleteSecretByID(s.ID)
		},
	}
}

// getSecret gets a secret by either id or name.
func getSecret(handler *secret.Handler, id, name string) (secret.Secret, error) {
	// Retrieve the secret.
	var s secret.Secret
	var err error
	if len(id) > 0 && len(name) == 0 {
		s, err = handler.GetSecretByID(id)
	} else if len(name) > 0 && len(id) == 0 {
		s, err = handler.GetSecretByName(name)
	} else {
		return secret.Secret{}, errors.New("id or name must be provided")
	}
	if err != nil {
		return secret.Secret{}, err
	}
	return s, nil
}
