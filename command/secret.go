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
			SecretGet(),
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
			s, err := getSecret(handler, ctx.String("id"), ctx.String("name"))
			if err != nil {
				return err
			}

			// Handle the secret.
			if ctx.IsSet("clipboard") {
				decrypted, err := s.Decrypt()
				if err != nil {
					return err
				}
				return clipboard.WriteAll(string(decrypted))
			}
			if ctx.IsSet("decrypt") {
				decrypted, err := s.Decrypt()
				if err != nil {
					return err
				}
				output.Println(string(decrypted))
				return nil
			}
			output.Println(string(s.JSON()))

			return nil
		},
	}
}

// SecretCreate is a subcommand for creating secrets.
func SecretCreate() *cli.Command {
	return &cli.Command{
		Name:    "create",
		Aliases: []string{"add"},
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
		Aliases: []string{"set"},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "id",
				Usage: "id of secret to retrieve",
			},
			&cli.StringFlag{
				Name:  "name",
				Usage: "name of secret to retrieve",
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
		Aliases: []string{"remote"},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "id",
				Usage: "id of secret to delete",
			},
			&cli.StringFlag{
				Name:  "name",
				Usage: "name of secret to delete",
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
