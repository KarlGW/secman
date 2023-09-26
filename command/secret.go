package command

import (
	"errors"
	"io"
	"os"
	"strings"

	"github.com/KarlGW/secman/output"
	"github.com/KarlGW/secman/secret"
	"github.com/atotto/clipboard"
	"github.com/urfave/cli/v2"
)

// SecretGenerate is a command for generating a secret.
func SecretGenerate() *cli.Command {
	return &cli.Command{
		Name:     "generate",
		Usage:    "generate a secret",
		Category: "Secrets",
		Flags: []cli.Flag{
			&cli.IntFlag{
				Name:    "length",
				Usage:   "Amount of characters",
				Aliases: []string{"l"},
				Value:   16,
			},
			&cli.BoolFlag{
				Name:    "no-special-characters",
				Usage:   "Omit special characters",
				Aliases: []string{"n"},
				Value:   false,
			},
		},
		Action: func(ctx *cli.Context) error {
			if ctx.Int("length") < 8 {
				return errors.New("a minimum of 8 characters must be specified")
			}

			var sc bool
			if !ctx.IsSet("no-special-characters") {
				sc = true
			}

			output.Println(secret.Generate(ctx.Int("length"), sc))
			return nil
		},
	}
}

// SecretList is a command for listing secrets.
func SecretList() *cli.Command {
	return &cli.Command{
		Name:     "list",
		Category: "Secrets",
		Usage:    "List secrets",
		Before: func(ctx *cli.Context) error {
			return initHandler(ctx)
		},
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

// SecretGet is a command for getting a secret.
func SecretGet() *cli.Command {
	return &cli.Command{
		Name:     "get",
		Category: "Secrets",
		Usage:    "Get a secret",
		Aliases:  []string{"show"},
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
		Before: func(ctx *cli.Context) error {
			return initHandler(ctx)
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

// SecretCreate is a command for creating a secret.
func SecretCreate() *cli.Command {
	return &cli.Command{
		Name:     "create",
		Category: "Secrets",
		Usage:    "Create a secret",
		Aliases:  []string{"add"},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "name",
				Aliases: []string{"n"},
				Usage:   "Name of secret to create",
			},
			&cli.StringFlag{
				Name:    "value",
				Aliases: []string{"v"},
				Usage:   "Value of the secret. Can be piped from stdin.",
			},
			&cli.BoolFlag{
				Name:    "clipboard",
				Aliases: []string{"c"},
				Usage:   "Get the secret value from clipboard",
			},
		},
		Before: func(ctx *cli.Context) error {
			return initHandler(ctx)
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
				value, err = fromPipe()
				if err != nil {
					return err
				}
			}

			_, err = handler.AddSecret(ctx.String("name"), value)
			return err
		},
	}
}

// SecretUpdate is a command for updating a secret.
func SecretUpdate() *cli.Command {
	return &cli.Command{
		Name:     "update",
		Category: "Secrets",
		Usage:    "Update a secret",
		Aliases:  []string{"set"},
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
				Usage:   "Value of the secret. Can be piped from stdin.",
			},
			&cli.BoolFlag{
				Name:    "clipboard",
				Aliases: []string{"c"},
				Usage:   "Get the secret value from clipboard",
			},
		},
		Before: func(ctx *cli.Context) error {
			return initHandler(ctx)
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

			var value string
			if ctx.IsSet("value") {
				value = ctx.String("value")
			} else if ctx.IsSet("clipboard") {
				value, err = clipboard.ReadAll()
				if err != nil {
					return err
				}
			} else {
				value, err = fromPipe()
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

// SecretDelete is a command for deleting a secret.
func SecretDelete() *cli.Command {
	return &cli.Command{
		Name:     "delete",
		Category: "Secrets",
		Usage:    "Delete a secret",
		Aliases:  []string{"remove"},
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
		Before: func(ctx *cli.Context) error {
			return initHandler(ctx)
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

// fromPipe reads from incoming stdin pipe.
func fromPipe() (string, error) {
	info, err := os.Stdin.Stat()
	if err != nil {
		return "", err
	}

	if (info.Mode() & os.ModeCharDevice) != 0 {
		return "", errors.New("no value provided")
	}

	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\n\r"), nil
}
