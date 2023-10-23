package command

import (
	"errors"

	"github.com/KarlGW/secman/internal/security"
	"github.com/urfave/cli/v2"
)

// Profile is the command containing subcommands for handling
// profiles.
func Profile() *cli.Command {
	return &cli.Command{
		Name:     "profile",
		Usage:    "Manage profile",
		Category: "Subcommands",
		Subcommands: []*cli.Command{
			ProfileUpdate(),
			ProfileExport(),
			ProfileImport(),
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
		Usage:   "Update profile",
		Aliases: []string{"set"},
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "password",
				Usage:   "Set passwprd for secret encryption key generation",
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

// ProfileExport is a subcommand for exporting profiles.
func ProfileExport() *cli.Command {
	return &cli.Command{
		Name:  "export",
		Usage: "Export profile",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "file",
				Aliases:  []string{"f"},
				Usage:    "File to export to.",
				Required: true,
			},
		},
		Action: func(ctx *cli.Context) error {
			return exportProfile(ctx)
		},
	}
}

// ProfileImport is a subcommand for importing profiles.
func ProfileImport() *cli.Command {
	return &cli.Command{
		Name:  "import",
		Usage: "Import profile",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "file",
				Aliases:  []string{"f"},
				Usage:    "file to import from",
				Required: true,
			},
		},
		Action: func(ctx *cli.Context) error {
			return importProfile(ctx)
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

// exportProfile exports profile after promptong for configured password,
// and then prompting for password on target file.
func exportProfile(ctx *cli.Context) error {
	cfg, err := configuration(ctx)
	if err != nil {
		return err
	}

	var password []byte
	tries := 0
	for {
		password, err = passwordPrompt()
		if err != nil {
			return err
		}
		ok := security.ComparePasswordAndKey(password, cfg.Key())
		if ok {
			break
		}
		tries++
		if tries == 3 && !ok {
			return errors.New("wrong password")
		}
	}

	password, err = passwordPrompt("Set password for output file: ")
	if err != nil {
		return err
	}
	key, err := security.NewSHA256FromPassword(password)
	if err != nil {
		return err
	}
	return cfg.Export(ctx.String("file"), key)
}

// importProfile after a valid password has been entered.
func importProfile(ctx *cli.Context) error {
	return nil
}
