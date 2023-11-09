package command

import (
	"errors"

	"github.com/KarlGW/secman/config"
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
			ProfileNew(),
			ProfileSet(),
			ProfileUpdate(),
			ProfileExport(),
			ProfileImport(),
		},
		Before: func(ctx *cli.Context) error {
			return configure(ctx)
		},
	}
}

// ProfileNew is a subcommand for creating profiles.
func ProfileNew() *cli.Command {
	return &cli.Command{
		Name:  "new",
		Usage: "Create new profile",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "name",
				Usage:   "Name of new profile. If omitted, current logged in user will be used",
				Aliases: []string{"n"},
			},
			&cli.BoolFlag{
				Name:  "password",
				Usage: "Add password (master key) to new profile",
			},
		},
		Action: func(ctx *cli.Context) error {
			return newProfile(ctx)
		},
	}
}

// ProfileSet is a subcommand for setting current profile.
func ProfileSet() *cli.Command {
	return &cli.Command{
		Name:  "set-current",
		Usage: "Set current profile",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "id",
				Usage:   "id of profile",
				Aliases: []string{"i"},
			},
		},
		Action: func(ctx *cli.Context) error {
			if !ctx.IsSet("id") {
				return errors.New("an ID must be provided")
			}
			cfg, err := configuration(ctx)
			if err != nil {
				return err
			}
			return cfg.SetProfile(ctx.String("id"))
		},
	}
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
			&cli.BoolFlag{
				Name:    "overwrite",
				Aliases: []string{"o"},
				Usage:   "Overwrite if profile with same ID already exist",
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

// newProfile creates a new profile.
func newProfile(ctx *cli.Context) error {
	cfg, err := configuration(ctx)
	if err != nil {
		return err
	}

	var name string
	if ctx.IsSet("name") {
		name = ctx.String("name")
	}

	var password []byte
	if ctx.IsSet("password") {
		password, err = passwordPrompt("Set password: ")
		if err != nil {
			return err
		}
	}
	profile, err := cfg.NewProfile(name, password)
	if err != nil {
		return err
	}
	return cfg.SetProfile(profile.ID)
}

// exportProfile exports profile after promptong for configured password,
// and then prompting for password on target file.
func exportProfile(ctx *cli.Context) error {
	cfg, err := configuration(ctx)
	if err != nil {
		return err
	}

	password, err := passwordPrompt()
	if err != nil {
		return err
	}
	if ok := security.ComparePasswordAndKey(password, cfg.Key()); !ok {
		return errors.New("invalid password")
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
	cfg, err := configuration(ctx)
	if err != nil {
		return err
	}
	password, err := passwordPrompt()
	if err != nil {
		return err
	}
	key, err := security.NewSHA256FromPassword(password)
	if err != nil {
		return err
	}

	imported, err := config.Import(ctx.String("file"), key)
	if err != nil {
		return err
	}

	if err := cfg.AddProfile(imported.Profile, ctx.Bool("overwrite")); err != nil {
		return err
	}
	if err := cfg.SetProfile(imported.Profile.ID); err != nil {
		return err
	}
	if err := cfg.SetStorageKey(imported.KeyringItem.StorageKey); err != nil {
		return err
	}
	if err := cfg.SetKey(imported.KeyringItem.Key); err != nil {
		return err
	}
	return nil
}
