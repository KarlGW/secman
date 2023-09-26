package command

import (
	"errors"
	"syscall"

	"github.com/KarlGW/secman/config"
	"github.com/KarlGW/secman/output"
	"github.com/KarlGW/secman/secret"
	"github.com/KarlGW/secman/storage"
	"github.com/urfave/cli/v2"
	"golang.org/x/term"
)

var (
	ErrUnableToRetrieveConfig = errors.New("unable to retrieve config")
	ErrUnableToRetieveHandler = errors.New("unable to retrieve handler")
)

// configure creates a configuration and sets it to the provided *cli.Context.
func configure(ctx *cli.Context) error {
	cfg, err := config.Configure()
	if err != nil {
		return err
	}
	ctx.App.Metadata["config"] = cfg
	return nil
}

// configuration returns the configuration from the provided *cli.Context.
func configuration(ctx *cli.Context) (config.Configuration, error) {
	cfg, ok := ctx.App.Metadata["config"].(config.Configuration)
	if !ok {
		return config.Configuration{}, ErrUnableToRetrieveConfig
	}
	return cfg, nil
}

// initHandler performs the necessary steps to setup a handler and
// set it to the provided *cli.Context.
func initHandler(ctx *cli.Context) error {
	cfg, err := config.Configure()
	if err != nil {
		return err
	}

	if len(cfg.StorageKey().Value) != secret.KeyLength {
		return errors.New("a key must be set for storage")
	}
	if len(cfg.Key().Value) != secret.KeyLength {
		return errors.New("a key must be set")
	}

	handler, err := secret.NewHandler(
		cfg.ProfileID,
		cfg.StorageKey(),
		cfg.Key(),
		storage.NewFileSystem(cfg.StoragePath()),
		secret.WithLoadCollection(),
	)
	if err != nil {
		return err
	}
	ctx.App.Metadata["handler"] = handler
	return nil
}

// handler retrieves the handler from the provided *cli.Context.
func handler(ctx *cli.Context) (*secret.Handler, error) {
	handler, ok := ctx.App.Metadata["handler"].(*secret.Handler)
	if !ok {
		return nil, ErrUnableToRetieveHandler
	}
	return handler, nil
}

// passwordPrompt prompts for entering a password.
func passwordPrompt() ([]byte, error) {
	output.Print("Enter password: ")
	p, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return nil, err
	}
	output.PrintEmptyln()
	return p, nil
}
