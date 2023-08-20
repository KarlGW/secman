package command

import (
	"errors"

	"github.com/KarlGW/secman/config"
	"github.com/KarlGW/secman/secret"
	"github.com/KarlGW/secman/storage"
	"github.com/urfave/cli/v2"
)

var (
	ErrUnableToRetrieveConfig = errors.New("unable to retrieve config")
	ErrUnableToRetieveHandler = errors.New("unable to retrieve handler")
)

// configure creates a configuration and sets it to the provided *cli.Context.
func configure(c *cli.Context) error {
	cfg, err := config.Configure()
	if err != nil {
		return err
	}
	c.App.Metadata["config"] = cfg
	return nil
}

// configuration returns the configuration from the provided *cli.Context.
func configuration(c *cli.Context) (config.Configuration, error) {
	cfg, ok := c.App.Metadata["config"].(config.Configuration)
	if !ok {
		return config.Configuration{}, ErrUnableToRetrieveConfig
	}
	return cfg, nil
}

// initHandler performs the necessary steps to setup a handler and
// set it to the provided *cli.Context.
func initHandler(c *cli.Context) error {
	config, err := configuration(c)
	if err != nil {
		return err
	}
	if len(config.StorageKey().Value) != secret.KeyLength {
		return errors.New("a key must be set for storage")
	}
	if len(config.Key().Value) != secret.KeyLength {
		return errors.New("a key must be set")
	}

	handler, err := secret.NewHandler(
		config.ProfileID,
		config.Key(),
		config.StorageKey(),
		storage.NewFileSystem(config.StoragePath()),
		secret.WithLoadCollection(),
	)
	if err != nil {
		return err
	}
	c.App.Metadata["handler"] = handler
	return nil
}

// handler retrieves the handler from the provided *cli.Context.
func handler(c *cli.Context) (*secret.Handler, error) {
	handler, ok := c.App.Metadata["handler"].(*secret.Handler)
	if !ok {
		return nil, ErrUnableToRetieveHandler
	}
	return handler, nil
}
