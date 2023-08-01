package config

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

	"github.com/KarlGW/secman/internal/fs"
	"gopkg.in/yaml.v3"
)

const (
	dir        = ".secman"
	configFile = "config.yaml"
)

// configuration for the application.
type configuration struct {
	path string
	key  *[32]byte
}

// Option sets options to the configuration.
type Option func(c *configuration)

// Configure creates and returns a configuration.
func Configure(options ...Option) (cfg configuration, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	cfg.path = filepath.Join(home, dir)
	for _, option := range options {
		option(&cfg)
	}

	configFile, err := fs.OpenWithCreateIfNotExist(filepath.Join(cfg.path, configFile))
	if err != nil {
		return
	}
	defer func() {
		if e := configFile.Close(); e != nil {
			err = e
		}
	}()

	b, err := io.ReadAll(configFile)
	if err != nil {
		return
	}

	if err = cfg.FromYAML(b); err != nil {
		return
	}

	return cfg, err
}

// YAML returns the YAML encoding of the configuration.
func (c configuration) YAML() []byte {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	encoder.Encode(c)

	return buf.Bytes()
}

// FromYAML sets configuration from yaml.
func (c *configuration) FromYAML(b []byte) error {
	return yaml.Unmarshal(b, c)
}

// Save the configuration to local storage.
func (c *configuration) Save() (err error) {
	file, err := fs.OpenWithCreateIfNotExist(filepath.Join(c.path, configFile))
	if err != nil {
		return err
	}
	defer func() {
		if e := file.Close(); e != nil {
			err = e
		}
	}()

	_, err = file.Write(c.YAML())
	return err
}

// Key returns the key configured the application.
func (c configuration) Key() *[32]byte {
	return c.key
}

// WithKey sets the key on the configuration.
func WithKey(key *[32]byte) Option {
	return func(c *configuration) {
		c.key = key
	}
}
