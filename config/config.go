package config

import (
	"bytes"
	"io"
	"os"
	"os/user"
	"path/filepath"

	"github.com/KarlGW/secman/internal/fs"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

const (
	application = "secman"
	dir         = ".secman"
	configFile  = "config.yaml"
)

// configuration for the application.
type configuration struct {
	path     string
	key      *[32]byte
	Profile  string             `yaml:"profile"`
	Profiles map[string]Profile `yaml:"profiles"`
	profile  Profile
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

	if err = cfg.FromYAMLFile(configFile); err != nil {
		return
	}

	if len(cfg.Profile) == 0 {
		user, err := user.Current()
		if err != nil {
			return cfg, err
		}
		cfg.Profile = user.Username
	}

	if cfg.Profiles == nil {
		cfg.Profiles = make(map[string]Profile)
	}

	profile, ok := cfg.Profiles[cfg.Profile]
	if !ok {
		profile = Profile{
			ID:   uuid.New().String(),
			Name: cfg.Profile,
		}
		cfg.Profiles[cfg.Profile] = profile
		if err := cfg.Save(); err != nil {
			return cfg, err
		}
	}

	return
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

// FromYAMLFile sets configuration from a yaml file.
func (c *configuration) FromYAMLFile(file *os.File) error {
	b, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	return c.FromYAML(b)
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
