package config

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"

	"github.com/KarlGW/secman/internal/fs"
	"github.com/KarlGW/secman/internal/security"
	"github.com/zalando/go-keyring"
	"gopkg.in/yaml.v3"
)

const (
	application       = "secman"
	dir               = ".secman"
	configFile        = "config.yaml"
	profilesFile      = "profiles.yaml"
	storageFileSuffix = ".sec"
)

// configuration for the application.
type configuration struct {
	ProfileID   string `yaml:"profileId"`
	path        string
	storagePath string
	key         [32]byte
}

// Option sets options to the configuration.
type Option func(c *configuration)

// Configure creates and returns a configuration.
func Configure(options ...Option) (cfg configuration, err error) {
	user, err := user.Current()
	if err != nil {
		return
	}

	if len(user.HomeDir) == 0 {
		return cfg, errors.New("home directory could not be determined")
	}

	cfg.path = filepath.Join(user.HomeDir, dir)
	for _, option := range options {
		option(&cfg)
	}

	configFile, err := fs.OpenWithCreateIfNotExist(filepath.Join(cfg.path, configFile))
	if err != nil {
		return
	}

	profilesFile, err := fs.OpenWithCreateIfNotExist(filepath.Join(cfg.path, profilesFile))
	if err != nil {
		return
	}
	defer func() {
		if e := configFile.Close(); e != nil {
			err = e
		}

		if e := profilesFile.Close(); e != nil {
			err = e
		}
	}()

	if err = cfg.Load(configFile); err != nil {
		return
	}

	profiles := profiles{
		p:    make(map[string]profile),
		path: filepath.Dir(profilesFile.Name()),
	}
	if err := profiles.Load(profilesFile); err != nil {
		return cfg, err
	}

	profile := setupProfile(profiles, user.Username)
	cfg.ProfileID = profile.ID
	cfg.storagePath = filepath.Join(cfg.path, cfg.ProfileID+storageFileSuffix)

	key, err := setKey(profile.ID)
	if err != nil {
		return
	}
	cfg.key = key

	if err := cfg.Save(); err != nil {
		return cfg, err
	}
	if err := profiles.Save(); err != nil {
		return cfg, err
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

// Load a configuration from a yaml file.
func (c *configuration) Load(file *os.File) error {
	b, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	return c.FromYAML(b)
}

// Save the configuration to file.
func (c configuration) Save() (err error) {
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

// setupProfile checks profiles for profile by name, and creates it if necessary.
func setupProfile(profiles profiles, username string) profile {
	p := profiles.GetByName(username)
	if p == (profile{}) {
		p = newProfile(username)
		profiles.p[p.ID] = p
	}
	return p
}

// setKey sets key for the configuration. If kehy does not exist for the provided
// profile ID, a new one will be created.
func setKey(profileID string) ([32]byte, error) {
	var key [32]byte
	k, err := keyring.Get(application, profileID)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			key = security.NewKey()
			if err := keyring.Set(application, profileID, string(key[:])); err != nil {
				return key, err
			}
			return key, nil
		} else {
			return key, err
		}
	}
	copy(key[:], k)
	return key, nil
}
