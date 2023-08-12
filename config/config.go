package config

import (
	"bytes"
	"encoding/json"
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
	key         []byte
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

// Key returns the key set to the configuration.
func (c configuration) Key() []byte {
	return c.key
}

// StoragePath returns the storage path of the key file.
func (c configuration) StoragePath() string {
	return c.storagePath
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
func setKey(profileID string) ([]byte, error) {
	var item keyringItem
	val, err := keyring.Get(application, profileID)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			key, err := security.NewKey()
			if err != nil {
				return nil, nil
			}
			item = keyringItem{Key: key.Value}
			if err := keyring.Set(application, profileID, string(item.Encode())); err != nil {
				return nil, err
			}
			return item.Key, nil
		} else {
			return nil, err
		}
	}
	if err := item.Decode([]byte(val)); err != nil {
		return nil, err
	}
	return item.Key, nil
}

// keyringItem contains a key for encryption, a secondary key
// for encryption (if a secondary storage is used) and
// a salted hashed password.
type keyringItem struct {
	// The encrption key for main storage.
	Key []byte `json:"key"`
	// The encryption key for secondary storage (if any).
	SecondaryKey []byte `json:"secondaryKey"`
	// Password set by user.
	Password []byte `json:"password"`
}

// Encode the keyringItem to be stored in the keychain.
func (i keyringItem) Encode() []byte {
	b, _ := json.Marshal(i)
	return b
}

// Decode data into a keyringItem.
func (i *keyringItem) Decode(b []byte) error {
	item := keyringItem{}
	if err := json.Unmarshal(b, &item); err != nil {
		return err
	}
	i.Key, i.SecondaryKey, i.Password = item.Key, item.SecondaryKey, item.Password
	return nil
}
