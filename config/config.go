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

// Configuration for the application.
type Configuration struct {
	ProfileID string `yaml:"profileId"`
	// path to the application files for a user.
	path string
	// storagePath is the path to the storage of the persistence file.
	storagePath string
	keyringItem keyringItem
}

// Option sets options to the Configuration.
type Option func(c *Configuration)

// Configure creates and returns a Configuration.
func Configure(options ...Option) (cfg Configuration, err error) {
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

	// Load existing config from file to Configuration.
	if err = cfg.Load(configFile); err != nil {
		return
	}

	if err = cfg.setupProfileAndStoragePath(profilesFile, user.Username); err != nil {
		return
	}

	if err = cfg.setKeyringItem(cfg.ProfileID); err != nil {
		return
	}

	if err = cfg.Save(); err != nil {
		return cfg, err
	}
	return
}

// YAML returns the YAML encoding of the Configuration.
func (c Configuration) YAML() []byte {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	encoder.Encode(c)

	return buf.Bytes()
}

// FromYAML sets Configuration from yaml.
func (c *Configuration) FromYAML(b []byte) error {
	return yaml.Unmarshal(b, c)
}

// Load a Configuration from a yaml file.
func (c *Configuration) Load(file *os.File) error {
	b, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	return c.FromYAML(b)
}

// Save the Configuration to file.
func (c Configuration) Save() (err error) {
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

// SetKey sets the key to the configuration.
func (c *Configuration) SetKey(key security.Key) error {
	c.keyringItem.Key = key
	return keyring.Set(application, c.ProfileID, string(c.keyringItem.Encode()))
}

// Key returns the key.
func (c *Configuration) Key() security.Key {
	return c.keyringItem.Key
}

// StorageKey returns the key for the storage file.
func (c Configuration) StorageKey() security.Key {
	return c.keyringItem.StorageKey
}

// StoragePath returns the storage path of the key file.
func (c Configuration) StoragePath() string {
	return c.storagePath
}

// setupProfileAndStoragePath checks profiles for profile by name, and creates it if necessary.
// Sets up storage path based on profile ID.
func (c *Configuration) setupProfileAndStoragePath(profilesFile *os.File, username string) error {
	profiles := profiles{
		p:    make(map[string]profile),
		path: filepath.Dir(profilesFile.Name()),
	}
	if err := profiles.Load(profilesFile); err != nil {
		return err
	}

	p := profiles.GetByName(username)
	if p == (profile{}) {
		p = newProfile(username)
		profiles.p[p.ID] = p
	}
	c.ProfileID = p.ID
	c.storagePath = filepath.Join(c.path, "collections", c.ProfileID+storageFileSuffix)

	return profiles.Save()
}

// setKeyringItem sets keys for the Configuration. If storage key does not exist for the provided
// profile ID, a new one will be created.
func (c *Configuration) setKeyringItem(profileID string) error {
	val, err := keyring.Get(application, profileID)
	if err == nil {
		if err := c.keyringItem.Decode([]byte(val)); err != nil {
			return err
		}
		return c.keyringItem.Decode([]byte(val))
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		return err
	}

	key, err := security.NewKey()
	if err != nil {
		return nil
	}
	c.keyringItem = keyringItem{StorageKey: key}
	return keyring.Set(application, profileID, string(c.keyringItem.Encode()))
}

// keyringItem contains a key for encryption, a secondary key
// for encryption (if a secondary storage is used) and
// a salted hashed password.
type keyringItem struct {
	// Key set by user. Contains hash.
	Key security.Key `json:"key"`
	// The key for main storage.
	StorageKey security.Key `json:"storageKey"`
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
	i.Key, i.StorageKey = item.Key, item.StorageKey
	return nil
}
