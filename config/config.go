package config

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"

	"github.com/KarlGW/secman/internal/filesystem"
	"github.com/KarlGW/secman/internal/gob"
	"github.com/KarlGW/secman/internal/security"
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
	Username  string `yaml:"username"`
	u         *user.User
	profile   profile
	profiles  profiles
	// path to the application files for a user.
	path string
	// storagePath is the path to the storage of the persistence file.
	storagePath string
	keyringItem keyringItem
	keyring     keyringer
}

// Option sets options to the Configuration.
type Option func(c *Configuration)

// Configure creates and returns a Configuration. Several options can be provided
// to modify the behaviour.
func Configure(options ...Option) (Configuration, error) {
	cfg := Configuration{}
	for _, option := range options {
		option(&cfg)
	}
	if cfg.keyring == nil {
		cfg.keyring = keyring{}
	}

	if err := cfg.setUser(cfg.Username); err != nil {
		return cfg, err
	}

	if len(cfg.u.HomeDir) == 0 {
		return cfg, errors.New("home directory could not be determined")
	}

	if len(cfg.path) == 0 {
		cfg.path = filepath.Join(cfg.u.HomeDir, dir)
	}

	if err := cfg.Load(); err != nil {
		return cfg, err
	}

	if len(cfg.ProfileID) > 0 {
		if err := cfg.SetProfile(cfg.ProfileID); err != nil {
			return cfg, err
		}
		cfg.storagePath = filepath.Join(cfg.path, "collections", cfg.ProfileID+storageFileSuffix)

		if err := cfg.setupKeyringItem(cfg.ProfileID, false); err != nil {
			return cfg, err
		}
	}

	return cfg, nil
}

// WithProfile sets a profile to the Configuration.
func WithProfile(id string) Option {
	return func(c *Configuration) {
		c.ProfileID = id
	}
}

// WithUser sets the user to the Configuration.
func WithUser(name string) Option {
	return func(c *Configuration) {
		c.Username = name
	}
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
func (c *Configuration) Load() error {
	file, err := filesystem.OpenFile(filepath.Join(c.path, configFile), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	b, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	if err := c.FromYAML(b); err != nil {
		return err
	}

	profiles := profiles{path: filepath.Join(c.path, profilesFile)}
	if err := profiles.Load(); err != nil {
		return err
	}
	c.profiles = profiles

	return nil
}

// Save the Configuration to file.
func (c Configuration) Save() (err error) {
	file, err := filesystem.OpenFile(filepath.Join(c.path, configFile), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if e := file.Close(); e != nil {
			err = e
		}
	}()

	_, err = file.Write(c.YAML())
	return c.profiles.Save()
}

// SetStorageKey sets the storage key to the configuration.
func (c *Configuration) SetStorageKey(key security.Key) error {
	c.keyringItem.StorageKey = key
	if !c.keyringItem.isSet && c.keyringItem.Key.Valid() {
		c.keyringItem.isSet = true
	}
	return c.keyring.Set(application, c.ProfileID, string(c.keyringItem.Encode()))
}

// SetKey sets the key to the configuration.
func (c *Configuration) SetKey(key security.Key) error {
	c.keyringItem.Key = key
	if !c.keyringItem.isSet && c.keyringItem.StorageKey.Valid() {
		c.keyringItem.isSet = true
	}
	return c.keyring.Set(application, c.ProfileID, string(c.keyringItem.Encode()))
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

// Export a configuration and profile
func (c Configuration) Export(dst string, key []byte) error {
	exported := export{
		Version:     exportVersion,
		KeyringItem: c.keyringItem,
	}

	p := profiles{}
	if err := p.Load(); err != nil {
		return err
	}

	if profile, ok := p.p[c.ProfileID]; !ok {
		return errors.New("profile not found")
	} else {
		exported.Profile = profile
	}

	b, err := gob.Encode(exported)
	if err != nil {
		return err
	}
	encrypted, err := security.Encrypt(b, key)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, encrypted, 0600)
}

// NewProfile creates a new profile and generates a new storage
// key for it.
func (c *Configuration) NewProfile(name string, password []byte) (profile, error) {
	if len(name) == 0 {
		name = c.u.Username
	}

	profile, err := c.profiles.newProfile(name)
	if err != nil {
		return profile, err
	}
	// Get keyring item if it already exists for ID, otherwise
	// generate a new one.
	if err := c.setupKeyringItem(profile.ID, true); err != nil {
		return profile, err
	}
	if password == nil {
		return profile, c.Save()
	}
	key, err := security.NewKeyFromPassword(password)
	if err != nil {
		return profile, err
	}
	if err := c.SetKey(key); err != nil {
		return profile, err
	}
	return profile, c.Save()
}

// AddProfile adds a profile to th configuration.
func (c *Configuration) AddProfile(p profile, overwrite bool) error {
	if _, ok := c.profiles.p[p.ID]; ok {
		if !overwrite {
			return errors.New("profile already exist")
		}
	}
	c.profiles.p[p.ID] = p
	return c.Save()
}

// SetPorofile sets profile on the configuration.
func (c *Configuration) SetProfile(id string) error {
	profile, ok := c.profiles.p[id]
	if !ok {
		return errors.New("profile with that ID does not exist")
	}
	c.profile = profile
	c.ProfileID = profile.ID

	return c.Save()
}

// setupKeyringItem sets keys for the Configuration. If storage key does not exist for the provided
// profile ID, a new one will be created.
func (c *Configuration) setupKeyringItem(profileID string, create bool) error {
	id := c.profile.ID
	if len(profileID) > 0 {
		id = profileID
	}
	if len(id) == 0 {
		return errors.New("no profile set or provided")
	}

	val, err := c.keyring.Get(application, id)
	if err == nil {
		if err := c.keyringItem.Decode([]byte(val)); err != nil {
			return err
		}
		return c.keyringItem.Decode([]byte(val))
	}
	if !errors.Is(err, ErrNotFound) {
		return err
	}

	if create {
		key, err := security.NewKey()
		if err != nil {
			return nil
		}
		c.keyringItem = keyringItem{StorageKey: key, isSet: true}
		return c.keyring.Set(application, id, string(c.keyringItem.Encode()))
	}
	return nil
}

// setUser sets user to the Configuration.
func (c *Configuration) setUser(name string) error {
	currentUser, err := currentUser()
	if err != nil {
		return err
	}
	c.u = currentUser
	if len(name) > 0 {
		c.Username = name
	} else {
		c.Username = c.u.Username
	}
	return nil
}

var currentUser = func() (*user.User, error) {
	return user.Current()
}
