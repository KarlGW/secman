package config

import (
	"bytes"
	"errors"
	"io"
	"os"

	"github.com/KarlGW/secman/internal/filesystem"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// profile contains information of a user profile.
type profile struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	DisplayName string `yaml:"displayName,omitempty"`
	Description string `yaml:"description,omitempty"`
}

// profile contains profiles.
type profiles struct {
	p    map[string]profile
	path string
}

// YAML returns the YAML encoding of the profiles.
func (p profiles) YAML() []byte {
	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	encoder.Encode(p.p)

	return buf.Bytes()
}

// FromYAML sets profiles from yaml.
func (p *profiles) FromYAML(b []byte) error {
	return yaml.Unmarshal(b, p.p)
}

// Load profiles from a yaml file.
func (p *profiles) Load() error {
	if len(p.path) == 0 {
		return errors.New("profile path empty")
	}
	file, err := filesystem.OpenFile(p.path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}

	if p.p == nil {
		p.p = make(map[string]profile)
	}

	b, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return p.FromYAML(b)
}

// Save the profiles to file.
func (p profiles) Save() error {
	file, err := filesystem.OpenFile(p.path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err = file.Write(p.YAML()); err != nil {
		return err
	}
	return file.Close()
}

// Get a profile.
func (p profiles) Get(id string) profile {
	return p.p[id]
}

// newProfile creates and adds a new profile.
func (p *profiles) newProfile(name string) (profile, error) {
	if p.p == nil {
		p.p = make(map[string]profile)
	}

	_profile := profile{
		ID:   newUUID(),
		Name: name,
	}
	if _, ok := p.p[_profile.ID]; ok {
		return profile{}, errors.New("a profile with that ID already exists")
	}
	p.p[_profile.ID] = _profile
	return p.p[_profile.ID], nil
}

var newUUID = func() string {
	return uuid.New().String()
}
