package config

import (
	"bytes"
	"io"
	"os"
	"path/filepath"

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
func (p *profiles) Load(file *os.File) error {
	if p.p == nil {
		p.p = make(map[string]profile)
	}

	b, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	return p.FromYAML(b)
}

// Save the profiles to file.
func (p profiles) Save() (err error) {
	file, err := filesystem.OpenFile(filepath.Join(p.path, profilesFile), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if e := file.Close(); e != nil {
			err = e
		}
	}()

	_, err = file.Write(p.YAML())
	return err
}

// GetByName gets a profile by name.
func (p profiles) GetByName(name string) profile {
	for k, v := range p.p {
		if v.Name == name {
			return p.p[k]
		}
	}
	return profile{}
}

// newProfile creates and returns a new profile.
func newProfile(name string) profile {
	return profile{
		ID:   uuid.New().String(),
		Name: name,
	}
}
