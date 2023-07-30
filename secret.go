package secman

import (
	"time"

	"github.com/KarlGW/secman/security"
	"github.com/google/uuid"
)

type Type string

const (
	TypeGeneric = iota
	TypeNote
	TypeFile
)

// Secret represents a secret and it's data.
type Secret struct {
	ID          string
	Name        string
	DisplayName string
	// Value should be the encypted value of the secret.
	Value   []byte
	Type    Type
	Labels  []string
	Tags    map[string]string
	Created time.Time
	Updated time.Time
}

type SecretOptions struct {
	DisplayName string
	Type        Type
	Labels      []string
	Tags        map[string]string
	Updated     time.Time
}

type SecretOption func(s *SecretOptions)

// NewSecret creates a new secret.
func NewSecret(name, value string, key *[32]byte, options ...SecretOption) Secret {
	opts := SecretOptions{}
	for _, option := range options {
		option(&opts)
	}

	// Always make use of the provided value and key when creating
	// a secret and ignore one provided by options.
	encrypted, _ := security.Encrypt([]byte(value), key)
	s := Secret{
		ID:          newUUID(),
		Name:        name,
		DisplayName: opts.DisplayName,
		Value:       encrypted,
		Type:        opts.Type,
		Labels:      opts.Labels,
		Tags:        opts.Tags,
		Created:     now(),
	}

	return s
}

// now returns the current time.
var now = func() time.Time {
	return time.Now()
}

// newUUID creates a new UUID as a string.
var newUUID = func() string {
	return uuid.NewString()
}
