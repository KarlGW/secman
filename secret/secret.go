package secret

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/KarlGW/secman/internal/security"
	"github.com/google/uuid"
)

var (
	// ErrInvalidKey is returned when the provided key is invalid.
	ErrInvalidKey = security.ErrInvalidKey
	// ErrInvalidKeyLength is returned when the provided key is not the correct size.
	ErrInvalidKeyLength = security.ErrInvalidKeyLength
)

var (
	// ErrSecretEncrypt is returned when an error is encountered when encrypting a secret.
	ErrSecretEncrypt = errors.New("encrypting secret")
	// ErrSecretDecrypt is returned when an error is encountered when decrypting a secret.
	ErrSecretDecrypt = errors.New("decrypting secret")
)

const (
	KeyLength = security.KeyLength
)

// Type represents the type of secret.
type Type uint8

const (
	// TypeGeneric represents a generic secret.
	TypeGeneric Type = iota
	// TypeCredential represents a credential secret.
	TypeCredential
	// TypeNote represents a secret note.
	TypeNote
	// TypeFile represents a secret file.
	TypeFile
)

// String returns the string representation of a secret type.
func (t Type) String() string {
	switch t {
	case TypeGeneric:
		return "generic"
	case TypeCredential:
		return "credential"
	case TypeNote:
		return "note"
	case TypeFile:
		return "file"
	}
	return ""
}

// MarshalJSON marshals the Type to its string representation
// for JSON.
func (t Type) MarshalJSON() ([]byte, error) {
	return []byte("\"" + t.String() + "\""), nil
}

// UnmarhsalJSON unmarshals the Type to its Type (uint8)
// representation.
func (t *Type) UnmarhsalJSON(data []byte) error {
	i, err := strconv.ParseUint("", 10, 8)
	if err != nil {
		return err
	}
	*t = Type(i)
	return nil
}

// Secret represents a secret and its data.
type Secret struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	// Value is the encrypted value of a secret.
	Value   []byte            `json:"-"`
	Type    Type              `json:"type"`
	Labels  []string          `json:"labels,omitempty"`
	Tags    map[string]string `json:"tags,omitempty"`
	Created time.Time         `json:"created,omitempty"`
	Updated time.Time         `json:"updated,omitempty"`
	// Key for encrypting the secret. The key is not persisted
	// or transmitted.
	key []byte `json:"-"`
}

// SecretOptions contains options for a secret.
type SecretOptions struct {
	DisplayName string
	Value       []byte
	Type        Type
	Labels      []string
	Tags        map[string]string
	Updated     time.Time
	key         []byte
}

// SecretOption is a function to set SecretOptions.
type SecretOption func(options *SecretOptions)

// NewSecret creates a new secret.
func NewSecret(name, value string, key []byte, options ...SecretOption) (Secret, error) {
	if len(key) != KeyLength {
		return Secret{}, ErrInvalidKeyLength
	}
	opts := SecretOptions{}
	for _, option := range options {
		option(&opts)
	}

	// Always make use of the provided value and key when creating
	// a secret and ignore one provided by options.
	encrypted, err := security.Encrypt([]byte(value), key)
	if err != nil {
		return Secret{}, fmt.Errorf("%w: %w", ErrSecretEncrypt, err)
	}

	return Secret{
		ID:          newUUID(),
		Name:        name,
		DisplayName: opts.DisplayName,
		Value:       encrypted,
		Type:        opts.Type,
		Labels:      opts.Labels,
		Tags:        opts.Tags,
		Created:     now(),
		key:         key,
	}, nil
}

// Valid returns true if the secret is valid, false if not.
func (s Secret) Valid() bool {
	return len(s.ID) > 0 && len(s.Name) > 0
}

// Decrypt and return the Value of the Secret.
func (s *Secret) Decrypt(options ...SecretOption) ([]byte, error) {
	opts := SecretOptions{}
	for _, option := range options {
		option(&opts)
	}
	if opts.key != nil && len(opts.key) == KeyLength {
		s.key = opts.key
	}

	decrypted, err := security.Decrypt(s.Value, s.key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSecretDecrypt, err)
	}
	return decrypted, nil
}

// Set options to a secret.
func (s *Secret) Set(options ...SecretOption) error {
	opts := SecretOptions{}
	for _, option := range options {
		option(&opts)
	}

	// Check if a key is provided in options, and set it
	// to key.
	var key, previousKey []byte
	if len(opts.key) > 0 {
		previousKey = s.key
		key = opts.key
	} else {
		key = s.key
	}

	if len(opts.Value) > 0 {
		encrypted, err := security.Encrypt(opts.Value, key)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSecretEncrypt, err)
		}
		s.Value = encrypted
	}

	if previousKey != nil {
		decrypted, err := security.Decrypt(s.Value, previousKey)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSecretDecrypt, err)
		}
		s.key = key
		encrypted, err := security.Encrypt(decrypted, s.key)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSecretEncrypt, err)
		}
		s.Value = encrypted
	}

	if len(opts.DisplayName) > 0 {
		s.DisplayName = opts.DisplayName
	}
	if opts.Type != s.Type {
		s.Type = opts.Type
	}
	if len(opts.Labels) > 0 {
		s.Labels = opts.Labels
	}
	if len(opts.Tags) > 0 {
		s.Tags = opts.Tags
	}
	return nil
}

// JSON returns the JSON encoding of Secret.
func (s Secret) JSON() []byte {
	b, _ := json.MarshalIndent(s, "", "  ")
	return b
}

// Secrets is a slice of Secret.
type Secrets []Secret

// JSON returns the JSON encoding of Secrets.
func (s Secrets) JSON() []byte {
	b, _ := json.MarshalIndent(s, "", "  ")
	return b
}

// WithValue sets the value to SecretOptions.
func WithValue(value []byte) SecretOption {
	return func(o *SecretOptions) {
		o.Value = value
	}
}

// WithKey sets key to SecretOptions.
func WithKey(key []byte) SecretOption {
	return func(o *SecretOptions) {
		o.key = key
	}
}

// now returns the current time.
var now = func() time.Time {
	return time.Now()
}

// newUUID creates a new UUID as a string.
var newUUID = func() string {
	return uuid.NewString()
}

const (
	charset        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUWXYZ"
	specialCharset = "_-!?=()&%"
)

// Generate a random string of the specified amount of characters,
// and if special characters should be included.
func Generate(length int, specialChars bool) string {
	var builder strings.Builder
	builder.Grow(length)

	chars := charset
	if specialChars {
		chars += specialCharset
	}

	for i := 0; i < length; i++ {
		builder.WriteByte(chars[rand.Intn(len(chars))])
	}

	return builder.String()
}
