package config

import (
	"encoding/json"

	"github.com/KarlGW/secman/internal/security"
	kr "github.com/zalando/go-keyring"
)

var (
	ErrNotFound = kr.ErrNotFound
)

// keyringer is the interface that wraps around method Get and set.
type keyringer interface {
	Get(string, string) (string, error)
	Set(string, string, string) error
}

// keyring satisfies keyringer.
type keyring struct{}

// Get value from keyring.
func (k keyring) Get(service, user string) (string, error) {
	return kr.Get(service, user)
}

// Set value to keyring.
func (k keyring) Set(service, user, password string) error {
	return kr.Set(service, user, password)
}

// keyringItem contains a key for encryption, a secondary key
// for encryption (if a secondary storage is used) and
// a salted hashed password.
type keyringItem struct {
	// Key set by user. Contains hash.
	Key security.Key `json:"key"`
	// The key for main storage.
	StorageKey security.Key `json:"storageKey"`
	// isSet indicates if the keyring item is set.
	isSet bool
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

// Valid checks if the keyringItem is valid.
func (i keyringItem) Valid() bool {
	return i.isSet && i.Key.Valid() && i.StorageKey.Valid()
}
