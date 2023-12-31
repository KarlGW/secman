// Package security contains functions to encrypt and decrypt data.
// These functions where created/based upon: https://github.com/gtank/cryptopasta.
package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"strconv"

	"golang.org/x/crypto/argon2"
)

var (
	// ErrMalformedData is returned with the provided data is erroneous.
	ErrMalformedData = errors.New("malformed data")
	// ErrInvalidKey is returned when the provided key is invalid.
	ErrInvalidKey = errors.New("invalid key")
	// ErrInvalidKeyLength is returned when the provided key is not the correct size.
	ErrInvalidKeyLength = errors.New("invalid key length, must be " + strconv.Itoa(KeyLength) + " bytes")
)

const (
	// HashLength is the length of the hash byte slice.
	HashLength = 16
	// KeyLength is the length of the key byte slice.
	KeyLength = 32
)

var (
	delimiter = []byte("$")
)

// Encrypt data with 256-bit AES-GCM encryption using the given key.
func Encrypt(b []byte, key []byte) ([]byte, error) {
	if len(key) != KeyLength {
		return nil, ErrInvalidKeyLength
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, b, nil), nil
}

// Decrypt data encrypted with 256-bit AES-GCM encryption using the given key.
func Decrypt(b []byte, key []byte) ([]byte, error) {
	if len(key) != KeyLength {
		return nil, ErrInvalidKeyLength
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(b) < gcm.NonceSize() {
		return nil, ErrMalformedData
	}

	data, err := gcm.Open(
		nil,
		b[:gcm.NonceSize()],
		b[gcm.NonceSize():],
		nil,
	)
	if err != nil {
		return nil, ErrInvalidKey
	}

	return data, nil
}

// NewHash generates a new random key with argon2id.
func NewKey() (Key, error) {
	salt, err := generateBytes(16)
	if err != nil {
		return Key{}, err
	}
	b, err := generateBytes(KeyLength)
	if err != nil {
		return Key{}, err
	}

	return Key{
		Value: idKey(b, salt, KeyLength),
		Salt:  salt,
	}, nil
}

// NewKeyFromPassword creates a new key from the provided password
// using argon2id.
func NewKeyFromPassword(password []byte) (Key, error) {
	salt, err := generateBytes(HashLength)
	if err != nil {
		return Key{}, err
	}

	return Key{
		Value: idKey(password, salt, KeyLength),
		Salt:  salt,
	}, nil
}

// NewSHA256FromPassword creates a new SHA256 from the provided
// password.
func NewSHA256FromPassword(password []byte) ([]byte, error) {
	h := sha256.New()
	if _, err := h.Write(password); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// ComparePasswordAndKey compares the provided password with
// the provided key.
func ComparePasswordAndKey(password []byte, key Key) bool {
	hash := idKey(password, key.Salt, KeyLength)
	if len(hash) != len(key.Value) {
		return false
	}
	return subtle.ConstantTimeCompare(hash, key.Value) == 1
}

// Key contains a hashed value and the salt used to hash
// it.
type Key struct {
	Value, Salt []byte
}

// Encode the key for persistance.
// Format: base64(salt)$base64(hash)
func (k Key) Encode() []byte {
	encodedSalt := make([]byte, base64.StdEncoding.EncodedLen(len(k.Salt)))
	base64.StdEncoding.Encode(encodedSalt, k.Salt)

	encodedHash := make([]byte, base64.StdEncoding.EncodedLen(len(k.Value)))
	base64.StdEncoding.Encode(encodedHash, k.Value)

	return concatenate(encodedSalt, delimiter, encodedHash)
}

// Decodes the provided bytes into a Key.
// Format: base64(salt)$base64(hash)
func (k *Key) Decode(b []byte) error {
	parts := bytes.Split(b, delimiter)
	if len(parts) != 2 {
		return errors.New("invalid data")
	}
	encodedSalt := parts[0]
	encodedHash := parts[1]

	salt := make([]byte, base64.StdEncoding.DecodedLen(len(encodedSalt)))
	n, err := base64.StdEncoding.Decode(salt, encodedSalt)
	if err != nil {
		return err
	}
	k.Salt = salt[:n]

	hash := make([]byte, base64.StdEncoding.DecodedLen(len(encodedHash)))
	n, err = base64.StdEncoding.Decode(hash, encodedHash)
	if err != nil {
		return err
	}
	k.Value = hash[:n]

	return nil
}

// Valid checks if a key is valid
func (k Key) Valid() bool {
	return k.Value != nil
}

// generateBytes generates a random [n]byte.
func generateBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// concatenate slices.
func concatenate[S ~[]E, E any](elems ...S) S {
	var result S
	for _, e := range elems {
		result = append(result, e...)
	}
	return result
}

// idKey is a convenience function that returns a key
// using argon2id with set values for time, memory and
// key length.
func idKey(b, s []byte, l uint32) []byte {
	return argon2.IDKey(b, s, 1, 1<<15, 1, l)
}
