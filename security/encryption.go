// Package security contains functions to encrypt and decrypt data.
// These functions where created/based upon: https://github.com/gtank/cryptopasta.
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
)

var (
	// ErrMalformedData is returned with the provided data is erroneous.
	ErrMalformedData = errors.New("malformed data")
	// ErrInbalidKey is returned when the provided key is invalid.
	ErrInvalidKey = errors.New("invalid key")
)

// Encrypt data with 256-bit AES-GCM encryption using the given key.
func Encrypt(b []byte, key *[32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
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
func Decrypt(b []byte, key *[32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
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

// NewKey generates a new random key for Encrypt/Decrypt.
func NewKey() *[32]byte {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return &key
}

// NewKeyFrom creates a new key based on the provided data.
func NewKeyFrom(b []byte) *[32]byte {
	hash := sha512.Sum512(b)
	out := [32]byte{}
	for i, v := range hash[:32] {
		out[i] = v
	}
	return &out
}
