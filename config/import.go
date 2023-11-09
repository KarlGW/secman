package config

import (
	"os"

	"github.com/KarlGW/secman/internal/gob"
	"github.com/KarlGW/secman/internal/security"
)

// Import importable configuration and profile from file.
func Import(src string, key []byte) (export, error) {
	b, err := os.ReadFile(src)
	if err != nil {
		return export{}, err
	}
	decrypted, err := security.Decrypt(b, key)
	if err != nil {
		return export{}, err
	}
	var exported export
	if err := gob.Decode(decrypted, &exported); err != nil {
		return export{}, err
	}
	return exported, nil
}
