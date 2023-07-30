package secman

import (
	"time"

	"github.com/KarlGW/secman/internal/gob"
)

// Collection represents a collection of secrets.
type Collection struct {
	Secrets      []Secret
	LastModified time.Time
}

// Encode a collection to a gob.
func (c Collection) Encode() []byte {
	encoded, _ := gob.Encode(c)
	return encoded
}

// Decode a collection from a gob.
func (c *Collection) Decode(data []byte) error {
	return gob.Decode(data, c)
}
