package secman

import (
	"time"

	"github.com/KarlGW/secman/internal/gob"
)

// Collection represents a collection of secrets.
type Collection struct {
	secrets       []Secret
	updated       time.Time
	secretsByID   map[string]int
	secretsByName map[string]int
}

// Secrets returns all the secrets in the collection.
func (c Collection) Secrets() []Secret {
	return c.secrets
}

// Secret returns a secret by ID.
func (c Collection) Secret(id string) Secret {
	return c.SecretByID(id)
}

// SecretByID returns a secret by the provided ID.
func (c Collection) SecretByID(id string) Secret {
	i, ok := c.secretsByID[id]
	if !ok {
		return Secret{}
	}
	return c.secrets[i]
}

// SecretByName returns a secret by the provided name.
func (c Collection) SecretByName(name string) Secret {
	i, ok := c.secretsByName[name]
	if !ok {
		return Secret{}
	}
	return c.secrets[i]
}

// Add a secret to the collection. Returns true if secret was added,
// false if not (secret already exists).
func (c *Collection) Add(secret Secret) bool {
	if c.SecretByID(secret.ID).Valid() || c.SecretByName(secret.Name).Valid() {
		return false
	}

	// If maps are not set, initialize them.
	if c.secretsByID == nil {
		c.secretsByID = make(map[string]int)
	}
	if c.secretsByName == nil {
		c.secretsByName = make(map[string]int)
	}

	c.secrets = append(c.secrets, secret)
	index := len(c.secrets) - 1

	c.secretsByID[secret.ID] = index
	c.secretsByName[secret.Name] = index
	c.updated = now()
	return true
}

// Update a secret.
func (c *Collection) Update(secret Secret) bool {
	i, ok := c.secretsByID[secret.ID]
	if !ok {
		return false
	}
	n := now()
	s := c.secrets[i]

	if len(secret.DisplayName) > 0 {
		s.DisplayName = secret.DisplayName
	}

	if secret.Value != nil {
		s.Value = secret.Value
	}
	if secret.Labels != nil {
		s.Labels = secret.Labels
	}
	if secret.Tags != nil {
		s.Tags = secret.Tags
	}
	s.Type = secret.Type
	s.Updated = n

	c.secrets[i] = s
	c.updated = n

	return true
}

// Remove a secret by the provided ID.
func (c *Collection) Remove(id string) bool {
	return c.RemoveByID(id)
}

// RemoveByID removes a secret by the provided ID.
func (c *Collection) RemoveByID(id string) bool {
	if c.secretsByID == nil {
		return false
	}

	i, ok := c.secretsByID[id]
	if !ok {
		return false
	}

	c.remove(i)
	c.updated = now()

	return true
}

// RemoveByID removes a secret by the provided name.
func (c *Collection) RemoveByName(name string) bool {
	if c.secretsByName == nil {
		return false
	}

	i, ok := c.secretsByName[name]
	if !ok {
		return false
	}

	c.remove(i)
	c.updated = now()

	return true
}

// remove the secret by index and update the index maps.
func (c *Collection) remove(i int) {
	c.secrets = append(c.secrets[:i], c.secrets[i+1:]...)
	for k, v := range c.secretsByID {
		if v == i {
			delete(c.secretsByID, k)
		}
		if v > i {
			c.secretsByID[k]--
		}
	}
	for k, v := range c.secretsByName {
		if v == i {
			delete(c.secretsByName, k)
		}
		if v > i {
			c.secretsByName[k]--
		}
	}
}

// Updated returns when the collection was last modified.
func (c Collection) Updated() time.Time {
	return c.updated
}

// encodedCollection is used for encoding a collection.
type encodedCollection struct {
	Secrets       []Secret
	Updated       time.Time
	SecretsByID   map[string]int
	SecretsByName map[string]int
}

// Encode a collection to a gob.
func (c Collection) Encode() []byte {
	collection := encodedCollection{
		Secrets:       c.secrets,
		Updated:       c.updated,
		SecretsByID:   c.secretsByID,
		SecretsByName: c.secretsByName,
	}

	encoded, _ := gob.Encode(collection)
	return encoded
}

// Decode a collection from a gob.
func (c *Collection) Decode(data []byte) error {
	var collection encodedCollection
	if err := gob.Decode(data, &collection); err != nil {
		return err
	}

	c.secrets = collection.Secrets
	c.updated = collection.Updated
	c.secretsByID = collection.SecretsByID
	c.secretsByName = collection.SecretsByName

	return nil
}
