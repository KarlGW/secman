package secman

import (
	"bytes"
	"time"

	"encoding/gob"
)

// Collection represents a collection of secrets.
type Collection struct {
	secrets        []Secret
	ids            map[string]int
	names          map[string]int
	profileID      string
	updated        time.Time
	expires        time.Time
	expireInterval time.Duration
}

// CollectionOptions contains options for a Collection.
type CollectionOptions struct {
	Expires        time.Time
	ExpireInterval time.Duration
}

// CollectionOption is a function that sets options
// to CollectionOptions.
type CollectionOption func(o *CollectionOptions)

// NewCollection creates and returns a new collections.
func NewCollection(profileID string, options ...CollectionOption) Collection {
	opts := CollectionOptions{}
	for _, option := range options {
		option(&opts)
	}

	return Collection{
		profileID:      profileID,
		secrets:        make([]Secret, 0),
		ids:            map[string]int{},
		names:          map[string]int{},
		expires:        opts.Expires,
		expireInterval: opts.ExpireInterval,
	}
}

// List all secrets.
func (c Collection) List() []Secret {
	return c.secrets
}

// Get a secret by ID.
func (c Collection) Get(id string) Secret {
	return c.GetByID(id)
}

// GetByID gets a secret by the provided ID.
func (c Collection) GetByID(id string) Secret {
	i, ok := c.ids[id]
	if !ok {
		return Secret{}
	}
	return c.secrets[i]
}

// GetByName gets a secret by the provided name.
func (c Collection) GetByName(name string) Secret {
	i, ok := c.names[name]
	if !ok {
		return Secret{}
	}
	return c.secrets[i]
}

// Add a secret to the collection. Returns true if secret was added,
// false if not (secret already exists).
func (c *Collection) Add(secret Secret) bool {
	if c.GetByID(secret.ID).Valid() || c.GetByName(secret.Name).Valid() {
		return false
	}

	// If maps are not set, initialize them.
	if c.ids == nil {
		c.ids = make(map[string]int)
	}
	if c.names == nil {
		c.names = make(map[string]int)
	}

	c.secrets = append(c.secrets, secret)
	index := len(c.secrets) - 1

	c.ids[secret.ID] = index
	c.names[secret.Name] = index
	c.updated = now()
	return true
}

// Update a secret.
func (c *Collection) Update(secret Secret) bool {
	i, ok := c.ids[secret.ID]
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
	if c.ids == nil {
		return false
	}

	i, ok := c.ids[id]
	if !ok {
		return false
	}

	c.remove(i)
	c.updated = now()

	return true
}

// RemoveByID removes a secret by the provided name.
func (c *Collection) RemoveByName(name string) bool {
	if c.names == nil {
		return false
	}

	i, ok := c.names[name]
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
	for k, v := range c.ids {
		if v == i {
			delete(c.ids, k)
		}
		if v > i {
			c.ids[k]--
		}
	}
	for k, v := range c.names {
		if v == i {
			delete(c.names, k)
		}
		if v > i {
			c.names[k]--
		}
	}
}

// Updated returns when the collection was last modified.
func (c Collection) Updated() time.Time {
	return c.updated
}

// Set options for a collection.
func (c *Collection) Set(options ...CollectionOption) {
	opts := CollectionOptions{}
	for _, option := range options {
		option(&opts)
	}
}

// encodedCollection is used for encoding a collection.
type encodedCollection struct {
	Secrets        []Secret
	IDs            map[string]int
	Names          map[string]int
	ProfileID      string
	Updated        time.Time
	Expires        time.Time
	ExpireInterval time.Duration
}

// GobEncode serializes the Collection into a binary format.
func (c Collection) GobEncode() ([]byte, error) {
	encoded := encodedCollection{
		Secrets:        c.secrets,
		IDs:            c.ids,
		Names:          c.names,
		ProfileID:      c.profileID,
		Updated:        c.updated,
		Expires:        c.expires,
		ExpireInterval: c.expireInterval,
	}

	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	if err := encoder.Encode(encoded); err != nil {
		return nil, nil
	}
	return buf.Bytes(), nil
}

// GobDecode populates the Collection from a binary format.
func (c *Collection) GobDecode(b []byte) error {
	buf := bytes.NewReader(b)
	decoder := gob.NewDecoder(buf)

	encoded := &encodedCollection{}
	if err := decoder.Decode(encoded); err != nil {
		return err
	}

	c.secrets = encoded.Secrets
	c.ids = encoded.IDs
	c.names = encoded.Names
	c.profileID = encoded.ProfileID
	c.updated = encoded.Updated
	c.expires = encoded.Expires
	c.expireInterval = encoded.ExpireInterval

	return nil
}

// WithExpireInterfal sets expire interval on a collection.
func WithExpireInterval(d time.Duration) CollectionOption {
	return func(o *CollectionOptions) {
		o.Expires = time.Now().Add(d)
		o.ExpireInterval = d
	}
}
