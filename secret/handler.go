package secret

import (
	"errors"
	"time"

	"github.com/KarlGW/secman/internal/gob"
	"github.com/KarlGW/secman/internal/security"
	stg "github.com/KarlGW/secman/storage"
)

var (
	// ErrProfileID is returned when no profile ID is provided.
	ErrProfileID = errors.New("a profile ID must be provided")
	// ErrStorage is returned when no storage is provided.
	ErrStorage = errors.New("a storage path must be provided when using default storage")
	// ErrSecretNotFound is returned when a secret cannot be found.
	ErrSecretNotFound = errors.New("a secret with that identifier cannot be found")
	// ErrSecretAlreadyExists is returned when a secret already exists.
	ErrSecretAlreadyExists = errors.New("a secret with that ID or name already exists")
)

// Storage is the interface that wraps around methods Save, Load and Updated.
type Storage interface {
	Save(data []byte) error
	Load() ([]byte, error)
	Updated() (time.Time, error)
}

// Handler represents a handler for a Collection and the
// storage configurations.
type Handler struct {
	// collection contains a collection loaded by the handler.
	collection       *Collection
	storage          Storage
	secondaryStorage Storage
	storageKey       security.Key
	key              security.Key
	decrypt          bool
}

// HandlerOptions contains options for a Handler.
type HandlerOptions struct {
	SecondaryStorage Storage
	LoadCollection   bool
}

// HandlerOption is a function that sets HandlerOptions.
type HandlerOption func(o *HandlerOptions)

// NewHandler creates and returns a new Handler.
func NewHandler(profileID string, storageKey, key security.Key, storage Storage, options ...HandlerOption) (Handler, error) {
	if len(profileID) == 0 {
		return Handler{}, ErrProfileID
	}
	if len(storageKey.Value) != KeyLength {
		return Handler{}, ErrInvalidKeyLength
	}
	if len(key.Value) != KeyLength {
		return Handler{}, ErrInvalidKeyLength
	}
	if storage == nil {
		return Handler{}, ErrStorage
	}

	opts := HandlerOptions{}
	for _, option := range options {
		option(&opts)
	}

	handler := Handler{
		storage:          storage,
		secondaryStorage: opts.SecondaryStorage,
		storageKey:       storageKey,
		key:              key,
	}

	if opts.LoadCollection {
		// Attempt to load data. If the data source cannot be found,
		// create a new collection.
		if err := handler.Load(); err != nil {
			if errors.Is(err, stg.ErrStorageSourceNotFound) {
				collection := NewCollection(profileID)
				handler.collection = &collection
			} else {
				return handler, err
			}
		}
	} else {
		collection := NewCollection(profileID)
		handler.collection = &collection
	}

	return handler, nil
}

// Collection returns the current collection set to the handler.
func (h Handler) Collection() *Collection {
	return h.collection
}

// Load collection into Handler.
func (h *Handler) Load() error {
	collection, err := loadDecryptDecode(h.storage, h.storageKey.Value)
	if err != nil {
		return err
	}
	h.collection = &collection
	return nil
}

// Save collection.
func (h *Handler) Save() error {
	return encodeEncryptSave(h.storage, *h.collection, h.storageKey.Value)
}

// Sync current collection with collection from secondary storage (if any).
func (h *Handler) Sync() error {
	if h.secondaryStorage == nil {
		// No secondary storage is set.
		return nil
	}

	updated, err := h.storage.Updated()
	if err != nil {
		return err
	}

	secondaryUpdated, err := h.secondaryStorage.Updated()
	if err != nil {
		return err
	}

	// Check if the remote storage is more recent. This is a shallow check on the state of the
	// secrets. In further updates a deeper check should be made available.
	var srcStg, dstStg Storage
	if secondaryUpdated.After(updated) {
		srcStg = h.secondaryStorage
		dstStg = h.storage
	} else {
		srcStg = h.storage
		dstStg = h.secondaryStorage
	}

	collection, err := loadDecryptDecode(srcStg, h.storageKey.Value)
	if err != nil {
		return err
	}

	h.collection = &collection
	return encodeEncryptSave(dstStg, *h.collection, h.storageKey.Value)
}

// GetSecretByID retrieves a secret by ID.
func (h Handler) GetSecretByID(id string, options ...SecretOption) (Secret, error) {
	opts := SecretOptions{}
	for _, option := range options {
		option(&opts)
	}

	secret := h.collection.GetByID(id)
	if !secret.Valid() {
		return secret, ErrSecretNotFound
	}

	secret.key = h.key.Value
	if opts.decrypt {
		decrypted, err := secret.Decrypt()
		if err != nil {
			return secret, err
		}
		secret.Value = []byte(decrypted)
	}
	return secret, nil
}

// GetSecretByName retrieves a secret by Name.
func (h Handler) GetSecretByName(name string) (Secret, error) {
	secret := h.collection.GetByName(name)
	if !secret.Valid() {
		return secret, ErrSecretNotFound
	}
	secret.key = h.key.Value
	return secret, nil
}

// AddSecret adds a new secret to the collection.
func (h Handler) AddSecret(name, value string, options ...SecretOption) (Secret, error) {
	secret, err := NewSecret(name, value, h.key.Value, options...)
	if err != nil {
		return Secret{}, err
	}
	if !h.collection.Add(secret) {
		return Secret{}, ErrSecretAlreadyExists
	}

	secret, err = h.GetSecretByID(secret.ID)
	if err != nil {
		return secret, err
	}
	return secret, h.Save()
}

// UpdateSecretByUD updates a secret in the collection by ID.
func (h Handler) UpdateSecretByID(id string, options ...SecretOption) (Secret, error) {
	secret := h.collection.GetByID(id)
	if !secret.Valid() {
		return secret, ErrSecretNotFound
	}

	opts := SecretOptions{}
	for _, option := range options {
		option(&opts)
	}
	secret.Set(options...)

	if !h.collection.Update(secret) {
		return secret, ErrSecretNotFound
	}

	return secret, nil
}

// UpdateSecretByName updates a secret in the collection by name.
func (h Handler) UpdateSecretByName(name string, options ...SecretOption) (Secret, error) {
	secret := h.collection.GetByName(name)
	if !secret.Valid() {
		return secret, ErrSecretNotFound
	}

	opts := SecretOptions{}
	for _, option := range options {
		option(&opts)
	}
	secret.Set(options...)

	if !h.collection.Update(secret) {
		return secret, ErrSecretNotFound
	}

	return secret, nil
}

// DeleteSecretByID deletes a secret by ID.
func (h Handler) DeleteSecretByID(id string) error {
	if !h.collection.RemoveByID(id) {
		return ErrSecretNotFound
	}
	return nil
}

// DeleteSecretByName deletes a secret by name.
func (h Handler) DeleteSecretByName(name string) error {
	if !h.collection.RemoveByName(name) {
		return ErrSecretNotFound
	}
	return nil
}

// loadDecryptDecode loads data from storage, decrypts it and finally
// decodes it.
func loadDecryptDecode(storage Storage, key []byte) (Collection, error) {
	var collection Collection
	b, err := storage.Load()
	if err != nil {
		return collection, err
	}

	decrypted, err := security.Decrypt(b, key)
	if err != nil {
		return collection, err
	}

	if err := gob.Decode(decrypted, &collection); err != nil {
		return collection, err
	}
	return collection, nil
}

// encodeEncryptSave encrypt, encodes and finally saves data to storate.
func encodeEncryptSave(storage Storage, collection Collection, key []byte) error {
	encoded, err := gob.Encode(collection)
	if err != nil {
		return err
	}
	encrypted, err := security.Encrypt(encoded, key)
	if err != nil {
		return err
	}
	return storage.Save(encrypted)
}

// WithSecondaryStorage sets secondary storage for the Handler.
func WithSecondaryStorage(storage Storage) HandlerOption {
	return func(o *HandlerOptions) {
		o.SecondaryStorage = storage
	}
}

// WithLoadCollection() sets that collections should be loaded
// when creating a new handler.
func WithLoadCollection() HandlerOption {
	return func(o *HandlerOptions) {
		o.LoadCollection = true
	}
}
