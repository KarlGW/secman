package secman

import (
	"errors"
	"time"

	"github.com/KarlGW/secman/internal/gob"
	"github.com/KarlGW/secman/internal/security"
)

var (
	// ErrProfileID is returned when no profile ID is provided.
	ErrProfileID = errors.New("a profile ID must be provided")
	// ErrStorage is returned when no storage is provided.
	ErrStorage = errors.New("a storage path must be provided when using default storage")
)

// Storage is the interface that wraps around methods Save and Load.
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
	key              [32]byte
}

// HandlerOptions contains options for a Handler.
type HandlerOptions struct {
	SecondaryStorage Storage
}

// HandlerOption is a function that sets HandlerOptions.
type HandlerOption func(o *HandlerOptions)

// NewHandler creates and returns a new Handler.
func NewHandler(profileID string, key [32]byte, storage Storage, options ...HandlerOption) (Handler, error) {
	if len(profileID) == 0 {
		return Handler{}, ErrProfileID
	}
	if storage == nil {
		return Handler{}, ErrStorage
	}

	opts := HandlerOptions{}
	for _, option := range options {
		option(&opts)
	}

	collection := NewCollection(profileID)

	return Handler{
		collection:       &collection,
		storage:          storage,
		secondaryStorage: opts.SecondaryStorage,
		key:              key,
	}, nil
}

// Collection returns the current collection set to the handler.
func (h Handler) Collection() *Collection {
	return h.collection
}

// Sync current collection with collection from secondary storage (if any).
func (h *Handler) Sync() error {
	if h.secondaryStorage == nil {
		// No secondary storage is set. Return nil.
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

	collection, err := loadDecryptDecode(srcStg, h.key)
	if err != nil {
		return err
	}

	h.collection = &collection

	encoded, err := gob.Encode(h.collection)
	if err != nil {
		return err
	}
	encrypted, err := security.Encrypt(encoded, h.key)
	if err != nil {
		return err
	}
	return dstStg.Save(encrypted)
}

// loadDecryptDecode loads data from a storage, decrypts it and finally
// decodes it.
func loadDecryptDecode(storage Storage, key [32]byte) (Collection, error) {
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

// WithSecondaryStorage sets secondary storage for the Handler.
func WithSecondaryStorage(storage Storage) HandlerOption {
	return func(o *HandlerOptions) {
		o.SecondaryStorage = storage
	}
}
