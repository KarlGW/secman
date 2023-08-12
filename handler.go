package secman

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
	key              []byte
}

// HandlerOptions contains options for a Handler.
type HandlerOptions struct {
	SecondaryStorage Storage
	LoadCollection   bool
}

// HandlerOption is a function that sets HandlerOptions.
type HandlerOption func(o *HandlerOptions)

// NewHandler creates and returns a new Handler.
func NewHandler(profileID string, key []byte, storage Storage, options ...HandlerOption) (Handler, error) {
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

	handler := Handler{
		storage:          storage,
		secondaryStorage: opts.SecondaryStorage,
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
	collection, err := loadDecryptDecode(h.storage, h.key)
	if err != nil {
		return err
	}
	h.collection = &collection
	return nil
}

// Save collection.
func (h *Handler) Save() error {
	return encodeEncryptSave(h.storage, *h.collection, h.key)
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

	collection, err := loadDecryptDecode(srcStg, h.key)
	if err != nil {
		return err
	}

	h.collection = &collection
	return encodeEncryptSave(dstStg, *h.collection, h.key)
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
