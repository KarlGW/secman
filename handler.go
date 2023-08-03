package secman

import (
	"time"

	"github.com/KarlGW/secman/internal/security"
)

// storage contains local and remote storage if any.
type storage struct {
	local  Storage
	remote Storage
}

// Storage is the interface that wraps around methods Save and Load.
type Storage interface {
	Save(data []byte) error
	Load() ([]byte, error)
	Updated() (time.Time, error)
}

// Handler represents a handler for collections and the
// storage configurations.
type Handler struct {
	// collection contains a collection loaded by the handler.
	collection Collection
	// storage contains the storage for the collection and a remote storage
	// if any.
	storage storage
	key     *[32]byte
}

// Collection returns the current collection set to the handler.
func (h Handler) Collection() Collection {
	return h.collection
}

// Sync current collection with collection from remote storage (if any).
func (h *Handler) Sync() error {
	if h.storage.remote == nil {
		// No remote storage is set. Return nil.
		return nil
	}

	localCollection, err := loadDecryptDecode(h.storage.local, h.key)
	if err != nil {
		return err
	}

	remoteCollection, err := loadDecryptDecode(h.storage.remote, h.key)
	if err != nil {
		return err
	}

	var collection Collection
	var saveFunc func(data []byte) error
	if remoteCollection.Updated().After(localCollection.Updated()) {
		collection = remoteCollection
		saveFunc = h.storage.local.Save
	} else {
		collection = localCollection
		saveFunc = h.storage.remote.Save
	}

	h.collection = collection
	encrypted, err := security.Encrypt(collection.Encode(), h.key)
	if err != nil {
		return err
	}

	return saveFunc(encrypted)
}

// loadDecryptDecode loads data from a storage, decrypts it and finally
// decodes it.
func loadDecryptDecode(storage Storage, key *[32]byte) (Collection, error) {
	var collection Collection
	b, err := storage.Load()
	if err != nil {
		return collection, err
	}

	decrypted, err := security.Decrypt(b, key)
	if err != nil {
		return collection, err
	}

	if err := collection.Decode(decrypted); err != nil {
		return collection, err
	}

	return collection, nil
}
