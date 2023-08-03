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

	localUpd, err := h.storage.local.Updated()
	if err != nil {
		return err
	}

	remoteUpd, err := h.storage.remote.Updated()
	if err != nil {
		return err
	}

	// Check if the remote storage is more recent. This is a shallow check on the state of the
	// secrets. In further updates a deeper check should be made available.
	var srcStg, dstStg Storage
	if remoteUpd.After(localUpd) {
		srcStg = h.storage.remote
		dstStg = h.storage.local
	} else {
		srcStg = h.storage.local
		dstStg = h.storage.remote
	}

	collection, err := loadDecryptDecode(srcStg, h.key)
	if err != nil {
		return err
	}

	h.collection = collection
	encrypted, err := security.Encrypt(collection.Encode(), h.key)
	if err != nil {
		return err
	}

	return dstStg.Save(encrypted)
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
