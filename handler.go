package secman

// storage contains local and remote storage if any.
type storage struct {
	local  Storage
	remote Storage
}

// Storage is the interface that wraps around methods Save and Load.
type Storage interface {
	Save(data []byte) error
	Load() ([]byte, error)
}

// Handler represents a handler for collections and the
// storage configurations.
type Handler struct {
	// collection contains a collection loaded by the handler.
	collection Collection
	// storage contains the storage for the collection and a remote storage
	// if any.
	storage storage
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

	b, err := h.storage.local.Load()
	if err != nil {
		return err
	}

	var localCollection Collection
	if err := localCollection.Decode(b); err != nil {
		return err
	}

	b, err = h.storage.remote.Load()
	if err != nil {
		return err
	}

	var remoteCollection Collection
	if err := remoteCollection.Decode(b); err != nil {
		return err
	}

	var collection Collection
	if remoteCollection.LastModified.After(localCollection.LastModified) {
		h.collection = remoteCollection
		return h.storage.local.Save(collection.Encode())
	} else {
		h.collection = localCollection
		return h.storage.remote.Save(collection.Encode())
	}
}
