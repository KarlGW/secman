package storage

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/KarlGW/secman/internal/fs"
)

var (
	// ErrStorage is used to wrap general storage errors.
	ErrStorage = errors.New("storage error")
	// ErrStorageSourceNotFound is returned when storage source cannot be found.
	ErrStorageSourceNotFound = errors.New("data source could not be found")
)

// FileSystem represents a storage in a file.
type FileSystem struct {
	path string
}

// FileSystemOptions contains options for the file storage.
type FileSystemOptions struct{}

// FileSystemOption sets an option to the FileSystemOptions.
type FileSystemOption func(options *FileSystemOptions)

// NewFileSystem creates a new File storage.
func NewFileSystem(path string, options ...FileSystemOption) FileSystem {
	return FileSystem{
		path: path,
	}
}

// Save data to the file.
func (f FileSystem) Save(data []byte) (err error) {
	file, err := fs.OpenWithCreateIfNotExist(f.path)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrStorageSourceNotFound, err)
	}

	defer func() {
		if e := file.Close(); e != nil {
			err = fmt.Errorf("%w: %w", ErrStorage, e)
		}
	}()

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("%w: %w", ErrStorage, err)
	}

	return err
}

// Load data from the file.
func (f FileSystem) Load() ([]byte, error) {
	if _, err := os.Stat(f.path); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStorageSourceNotFound, err)
	}

	b, err := os.ReadFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrStorage, err)
	}

	return b, nil
}

// Updated returns the time the file was last modified.
func (f FileSystem) Updated() (time.Time, error) {
	fi, err := os.Stat(f.path)
	if err != nil {
		return time.Time{}, nil
	}
	return fi.ModTime(), nil
}
