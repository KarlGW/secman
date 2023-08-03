package storage

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/KarlGW/secman/internal/fs"
)

var (
	// ErrFileStorage is used to wrap file storage errors.
	ErrFileStorage = errors.New("file storage")
)

// File represents a storage in a file.
type File struct {
	path string
}

// FileOptions contains options for the file storage.
type FileOptions struct{}

// FileOption sets an option to the FilesOptions.
type FileOption func(options *FileOptions)

// NewFile creates a new File storage.
func NewFile(path string, options ...FileOption) *File {
	return &File{
		path: path,
	}
}

// Save data to the file.
func (f File) Save(data []byte) (err error) {
	file, err := fs.OpenWithCreateIfNotExist(f.path)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFileStorage, err)
	}

	defer func() {
		if e := file.Close(); e != nil {
			err = fmt.Errorf("%w: %w", ErrFileStorage, e)
		}
	}()

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("%w: %w", ErrFileStorage, err)
	}

	return err
}

// Load data from the file.
func (f File) Load() ([]byte, error) {
	if _, err := os.Stat(f.path); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFileStorage, err)
	}

	b, err := os.ReadFile(f.path)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFileStorage, err)
	}

	return b, nil
}

// Updated returns the time the file was last modified.
func (f File) Updated() (time.Time, error) {
	fi, err := os.Stat(f.path)
	if err != nil {
		return time.Time{}, nil
	}
	return fi.ModTime(), nil
}
