package storage

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
func (f File) Save(data []byte) error {
	dir := filepath.Dir(f.path)

	// Check if directory exists. If not. Create it.
	_, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.MkdirAll(dir, 0700); err != nil {
				return fmt.Errorf("%w: %w", ErrFileStorage, err)
			}
		} else {
			return fmt.Errorf("%w: %w", ErrFileStorage, err)
		}
	}

	file, err := os.OpenFile(f.path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrFileStorage, err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil {
			err = fmt.Errorf("%w: %w", ErrFileStorage, err)
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
