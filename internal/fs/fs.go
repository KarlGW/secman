package fs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// FileMode is an alias for fs.FileMode.
type FileMode = fs.FileMode

const (
	// FileModeReadWriteExecute represents file permissions 0700.
	FileModeReadWriteExecute = 0700
	// FileModeReadWrite represents file permissions 0600.
	FileModeReadWrite = 0600
)

// fileOptions contains options for file handling.
type fileOptions struct {
	directoryPermissions FileMode
	filePermissions      FileMode
	close                bool
	truncate             bool
}

// FileOption is a function that sets file options.
type FileOption func(o *fileOptions)

// OpenCreateIfNotExist creates the file if it does not exist.
// It pre-checks each path part.
func OpenWithCreateIfNotExist(path string, options ...FileOption) (*os.File, error) {
	_, err := os.Stat(path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	opts := fileOptions{
		directoryPermissions: FileModeReadWriteExecute,
		filePermissions:      FileModeReadWrite,
	}

	for _, option := range options {
		option(&opts)
	}

	dir := filepath.Dir(path)
	_, err = os.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.MkdirAll(dir, opts.directoryPermissions); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	var flag int
	if opts.truncate {
		flag = os.O_CREATE | os.O_RDWR | os.O_TRUNC
	} else {
		flag = os.O_CREATE | os.O_RDWR
	}

	file, err := os.OpenFile(path, flag, opts.filePermissions)
	if err != nil {
		return nil, err
	}

	if opts.close {
		if err := file.Close(); err != nil {
			return file, err
		}
	}

	return file, nil
}

// WithDirectoryPermissions sets permissions for directories.
func WithDirectoryPermissions(perm FileMode) FileOption {
	return func(o *fileOptions) {
		o.directoryPermissions = perm
	}
}

// WithFilePermissions sets permissions for files.
func WithFilePermissions(perm FileMode) FileOption {
	return func(o *fileOptions) {
		o.filePermissions = perm
	}
}

// WithClose sets if file should be closed after creation.
func WithClose() FileOption {
	return func(o *fileOptions) {
		o.close = true
	}
}

// WithTruncate sets that file should be truncated when opened
// if it already exists.
func WithTruncate() FileOption {
	return func(o *fileOptions) {
		o.truncate = true
	}
}
