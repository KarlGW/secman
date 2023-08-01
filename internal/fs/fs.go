package fs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

// FileMode is an alias for fs.FileMode.
type FileMode = fs.FileMode

// CreateIfNotExist creates the file if it does not exist.
// It pre-checks each path part.
func CreateIfNotExist(path string, perm ...Permissions) (*os.File, error) {
	perms := permissions{
		directory: 0700,
		file:      0600,
	}

	for _, p := range perm {
		p(&perms)
	}

	dir := filepath.Dir(path)
	_, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.MkdirAll(dir, perms.directory); err != nil {
				return nil, nil
			}
		}
	} else {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, perms.file)
	if err != nil {
		return nil, err
	}

	return file, nil
}

// permissions contains permissions for directories and files.
type permissions struct {
	directory FileMode
	file      FileMode
}

// Permissions is a function that sets permissions.
type Permissions func(perm *permissions)

// WithDirectoryPermissions sets permissions for directories.
func WithDirectoryPermissions(perm FileMode) Permissions {
	return func(p *permissions) {
		p.directory = perm
	}
}

// WithFilePermissions sets permissions for files.
func WithFilePermissions(perm FileMode) Permissions {
	return func(p *permissions) {
		p.file = perm
	}
}
