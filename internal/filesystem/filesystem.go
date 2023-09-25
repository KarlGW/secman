package filesystem

import (
	"io/fs"
	"os"
	"path/filepath"
)

// OpenFile wraps around the standard library os.OpenFile with addition
// of creating the path to the file if it doesn't exist with os.MkdirAll.
func OpenFile(name string, flag int, perm fs.FileMode) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		return nil, err
	}
	return os.OpenFile(name, flag, perm)
}
