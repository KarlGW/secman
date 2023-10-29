package config

import (
	"strings"

	"github.com/KarlGW/secman/version"
)

var (
	// exportVersion is the major version of the CLI used to
	// create the export.
	exportVersion = strings.Split(version.Version(), ".")[0]
)

// export is an exported profile and key.
type export struct {
	Profile     profile
	KeyringItem keyringItem
	Version     string
}

// Valid returns true if the exported file is valid.
func (e export) Valid() bool {
	return len(e.Profile.ID) > 0 && e.KeyringItem.Valid()
}
