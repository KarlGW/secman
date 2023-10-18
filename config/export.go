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

// export is an exported profile and configuration.
type export struct {
	KeyringItem keyringItem
	Profile     profile
	Version     string
}
