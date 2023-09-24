package version

var (
	// version contains the version of the application.
	version = ""
	// commit contains the commit hash of the application.
	commit = ""
)

// Version returns the version of the application.
func Version() string {
	return version
}

// Commit returns the commit hash of the application.
func Commit() string {
	return commit
}
