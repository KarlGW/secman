package config

// Profile contains information of a user profile.
type Profile struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	DisplayName string `yaml:"displayName,omitempty"`
	Description string `yaml:"description,omitempty"`
	key         *[32]byte
}
