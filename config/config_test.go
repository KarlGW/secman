package config

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/KarlGW/secman/internal/security"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	user1Path = filepath.Join("../testdata", "user1", dir)
	user2Path = filepath.Join("../testdata", "user2", dir)
	user3Path = filepath.Join("../testdata", "user3", dir)
)

func TestConfigure(t *testing.T) {
	var tests = []struct {
		name    string
		input   []Option
		want    Configuration
		wantErr error
		before  func() error
	}{
		{
			name: "with configuration",
			input: []Option{
				func(c *Configuration) {
					c.path = user1Path
					c.keyring.Set("", "user1", "{}")
				},
			},
			want: Configuration{
				Username:  "user1",
				ProfileID: "AAAA",
				profile: profile{
					ID:   "AAAA",
					Name: "user1",
				},
				profiles: profiles{
					p: map[string]profile{
						"AAAA": {
							ID:   "AAAA",
							Name: "user1",
						},
					},
					path: filepath.Join(user1Path, profilesFile),
				},
				path:        user1Path,
				storagePath: filepath.Join(user1Path, "collections/AAAA.sec"),
				keyring: &mockKeyring{
					data: map[string]string{
						"user1": "{}",
					},
				},
			},
			before: func() error {
				currentUser = func() (*user.User, error) {
					return &user.User{
						Username: "user1",
						HomeDir:  "testdata/user1",
					}, nil
				}
				return nil
			},
		},
		{
			name: "default bare config",
			input: []Option{
				func(c *Configuration) {
					c.path = user2Path
				},
			},
			want: Configuration{
				Username: "user2",
				profiles: profiles{
					p:    map[string]profile{},
					path: filepath.Join(user2Path, profilesFile),
				},
				path:    user2Path,
				keyring: &mockKeyring{},
			},
			wantErr: nil,
			before: func() error {
				newUUID = func() string {
					return "BBBB"
				}
				currentUser = func() (*user.User, error) {
					return &user.User{
						Username: "user2",
						HomeDir:  "testdata/user2",
					}, nil
				}
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Cleanup(func() {
				_ = os.RemoveAll(user2Path)
				newUUID = originalUUID
			})
			if err := test.before(); err != nil {
				t.Errorf("error in test: %v\n", err)
			}

			opts := []Option{
				func(c *Configuration) {
					c.keyring = &mockKeyring{}
				},
			}
			opts = append(opts, test.input...)

			got, gotErr := Configure(opts...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Configuration{}, profiles{}, profile{}, keyringItem{}, mockKeyring{}), cmpopts.IgnoreFields(Configuration{}, "u")); diff != "" {
				t.Errorf("Configure() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Configure() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestConfiguration_SetStorageKey(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			c Configuration
			k security.Key
		}
		want    []byte
		wantErr error
	}{
		{
			name: "set storage key",
			input: struct {
				c Configuration
				k security.Key
			}{
				c: Configuration{
					profile: profile{
						ID: "AAAA",
					},
					keyringItem: keyringItem{},
					keyring:     &mockKeyring{},
				},
				k: security.Key{
					Value: []byte(`test`),
				},
			},
			want: []byte(`test`),
		},
		{
			name: "set storage key (key is set)",
			input: struct {
				c Configuration
				k security.Key
			}{
				c: Configuration{
					profile: profile{
						ID: "AAAA",
					},
					keyringItem: keyringItem{
						Key: security.Key{
							Value: []byte(`test`),
						},
					},
					keyring: &mockKeyring{},
				},
				k: security.Key{
					Value: []byte(`test`),
				},
			},
			want: []byte(`test`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotErr := test.input.c.SetStorageKey(test.input.k)
			got := test.input.c.StorageKey().Value

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("SetStorageKey() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("SetStorageKey() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestConfiguration_SetKey(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			c Configuration
			k security.Key
		}
		want    []byte
		wantErr error
	}{
		{
			name: "set key",
			input: struct {
				c Configuration
				k security.Key
			}{
				c: Configuration{
					profile: profile{
						ID: "AAAA",
					},
					keyringItem: keyringItem{},
					keyring:     &mockKeyring{},
				},
				k: security.Key{
					Value: []byte(`test`),
				},
			},
			want: []byte(`test`),
		},
		{
			name: "set key (storage key is set)",
			input: struct {
				c Configuration
				k security.Key
			}{
				c: Configuration{
					profile: profile{
						ID: "AAAA",
					},
					keyringItem: keyringItem{
						StorageKey: security.Key{
							Value: []byte(`test`),
						},
					},
					keyring: &mockKeyring{},
				},
				k: security.Key{
					Value: []byte(`test`),
				},
			},
			want: []byte(`test`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotErr := test.input.c.SetKey(test.input.k)
			got := test.input.c.Key().Value

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("SetKey() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("SetKey() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestConfiguration_ExportImport(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			c          Configuration
			encryptKey []byte
			decryptKey []byte
		}
		want    export
		wantErr error
		after   func() error
	}{
		{
			name: "export/import successful",
			input: struct {
				c          Configuration
				encryptKey []byte
				decryptKey []byte
			}{
				c: Configuration{
					profile: profile{
						ID: "AAAA",
					},
					keyringItem: keyringItem{
						Key:        security.Key{Value: []byte(`test1`)},
						StorageKey: security.Key{Value: []byte(`test2`)},
					},
				},
				encryptKey: []byte(`test`),
				decryptKey: []byte(`test`),
			},
			want: export{
				Version: exportVersion,
				Profile: profile{
					ID: "AAAA",
				},
				KeyringItem: keyringItem{
					Key:        security.Key{Value: []byte(`test1`)},
					StorageKey: security.Key{Value: []byte(`test2`)},
				},
			},
		},
		{
			name: "import fails",
			input: struct {
				c          Configuration
				encryptKey []byte
				decryptKey []byte
			}{
				c: Configuration{
					profile: profile{
						ID: "AAAA",
					},
					keyringItem: keyringItem{
						Key:        security.Key{Value: []byte(`test1`)},
						StorageKey: security.Key{Value: []byte(`test2`)},
					},
				},
				encryptKey: []byte(`test`),
				decryptKey: []byte(`wrong`),
			},
			wantErr: security.ErrInvalidKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exportedPath := filepath.Join(user1Path, "export.sec")
			t.Cleanup(func() {
				_ = os.RemoveAll(exportedPath)
			})

			eKey, _ := security.NewSHA256FromPassword(test.input.encryptKey)
			dKey, _ := security.NewSHA256FromPassword(test.input.decryptKey)

			_ = test.input.c.Export(exportedPath, eKey)
			got, gotErr := Import(exportedPath, dKey)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(keyringItem{})); diff != "" {
				t.Errorf("Export()/Import() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Export()/Import() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestConfiguration_NewProfile(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			name     string
			password []byte
		}
		want struct {
			config  Configuration
			profile profile
		}
		wantErr error
		before  func() error
	}{
		{
			name: "new profile",
			input: struct {
				name     string
				password []byte
			}{
				name: "user3",
			},
			want: struct {
				config  Configuration
				profile profile
			}{
				config: Configuration{
					ProfileID: "CCCC",
					profile: profile{
						ID:   "CCCC",
						Name: "user3",
					},
					profiles: profiles{
						p: map[string]profile{
							"CCCC": {
								ID:   "CCCC",
								Name: "user3",
							},
						},
						path: filepath.Join(user3Path, "profiles.yaml"),
					},
					path: user3Path,
					keyringItem: keyringItem{
						isSet: true,
					},
					keyring: &mockKeyring{},
				},
				profile: profile{
					ID:   "CCCC",
					Name: "user3",
				},
			},
			before: func() error {
				newUUID = func() string {
					return "CCCC"
				}
				return nil
			},
		},
		{
			name: "new profile - with password",
			input: struct {
				name     string
				password []byte
			}{
				name:     "user3",
				password: []byte(`12345`),
			},
			want: struct {
				config  Configuration
				profile profile
			}{
				config: Configuration{
					ProfileID: "CCCC",
					profile: profile{
						ID:   "CCCC",
						Name: "user3",
					},
					profiles: profiles{
						p: map[string]profile{
							"CCCC": {
								ID:   "CCCC",
								Name: "user3",
							},
						},
						path: filepath.Join(user3Path, "profiles.yaml"),
					},
					path: user3Path,
					keyringItem: keyringItem{
						isSet: true,
					},
					keyring: &mockKeyring{},
				},
				profile: profile{
					ID:   "CCCC",
					Name: "user3",
				},
			},
			before: func() error {
				newUUID = func() string {
					return "CCCC"
				}
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Cleanup(func() {
				_ = os.RemoveAll(user3Path)
				newUUID = originalUUID
			})

			if err := test.before(); err != nil {
				t.Errorf("error in test: %v\n", err)
			}

			gotConfig := Configuration{
				keyring:  &mockKeyring{},
				path:     user3Path,
				profiles: profiles{path: filepath.Join(user3Path, "profiles.yaml")},
			}

			gotProfile, gotErr := gotConfig.NewProfile(test.input.name, test.input.password)

			if diff := cmp.Diff(test.want.config, gotConfig, cmp.AllowUnexported(Configuration{}, profiles{}, profile{}, keyringItem{}, mockKeyring{}), cmpopts.IgnoreFields(mockKeyring{}, "data"), cmpopts.IgnoreFields(keyringItem{}, "Key", "StorageKey")); diff != "" {
				t.Errorf("NewProfile() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.want.profile, gotProfile, cmp.AllowUnexported(profile{})); diff != "" {
				t.Errorf("NewProfile() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("NewProfile() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

type mockKeyring struct {
	data map[string]string
	err  error
}

func (m mockKeyring) Get(service, user string) (string, error) {
	if m.err != nil {
		return "", m.err
	}

	val, ok := m.data[user]
	if !ok {
		return "", ErrNotFound
	}
	return val, nil
}

func (m *mockKeyring) Set(service, user, password string) error {
	if m.err != nil {
		return m.err
	}

	if m.data == nil {
		m.data = make(map[string]string)
	}
	m.data[user] = password
	return nil
}

var originalUUID = newUUID
