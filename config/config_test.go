package config

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	user1Path = filepath.Join("../testdata", "user1", dir)
	user2Path = filepath.Join("../testdata", "user2", dir)
)

func TestConfigure(t *testing.T) {
	var tests = []struct {
		name    string
		input   []Option
		want    Configuration
		wantErr error
		before  func() error
		after   func() error
	}{
		{
			name: "default bare config",
			input: []Option{
				func(c *Configuration) {
					c.path = user1Path
				},
			},
			want: Configuration{
				Username: "user1",
				profiles: profiles{
					p:    map[string]profile{},
					path: filepath.Join(user1Path, profilesFile),
				},
				path:    user1Path,
				keyring: mockKeyring{},
			},
			wantErr: nil,
			before: func() error {
				newUUID = func() string {
					return "AAAA"
				}
				currentUser = func() (*user.User, error) {
					return &user.User{
						Username: "user1",
						HomeDir:  "testdata/user1",
					}, nil
				}
				return nil
			},
			after: func() error {
				return os.RemoveAll(user1Path)
			},
		},
		{
			name: "with configuration",
			input: []Option{
				func(c *Configuration) {
					c.path = user2Path
				},
			}, want: Configuration{
				Username:  "user2",
				ProfileID: "A1A1",
				profile: profile{
					ID:   "A1A1",
					Name: "user2",
				},
				profiles: profiles{
					p: map[string]profile{
						"A1A1": {
							ID:   "A1A1",
							Name: "user2",
						},
					},
					path: filepath.Join(user2Path, profilesFile),
				},
				path:    user2Path,
				keyring: mockKeyring{},
			},
			before: func() error {
				currentUser = func() (*user.User, error) {
					return &user.User{
						Username: "user2",
						HomeDir:  "testdata/user2",
					}, nil
				}
				return nil
			},
			after: func() error {
				return nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.before(); err != nil {
				t.Errorf("error in test: %v\n", err)
			}
			opts := []Option{
				func(c *Configuration) {
					c.keyring = mockKeyring{}
				},
			}
			opts = append(opts, test.input...)

			got, gotErr := Configure(opts...)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Configuration{}, profiles{}, profile{}, keyringItem{}), cmpopts.IgnoreFields(Configuration{}, "u")); diff != "" {
				t.Errorf("Configure() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Configure() = unexpected error (-want +got)\n%s\n", diff)
			}

			if err := test.after(); err != nil {
				t.Errorf("error in test: %v\n", err)
			}
		})
	}
}

type mockKeyring struct{}

func (m mockKeyring) Get(service, user string) (string, error) {
	return "{}", nil
}

func (m mockKeyring) Set(service, user, password string) error {
	return nil
}
