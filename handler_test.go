package secman

import (
	"testing"
	"time"

	"github.com/KarlGW/secman/security"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	_testTime1 = time.Date(2023, time.July, 27, 13, 30, 0, 0, time.Local)
	_testTime2 = time.Date(2023, time.July, 27, 14, 30, 0, 0, time.Local)
)

func TestHandler_Sync(t *testing.T) {
	var tests = []struct {
		name    string
		input   Handler
		want    Collection
		wantErr error
	}{
		{
			name: "Sync - Local is newer",
			input: Handler{
				storage: storage{
					local: &mockStorage{
						collection: Collection{
							Secrets: []Secret{
								{
									Name: "secret",
								},
							},
							LastModified: _testTime2,
						},
					},
					remote: &mockStorage{
						collection: Collection{
							Secrets: []Secret{
								{
									Name: "secret-old",
								},
							},
							LastModified: _testTime1,
						},
					},
				},
				key: _testKey,
			},
			want: Collection{
				Secrets: []Secret{
					{
						Name: "secret",
					},
				},
				LastModified: _testTime2,
			},
		},
		{
			name: "Sync - remote is newer",
			input: Handler{
				storage: storage{
					local: &mockStorage{
						collection: Collection{
							Secrets: []Secret{
								{
									Name: "secret",
								},
							},
							LastModified: _testTime1,
						},
					},
					remote: &mockStorage{
						collection: Collection{
							Secrets: []Secret{
								{
									Name: "secret-new",
								},
							},
							LastModified: _testTime2,
						},
					},
				},
				key: _testKey,
			},
			want: Collection{
				Secrets: []Secret{
					{
						Name: "secret-new",
					},
				},
				LastModified: _testTime2,
			},
		},
		{
			name: "Sync - No remote set",
			input: Handler{
				storage: storage{
					local: &mockStorage{
						collection: Collection{
							Secrets: []Secret{
								{
									Name: "secret",
								},
							},
							LastModified: _testTime2,
						},
					},
				},
				key: _testKey,
			},
			want:    Collection{},
			wantErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotErr := test.input.Sync()
			got := test.input.Collection()

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Collection{}, storage{}, mockStorage{})); diff != "" {
				t.Errorf("Sync() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Sync() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

type mockStorage struct {
	collection Collection
	err        error
}

func (stg *mockStorage) Save(data []byte) error {
	if stg.err != nil {
		return stg.err
	}

	decrypted, _ := security.Decrypt(data, _testKey)

	var c Collection
	if err := c.Decode(decrypted); err != nil {
		return err
	}

	stg.collection = c
	return nil
}

func (stg mockStorage) Load() ([]byte, error) {
	if stg.err != nil {
		return nil, stg.err
	}

	b := stg.collection.Encode()

	encrypted, _ := security.Encrypt(b, _testKey)

	return encrypted, nil
}
