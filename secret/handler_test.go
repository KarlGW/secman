package secret

import (
	"testing"
	"time"

	"github.com/KarlGW/secman/internal/gob"
	"github.com/KarlGW/secman/internal/security"
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
		want    *Collection
		wantErr error
	}{
		{
			name: "Sync - Local is newer",
			input: Handler{
				storage: &mockStorage{
					collection: Collection{
						secrets: []Secret{
							{
								Name: "secret",
							},
						},
						updated: _testTime2,
					},
					updated: _testTime2,
				},
				secondaryStorage: &mockStorage{
					collection: Collection{
						secrets: []Secret{
							{
								Name: "secret-old",
							},
						},
						updated: _testTime1,
					},
					updated: _testTime1,
				},
				storageKey: _testKey,
			},
			want: &Collection{
				secrets: []Secret{
					{
						Name: "secret",
					},
				},
				updated: _testTime2,
			},
		},
		{
			name: "Sync - remote is newer",
			input: Handler{
				storage: &mockStorage{
					collection: Collection{
						secrets: []Secret{
							{
								Name: "secret",
							},
						},
						updated: _testTime1,
					},
					updated: _testTime1,
				},
				secondaryStorage: &mockStorage{
					collection: Collection{
						secrets: []Secret{
							{
								Name: "secret-new",
							},
						},
						updated: _testTime2,
					},
					updated: _testTime2,
				},
				storageKey: _testKey,
			},
			want: &Collection{
				secrets: []Secret{
					{
						Name: "secret-new",
					},
				},
				updated: _testTime2,
			},
		},
		{
			name: "Sync - No remote set",
			input: Handler{
				storage: &mockStorage{
					collection: Collection{
						secrets: []Secret{
							{
								Name: "secret",
							},
						},
						updated: _testTime2,
					},
				},
				storageKey: _testKey,
			},
			want:    nil,
			wantErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now = func() time.Time {
				return _testCreated
			}

			gotErr := test.input.Sync()
			got := test.input.Collection()

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Collection{}, mockStorage{}), cmpopts.IgnoreUnexported(Secret{})); diff != "" {
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
	updated    time.Time
}

func (stg *mockStorage) Save(data []byte) error {
	if stg.err != nil {
		return stg.err
	}

	decrypted, _ := security.Decrypt(data, _testKey.Value)

	var c Collection
	if err := gob.Decode(decrypted, &c); err != nil {
		return err
	}

	stg.collection = c
	return nil
}

func (stg mockStorage) Load() ([]byte, error) {
	if stg.err != nil {
		return nil, stg.err
	}

	b, err := gob.Encode(stg.collection)
	if err != nil {
		return nil, err
	}

	encrypted, _ := security.Encrypt(b, _testKey.Value)

	return encrypted, nil
}

func (stg mockStorage) Updated() (time.Time, error) {

	return stg.updated, nil
}
