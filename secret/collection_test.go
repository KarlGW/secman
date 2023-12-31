package secret

import (
	"testing"
	"time"

	"github.com/KarlGW/secman/internal/gob"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestCollection_Encode_Decode(t *testing.T) {
	var tests = []struct {
		name    string
		input   Collection
		want    Collection
		wantErr error
	}{
		{
			name: "Encode and Decode a collection",
			input: Collection{
				secrets: []Secret{
					{
						Name: "secret",
					},
				},
				updated: _testTime1,
			},
			want: Collection{
				secrets: []Secret{
					{
						Name: "secret",
					},
				},
				updated: _testTime1,
			},
			wantErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, gotErr := gob.Encode(test.input)
			if gotErr != nil {
				t.Errorf("unexpected error in test, could not encode to gob")
			}
			got := Collection{}
			gotErr = gob.Decode(encoded, &got)

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Collection{}), cmpopts.IgnoreUnexported(Secret{})); diff != "" {
				t.Errorf("Encode()/Decode() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr); diff != "" {
				t.Errorf("Encode()/Decode() = unexpected error (-want +got)\n%s\n", diff)
			}

		})
	}
}

func TestCollection_Add(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			collection Collection
			secret     Secret
		}
		want    Collection
		wantErr error
	}{
		{
			name: "Add secret to empty collection",
			input: struct {
				collection Collection
				secret     Secret
			}{
				collection: Collection{},
				secret: Secret{
					ID:   "1",
					Name: "secret-1",
				},
			},
			want: Collection{
				secrets: []Secret{
					{
						ID:   "1",
						Name: "secret-1",
					},
				},
				updated: _testUpdated,
				ids: map[string]int{
					"1": 0,
				},
				names: map[string]int{
					"secret-1": 0,
				},
			},
			wantErr: nil,
		},
		{
			name: "Add secret to collection with existing secrets",
			input: struct {
				collection Collection
				secret     Secret
			}{
				collection: Collection{
					secrets: []Secret{
						{
							ID:   "1",
							Name: "secret-1",
						},
						{
							ID:   "2",
							Name: "secret-2",
						},
					},
					ids: map[string]int{
						"1": 0,
						"2": 1,
					},
					names: map[string]int{
						"secret-1": 0,
						"secret-2": 1,
					},
				},
				secret: Secret{
					ID:   "3",
					Name: "secret-3",
				},
			},
			want: Collection{
				secrets: []Secret{
					{
						ID:   "1",
						Name: "secret-1",
					},
					{
						ID:   "2",
						Name: "secret-2",
					},
					{
						ID:   "3",
						Name: "secret-3",
					},
				},
				updated: _testUpdated,
				ids: map[string]int{
					"1": 0,
					"2": 1,
					"3": 2,
				},
				names: map[string]int{
					"secret-1": 0,
					"secret-2": 1,
					"secret-3": 2,
				},
			},
			wantErr: nil,
		},
		{
			name: "Add secret to collection (secret with ID already exist)",
			input: struct {
				collection Collection
				secret     Secret
			}{
				collection: Collection{
					secrets: []Secret{
						{
							ID:   "1",
							Name: "secret-1",
						},
						{
							ID:   "2",
							Name: "secret-2",
						},
					},
					ids: map[string]int{
						"1": 0,
						"2": 1,
					},
					names: map[string]int{
						"secret-1": 0,
						"secret-2": 1,
					},
					updated: time.Date(2023, 8, 2, 12, 30, 0, 0, time.Local),
				},
				secret: Secret{
					ID:   "1",
					Name: "secret-new",
				},
			},
			want: Collection{
				secrets: []Secret{
					{
						ID:   "1",
						Name: "secret-1",
					},
					{
						ID:   "2",
						Name: "secret-2",
					},
				},
				updated: time.Date(2023, 8, 2, 12, 30, 0, 0, time.Local),
				ids: map[string]int{
					"1": 0,
					"2": 1,
				},
				names: map[string]int{
					"secret-1": 0,
					"secret-2": 1,
				},
			},
			wantErr: ErrSecretAlreadyExists,
		},
		{
			name: "Add secret to collection (secret with name already exist)",
			input: struct {
				collection Collection
				secret     Secret
			}{
				collection: Collection{
					secrets: []Secret{
						{
							ID:   "1",
							Name: "secret-1",
						},
						{
							ID:   "2",
							Name: "secret-2",
						},
					},
					ids: map[string]int{
						"1": 0,
						"2": 1,
					},
					names: map[string]int{
						"secret-1": 0,
						"secret-2": 1,
					},
					updated: time.Date(2023, 8, 2, 12, 30, 0, 0, time.Local),
				},
				secret: Secret{
					ID:   "3",
					Name: "secret-1",
				},
			},
			want: Collection{
				secrets: []Secret{
					{
						ID:   "1",
						Name: "secret-1",
					},
					{
						ID:   "2",
						Name: "secret-2",
					},
				},
				updated: time.Date(2023, 8, 2, 12, 30, 0, 0, time.Local),
				ids: map[string]int{
					"1": 0,
					"2": 1,
				},
				names: map[string]int{
					"secret-1": 0,
					"secret-2": 1,
				},
			},
			wantErr: ErrSecretAlreadyExists,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now = func() time.Time {
				return _testUpdated
			}

			gotErr := test.input.collection.Add(test.input.secret)
			got := test.input.collection

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Collection{}, Secret{})); diff != "" {
				t.Errorf("Add() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Add() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestCollection_Update(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			collection Collection
			secret     Secret
		}
		want    Collection
		wantErr error
	}{
		{
			name: "Update a secret",
			input: struct {
				collection Collection
				secret     Secret
			}{
				collection: Collection{
					secrets: []Secret{
						{
							ID:      "1",
							Name:    "secret-1",
							Created: _testCreated,
						},
					},
					ids: map[string]int{
						"1": 0,
					},
					names: map[string]int{
						"secret-1": 0,
					},
				},
				secret: Secret{
					ID:          "1",
					Name:        "secret-1",
					Type:        TypeNote,
					DisplayName: "Secret 1",
					Value:       []byte(`test`),
					Labels:      []string{"label"},
					Tags: map[string]string{
						"key": "val",
					},
					Created: _testCreated,
				},
			},
			want: Collection{
				secrets: []Secret{
					{
						ID:          "1",
						Name:        "secret-1",
						Type:        TypeNote,
						DisplayName: "Secret 1",
						Value:       []byte(`test`),
						Labels:      []string{"label"},
						Tags: map[string]string{
							"key": "val",
						},
						Created: _testCreated,
						Updated: _testUpdated,
					},
				},
				ids: map[string]int{
					"1": 0,
				},
				names: map[string]int{
					"secret-1": 0,
				},
				updated: _testUpdated,
			},
			wantErr: nil,
		},
		{
			name: "Update a secret - does not exist",
			input: struct {
				collection Collection
				secret     Secret
			}{
				collection: Collection{
					secrets: []Secret{
						{
							ID:      "1",
							Name:    "secret-1",
							Created: _testCreated,
						},
					},
					ids: map[string]int{
						"1": 0,
					},
					names: map[string]int{
						"secret-1": 0,
					},
					updated: _testCreated,
				},
				secret: Secret{
					ID:          "2",
					Name:        "secret-2",
					Type:        TypeNote,
					DisplayName: "Secret 2",
					Value:       []byte(`test`),
					Labels:      []string{"label"},
					Tags: map[string]string{
						"key": "val",
					},
					Created: _testCreated,
				},
			},
			want: Collection{
				secrets: []Secret{
					{
						ID:      "1",
						Name:    "secret-1",
						Created: _testCreated,
					},
				},
				ids: map[string]int{
					"1": 0,
				},
				names: map[string]int{
					"secret-1": 0,
				},
				updated: _testCreated,
			},
			wantErr: ErrSecretNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now = func() time.Time {
				return _testUpdated
			}

			gotErr := test.input.collection.Update(test.input.secret)
			got := test.input.collection

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Collection{}), cmpopts.IgnoreUnexported(Secret{})); diff != "" {
				t.Errorf("Update() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Update() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestCollection_RemoveByID(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			collection Collection
			id         string
		}
		want    Collection
		wantErr error
	}{
		{
			name: "Remove a secret, one secret in collection",
			input: struct {
				collection Collection
				id         string
			}{
				collection: Collection{
					secrets: []Secret{
						{
							ID:   "1",
							Name: "secret-1",
						},
					},
					ids: map[string]int{
						"1": 0,
					},
					names: map[string]int{
						"secret-1": 0,
					},
				},
				id: "1",
			},
			want: Collection{
				secrets: []Secret{},
				updated: _testUpdated,
				ids:     map[string]int{},
				names:   map[string]int{},
			},
			wantErr: nil,
		},
		{
			name: "Remove a secret from a collection of multiple secrets (remove from middle)",
			input: struct {
				collection Collection
				id         string
			}{
				collection: Collection{
					secrets: []Secret{
						{
							ID:   "1",
							Name: "secret-1",
						},
						{
							ID:   "2",
							Name: "secret-2",
						},
						{
							ID:   "3",
							Name: "secret-3",
						},
						{
							ID:   "4",
							Name: "secret-4",
						},
						{
							ID:   "5",
							Name: "secret-5",
						},
					},
					ids: map[string]int{
						"1": 0,
						"2": 1,
						"3": 2,
						"4": 3,
						"5": 4,
					},
					names: map[string]int{
						"secret-1": 0,
						"secret-2": 1,
						"secret-3": 2,
						"secret-4": 3,
						"secret-5": 4,
					},
				},
				id: "3",
			},
			want: Collection{
				secrets: []Secret{
					{
						ID:   "1",
						Name: "secret-1",
					},
					{
						ID:   "2",
						Name: "secret-2",
					},
					{
						ID:   "4",
						Name: "secret-4",
					},
					{
						ID:   "5",
						Name: "secret-5",
					},
				},
				updated: _testUpdated,
				ids: map[string]int{
					"1": 0,
					"2": 1,
					"4": 2,
					"5": 3,
				},
				names: map[string]int{
					"secret-1": 0,
					"secret-2": 1,
					"secret-4": 2,
					"secret-5": 3,
				},
			},
			wantErr: nil,
		},
		{
			name: "Remove a secret from a collection of multiple secrets (remove from beginning)",
			input: struct {
				collection Collection
				id         string
			}{
				collection: Collection{
					secrets: []Secret{
						{
							ID:   "1",
							Name: "secret-1",
						},
						{
							ID:   "2",
							Name: "secret-2",
						},
						{
							ID:   "3",
							Name: "secret-3",
						},
						{
							ID:   "4",
							Name: "secret-4",
						},
						{
							ID:   "5",
							Name: "secret-5",
						},
					},
					ids: map[string]int{
						"1": 0,
						"2": 1,
						"3": 2,
						"4": 3,
						"5": 4,
					},
					names: map[string]int{
						"secret-1": 0,
						"secret-2": 1,
						"secret-3": 2,
						"secret-4": 3,
						"secret-5": 4,
					},
				},
				id: "1",
			},
			want: Collection{
				secrets: []Secret{
					{
						ID:   "2",
						Name: "secret-2",
					},
					{
						ID:   "3",
						Name: "secret-3",
					},
					{
						ID:   "4",
						Name: "secret-4",
					},
					{
						ID:   "5",
						Name: "secret-5",
					},
				},
				updated: _testUpdated,
				ids: map[string]int{
					"2": 0,
					"3": 1,
					"4": 2,
					"5": 3,
				},
				names: map[string]int{
					"secret-2": 0,
					"secret-3": 1,
					"secret-4": 2,
					"secret-5": 3,
				},
			},
			wantErr: nil,
		},
		{
			name: "Remove a secret from a collection of multiple secrets (remove from end)",
			input: struct {
				collection Collection
				id         string
			}{
				collection: Collection{
					secrets: []Secret{
						{
							ID:   "1",
							Name: "secret-1",
						},
						{
							ID:   "2",
							Name: "secret-2",
						},
						{
							ID:   "3",
							Name: "secret-3",
						},
						{
							ID:   "4",
							Name: "secret-4",
						},
						{
							ID:   "5",
							Name: "secret-5",
						},
					},
					ids: map[string]int{
						"1": 0,
						"2": 1,
						"3": 2,
						"4": 3,
						"5": 4,
					},
					names: map[string]int{
						"secret-1": 0,
						"secret-2": 1,
						"secret-3": 2,
						"secret-4": 3,
						"secret-5": 4,
					},
				},
				id: "5",
			},
			want: Collection{
				secrets: []Secret{
					{
						ID:   "1",
						Name: "secret-1",
					},
					{
						ID:   "2",
						Name: "secret-2",
					},
					{
						ID:   "3",
						Name: "secret-3",
					},
					{
						ID:   "4",
						Name: "secret-4",
					},
				},
				updated: _testUpdated,
				ids: map[string]int{
					"1": 0,
					"2": 1,
					"3": 2,
					"4": 3,
				},
				names: map[string]int{
					"secret-1": 0,
					"secret-2": 1,
					"secret-3": 2,
					"secret-4": 3,
				},
			},
			wantErr: nil,
		},
		{
			name: "secret with id does not exist",
			input: struct {
				collection Collection
				id         string
			}{
				collection: Collection{
					secrets: []Secret{
						{
							ID:   "1",
							Name: "secret-1",
						},
					},
					ids: map[string]int{
						"1": 0,
					},
					names: map[string]int{
						"secret-1": 0,
					},
				},
				id: "2",
			},
			want: Collection{
				secrets: []Secret{
					{
						ID:   "1",
						Name: "secret-1",
					},
				},
				ids: map[string]int{
					"1": 0,
				},
				names: map[string]int{
					"secret-1": 0,
				},
			},
			wantErr: ErrSecretNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now = func() time.Time {
				return _testUpdated
			}

			gotErr := test.input.collection.RemoveByID(test.input.id)
			got := test.input.collection

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Collection{}), cmpopts.IgnoreUnexported(Secret{})); diff != "" {
				t.Errorf("RemoveByID() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("RemoveByID() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestCollection_RemoveByName(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			collection Collection
			name       string
		}
		want    Collection
		wantErr error
	}{
		{
			name: "Remove a secret, one secret in collection",
			input: struct {
				collection Collection
				name       string
			}{
				collection: Collection{
					secrets: []Secret{
						{
							ID:   "1",
							Name: "secret-1",
						},
					},
					ids: map[string]int{
						"1": 0,
					},
					names: map[string]int{
						"secret-1": 0,
					},
				},
				name: "secret-1",
			},
			want: Collection{
				secrets: []Secret{},
				updated: _testUpdated,
				ids:     map[string]int{},
				names:   map[string]int{},
			},
			wantErr: nil,
		},
		{
			name: "Remove a secret from a collection of multiple secrets (remove from middle)",
			input: struct {
				collection Collection
				name       string
			}{
				collection: Collection{
					secrets: []Secret{
						{
							ID:   "1",
							Name: "secret-1",
						},
						{
							ID:   "2",
							Name: "secret-2",
						},
						{
							ID:   "3",
							Name: "secret-3",
						},
						{
							ID:   "4",
							Name: "secret-4",
						},
						{
							ID:   "5",
							Name: "secret-5",
						},
					},
					ids: map[string]int{
						"1": 0,
						"2": 1,
						"3": 2,
						"4": 3,
						"5": 4,
					},
					names: map[string]int{
						"secret-1": 0,
						"secret-2": 1,
						"secret-3": 2,
						"secret-4": 3,
						"secret-5": 4,
					},
				},
				name: "secret-3",
			},
			want: Collection{
				secrets: []Secret{
					{
						ID:   "1",
						Name: "secret-1",
					},
					{
						ID:   "2",
						Name: "secret-2",
					},
					{
						ID:   "4",
						Name: "secret-4",
					},
					{
						ID:   "5",
						Name: "secret-5",
					},
				},
				updated: _testUpdated,
				ids: map[string]int{
					"1": 0,
					"2": 1,
					"4": 2,
					"5": 3,
				},
				names: map[string]int{
					"secret-1": 0,
					"secret-2": 1,
					"secret-4": 2,
					"secret-5": 3,
				},
			},
			wantErr: nil,
		},
		{
			name: "Remove a secret from a collection of multiple secrets (remove from beginning)",
			input: struct {
				collection Collection
				name       string
			}{
				collection: Collection{
					secrets: []Secret{
						{
							ID:   "1",
							Name: "secret-1",
						},
						{
							ID:   "2",
							Name: "secret-2",
						},
						{
							ID:   "3",
							Name: "secret-3",
						},
						{
							ID:   "4",
							Name: "secret-4",
						},
						{
							ID:   "5",
							Name: "secret-5",
						},
					},
					ids: map[string]int{
						"1": 0,
						"2": 1,
						"3": 2,
						"4": 3,
						"5": 4,
					},
					names: map[string]int{
						"secret-1": 0,
						"secret-2": 1,
						"secret-3": 2,
						"secret-4": 3,
						"secret-5": 4,
					},
				},
				name: "secret-1",
			},
			want: Collection{
				secrets: []Secret{
					{
						ID:   "2",
						Name: "secret-2",
					},
					{
						ID:   "3",
						Name: "secret-3",
					},
					{
						ID:   "4",
						Name: "secret-4",
					},
					{
						ID:   "5",
						Name: "secret-5",
					},
				},
				updated: _testUpdated,
				ids: map[string]int{
					"2": 0,
					"3": 1,
					"4": 2,
					"5": 3,
				},
				names: map[string]int{
					"secret-2": 0,
					"secret-3": 1,
					"secret-4": 2,
					"secret-5": 3,
				},
			},
			wantErr: nil,
		},
		{
			name: "Remove a secret from a collection of multiple secrets (remove from end)",
			input: struct {
				collection Collection
				name       string
			}{
				collection: Collection{
					secrets: []Secret{
						{
							ID:   "1",
							Name: "secret-1",
						},
						{
							ID:   "2",
							Name: "secret-2",
						},
						{
							ID:   "3",
							Name: "secret-3",
						},
						{
							ID:   "4",
							Name: "secret-4",
						},
						{
							ID:   "5",
							Name: "secret-5",
						},
					},
					ids: map[string]int{
						"1": 0,
						"2": 1,
						"3": 2,
						"4": 3,
						"5": 4,
					},
					names: map[string]int{
						"secret-1": 0,
						"secret-2": 1,
						"secret-3": 2,
						"secret-4": 3,
						"secret-5": 4,
					},
				},
				name: "secret-5",
			},
			want: Collection{
				secrets: []Secret{
					{
						ID:   "1",
						Name: "secret-1",
					},
					{
						ID:   "2",
						Name: "secret-2",
					},
					{
						ID:   "3",
						Name: "secret-3",
					},
					{
						ID:   "4",
						Name: "secret-4",
					},
				},
				updated: _testUpdated,
				ids: map[string]int{
					"1": 0,
					"2": 1,
					"3": 2,
					"4": 3,
				},
				names: map[string]int{
					"secret-1": 0,
					"secret-2": 1,
					"secret-3": 2,
					"secret-4": 3,
				},
			},
			wantErr: nil,
		},
		{
			name: "secret with name does not exist",
			input: struct {
				collection Collection
				name       string
			}{
				collection: Collection{
					secrets: []Secret{
						{
							ID:   "1",
							Name: "secret-1",
						},
					},
					ids: map[string]int{
						"1": 0,
					},
					names: map[string]int{
						"secret-1": 0,
					},
				},
				name: "secret-2",
			},
			want: Collection{
				secrets: []Secret{
					{
						ID:   "1",
						Name: "secret-1",
					},
				},
				ids: map[string]int{
					"1": 0,
				},
				names: map[string]int{
					"secret-1": 0,
				},
			},
			wantErr: ErrSecretNotFound,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now = func() time.Time {
				return _testUpdated
			}

			gotErr := test.input.collection.RemoveByName(test.input.name)
			got := test.input.collection

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Collection{}), cmpopts.IgnoreUnexported(Secret{})); diff != "" {
				t.Errorf("RemoveByName() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("RemoveByName() = unexpected error (-want +got)\n%s\n", diff)
			}

		})
	}
}
