package secman

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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
				lastModified: _testTime1,
			},
			want: Collection{
				secrets: []Secret{
					{
						Name: "secret",
					},
				},
				lastModified: _testTime1,
			},
			wantErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got Collection
			gotErr := got.Decode(test.input.Encode())

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Collection{})); diff != "" {
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
		want       Collection
		wantResult bool
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
					Name: "secret",
				},
			},
			want: Collection{
				secrets: []Secret{
					{
						ID:   "1",
						Name: "secret",
					},
				},
				lastModified: _testLastModified,
				secretsByID: map[string]int{
					"1": 0,
				},
				secretsByName: map[string]int{
					"secret": 0,
				},
			},
			wantResult: true,
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
					secretsByID: map[string]int{
						"1": 0,
						"2": 1,
					},
					secretsByName: map[string]int{
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
				lastModified: _testLastModified,
				secretsByID: map[string]int{
					"1": 0,
					"2": 1,
					"3": 2,
				},
				secretsByName: map[string]int{
					"secret-1": 0,
					"secret-2": 1,
					"secret-3": 2,
				},
			},
			wantResult: true,
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
					secretsByID: map[string]int{
						"1": 0,
						"2": 1,
					},
					secretsByName: map[string]int{
						"secret-1": 0,
						"secret-2": 1,
					},
					lastModified: time.Date(2023, 8, 2, 12, 30, 0, 0, time.Local),
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
				lastModified: time.Date(2023, 8, 2, 12, 30, 0, 0, time.Local),
				secretsByID: map[string]int{
					"1": 0,
					"2": 1,
				},
				secretsByName: map[string]int{
					"secret-1": 0,
					"secret-2": 1,
				},
			},
			wantResult: false,
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
					secretsByID: map[string]int{
						"1": 0,
						"2": 1,
					},
					secretsByName: map[string]int{
						"secret-1": 0,
						"secret-2": 1,
					},
					lastModified: time.Date(2023, 8, 2, 12, 30, 0, 0, time.Local),
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
				lastModified: time.Date(2023, 8, 2, 12, 30, 0, 0, time.Local),
				secretsByID: map[string]int{
					"1": 0,
					"2": 1,
				},
				secretsByName: map[string]int{
					"secret-1": 0,
					"secret-2": 1,
				},
			},
			wantResult: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now = func() time.Time {
				return _testLastModified
			}
			gotResult := test.input.collection.Add(test.input.secret)
			got := test.input.collection

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Collection{}, Secret{})); diff != "" {
				t.Errorf("Add() = unexpected result (-want +got)\n%s\n", diff)
			}

			if test.wantResult != gotResult {
				t.Errorf("Add() = unexpected result, want: %t, got: %t\n", test.wantResult, gotResult)
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
		want       Collection
		wantResult bool
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
					secretsByID: map[string]int{
						"1": 0,
					},
					secretsByName: map[string]int{
						"secret-1": 0,
					},
				},
				id: "1",
			},
			want: Collection{
				secrets:       []Secret{},
				lastModified:  _testLastModified,
				secretsByID:   map[string]int{},
				secretsByName: map[string]int{},
			},
			wantResult: true,
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
					secretsByID: map[string]int{
						"1": 0,
						"2": 1,
						"3": 2,
						"4": 3,
						"5": 4,
					},
					secretsByName: map[string]int{
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
				lastModified: _testLastModified,
				secretsByID: map[string]int{
					"1": 0,
					"2": 1,
					"4": 2,
					"5": 3,
				},
				secretsByName: map[string]int{
					"secret-1": 0,
					"secret-2": 1,
					"secret-4": 2,
					"secret-5": 3,
				},
			},
			wantResult: true,
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
					secretsByID: map[string]int{
						"1": 0,
						"2": 1,
						"3": 2,
						"4": 3,
						"5": 4,
					},
					secretsByName: map[string]int{
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
				lastModified: _testLastModified,
				secretsByID: map[string]int{
					"2": 0,
					"3": 1,
					"4": 2,
					"5": 3,
				},
				secretsByName: map[string]int{
					"secret-2": 0,
					"secret-3": 1,
					"secret-4": 2,
					"secret-5": 3,
				},
			},
			wantResult: true,
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
					secretsByID: map[string]int{
						"1": 0,
						"2": 1,
						"3": 2,
						"4": 3,
						"5": 4,
					},
					secretsByName: map[string]int{
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
				lastModified: _testLastModified,
				secretsByID: map[string]int{
					"1": 0,
					"2": 1,
					"3": 2,
					"4": 3,
				},
				secretsByName: map[string]int{
					"secret-1": 0,
					"secret-2": 1,
					"secret-3": 2,
					"secret-4": 3,
				},
			},
			wantResult: true,
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
					secretsByID: map[string]int{
						"1": 0,
					},
					secretsByName: map[string]int{
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
				secretsByID: map[string]int{
					"1": 0,
				},
				secretsByName: map[string]int{
					"secret-1": 0,
				},
			},
			wantResult: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now = func() time.Time {
				return _testLastModified
			}

			gotResult := test.input.collection.RemoveByID(test.input.id)
			got := test.input.collection

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Collection{})); diff != "" {
				t.Errorf("RemoveByID() = unexpected result (-want +got)\n%s\n", diff)
			}

			if test.wantResult != gotResult {
				t.Errorf("RemoveByID() = unexpected result, want: %t, got: %t\n", test.wantResult, gotResult)
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
		want       Collection
		wantResult bool
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
					secretsByID: map[string]int{
						"1": 0,
					},
					secretsByName: map[string]int{
						"secret-1": 0,
					},
				},
				name: "secret-1",
			},
			want: Collection{
				secrets:       []Secret{},
				lastModified:  _testLastModified,
				secretsByID:   map[string]int{},
				secretsByName: map[string]int{},
			},
			wantResult: true,
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
					secretsByID: map[string]int{
						"1": 0,
						"2": 1,
						"3": 2,
						"4": 3,
						"5": 4,
					},
					secretsByName: map[string]int{
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
				lastModified: _testLastModified,
				secretsByID: map[string]int{
					"1": 0,
					"2": 1,
					"4": 2,
					"5": 3,
				},
				secretsByName: map[string]int{
					"secret-1": 0,
					"secret-2": 1,
					"secret-4": 2,
					"secret-5": 3,
				},
			},
			wantResult: true,
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
					secretsByID: map[string]int{
						"1": 0,
						"2": 1,
						"3": 2,
						"4": 3,
						"5": 4,
					},
					secretsByName: map[string]int{
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
				lastModified: _testLastModified,
				secretsByID: map[string]int{
					"2": 0,
					"3": 1,
					"4": 2,
					"5": 3,
				},
				secretsByName: map[string]int{
					"secret-2": 0,
					"secret-3": 1,
					"secret-4": 2,
					"secret-5": 3,
				},
			},
			wantResult: true,
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
					secretsByID: map[string]int{
						"1": 0,
						"2": 1,
						"3": 2,
						"4": 3,
						"5": 4,
					},
					secretsByName: map[string]int{
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
				lastModified: _testLastModified,
				secretsByID: map[string]int{
					"1": 0,
					"2": 1,
					"3": 2,
					"4": 3,
				},
				secretsByName: map[string]int{
					"secret-1": 0,
					"secret-2": 1,
					"secret-3": 2,
					"secret-4": 3,
				},
			},
			wantResult: true,
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
					secretsByID: map[string]int{
						"1": 0,
					},
					secretsByName: map[string]int{
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
				secretsByID: map[string]int{
					"1": 0,
				},
				secretsByName: map[string]int{
					"secret-1": 0,
				},
			},
			wantResult: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now = func() time.Time {
				return _testLastModified
			}

			gotResult := test.input.collection.RemoveByName(test.input.name)
			got := test.input.collection

			if diff := cmp.Diff(test.want, got, cmp.AllowUnexported(Collection{})); diff != "" {
				t.Errorf("RemoveByName() = unexpected result (-want +got)\n%s\n", diff)
			}

			if test.wantResult != gotResult {
				t.Errorf("RemoveByName() = unexpected result, want: %t, got: %t\n", test.wantResult, gotResult)
			}
		})
	}
}
