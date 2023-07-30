package secman

import (
	"testing"

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
				Secrets: []Secret{
					{
						Name: "secret",
					},
				},
				LastModified: _testTime1,
			},
			want: Collection{
				Secrets: []Secret{
					{
						Name: "secret",
					},
				},
				LastModified: _testTime1,
			},
			wantErr: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got Collection
			gotErr := got.Decode(test.input.Encode())

			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("Encode()/Decode() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr); diff != "" {
				t.Errorf("Encode()/Decode() = unexpected error (-want +got)\n%s\n", diff)
			}

		})
	}
}
