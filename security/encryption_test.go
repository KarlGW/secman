package security

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestEncryptDecrypt(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			b          []byte
			encryptKey *[32]byte
			decryptKey *[32]byte
		}
		want    []byte
		wantErr error
	}{
		{
			name: "Encrypt and decrypt data",
			input: struct {
				b          []byte
				encryptKey *[32]byte
				decryptKey *[32]byte
			}{
				b:          []byte(`data`),
				encryptKey: NewKeyFrom([]byte(`key`)),
				decryptKey: NewKeyFrom([]byte(`key`)),
			},
			want:    []byte(`data`),
			wantErr: nil,
		},
		{
			name: "Encrypt and decrypt data - error, faulty key",
			input: struct {
				b          []byte
				encryptKey *[32]byte
				decryptKey *[32]byte
			}{
				b:          []byte(`data`),
				encryptKey: NewKeyFrom([]byte(`key`)),
				decryptKey: NewKeyFrom([]byte(`wrongkey`)),
			},
			want:    nil,
			wantErr: ErrInvalidKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			enc, gotErr := Encrypt(test.input.b, test.input.encryptKey)
			got, gotErr := Decrypt(enc, test.input.decryptKey)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("Encrypt() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Encrypt = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

func TestNewKeyFrom(t *testing.T) {
	want := [32]byte{238, 38, 176, 221, 74, 247, 231, 73, 170, 26, 142, 227, 193, 10, 233, 146, 63, 97, 137, 128, 119, 46, 71, 63, 136, 25, 165, 212, 148, 14, 13, 178}
	got := NewKeyFrom([]byte(`test`))

	if diff := cmp.Diff(&want, got); diff != "" {
		t.Errorf("NewKeyFrom() = unexpected result (-want +got)\n%s\n", diff)
	}
}
