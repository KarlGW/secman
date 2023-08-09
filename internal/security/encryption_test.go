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
			encryptKey [32]byte
			decryptKey [32]byte
		}
		want    []byte
		wantErr error
	}{
		{
			name: "Encrypt and decrypt data",
			input: struct {
				b          []byte
				encryptKey [32]byte
				decryptKey [32]byte
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
				encryptKey [32]byte
				decryptKey [32]byte
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
	want := [32]byte{159, 134, 208, 129, 136, 76, 125, 101, 154, 47, 234, 160, 197, 90, 208, 21, 163, 191, 79, 27, 43, 11, 130, 44, 209, 93, 108, 21, 176, 240, 10, 8}
	got := NewKeyFrom([]byte(`test`))

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("NewKeyFrom() = unexpected result (-want +got)\n%s\n", diff)
	}
}
