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
			encryptKey Key
			decryptKey Key
		}
		want    []byte
		wantErr error
	}{
		{
			name: "Encrypt and decrypt data",
			input: struct {
				b          []byte
				encryptKey Key
				decryptKey Key
			}{
				b:          []byte(`data`),
				encryptKey: _testKey1,
				decryptKey: _testKey1,
			},
			want:    []byte(`data`),
			wantErr: nil,
		},
		{
			name: "Encrypt and decrypt data - error, faulty key",
			input: struct {
				b          []byte
				encryptKey Key
				decryptKey Key
			}{
				b:          []byte(`data`),
				encryptKey: _testKey1,
				decryptKey: _testKey2,
			},
			want:    nil,
			wantErr: ErrInvalidKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			enc, _ := Encrypt(test.input.b, test.input.encryptKey.Value)
			got, gotErr := Decrypt(enc, test.input.decryptKey.Value)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("Encrypt() = unexpected result (-want +got)\n%s\n", diff)
			}

			if diff := cmp.Diff(test.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("Encrypt = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

var (
	_testKey1, _ = NewKeyFromPassword([]byte("key"))
	_testKey2, _ = NewKeyFromPassword([]byte("wrongkey"))
)
