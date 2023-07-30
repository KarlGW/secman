package secman

import (
	"testing"
	"time"

	"github.com/KarlGW/secman/security"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestNewSecret(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			name, value string
			key         *[32]byte
			options     []SecretOption
		}
		want      Secret
		wantValue string
	}{
		{
			name: "New Secret",
			input: struct {
				name    string
				value   string
				key     *[32]byte
				options []SecretOption
			}{
				name:  "secret",
				value: _testValue,
				key:   _testKey,
			},
			want: Secret{
				ID:      "aaaa",
				Name:    "secret",
				Created: _testCreated,
			},
			wantValue: _testValue,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now = func() time.Time {
				return _testCreated
			}

			newUUID = func() string {
				return "aaaa"
			}

			got := NewSecret(test.input.name, test.input.value, test.input.key, test.input.options...)

			if diff := cmp.Diff(test.want, got, cmpopts.IgnoreFields(Secret{}, "Value")); diff != "" {
				t.Errorf("NewSecret() = unexpected result (-want +got)\n%s\n", diff)
			}

			gotValue, _ := security.Decrypt(got.Value, _testKey)
			if test.wantValue != string(gotValue) {
				t.Errorf("NewSecret() = unexpected value, want: %s, got: %s\n", test.wantValue, string(gotValue))
			}

		})
	}
}

var (
	_testValue        = "value"
	_testKey          = security.NewKeyFrom([]byte("test"))
	_testEncrypted, _ = security.Encrypt([]byte(_testValue), _testKey)
	_testCreated      = time.Date(2023, 7, 30, 13, 30, 0, 0, time.Local)
)
