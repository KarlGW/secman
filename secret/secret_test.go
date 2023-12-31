package secret

import (
	"testing"
	"time"

	"github.com/KarlGW/secman/internal/security"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestNewSecret(t *testing.T) {
	var tests = []struct {
		name  string
		input struct {
			name, value string
			key         []byte
			options     []SecretOption
		}
		want      Secret
		wantValue string
		wantErr   error
	}{
		{
			name: "New Secret",
			input: struct {
				name    string
				value   string
				key     []byte
				options []SecretOption
			}{
				name:  "secret",
				value: _testValue,
				key:   _testKey.Value,
			},
			want: Secret{
				ID:      "aaaa",
				Name:    "secret",
				Type:    TypeGeneric,
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

			got, gotErr := NewSecret(test.input.name, test.input.value, test.input.key, test.input.options...)

			if diff := cmp.Diff(test.want, got, cmpopts.IgnoreFields(Secret{}, "Value"), cmpopts.IgnoreUnexported(Secret{})); diff != "" {
				t.Errorf("NewSecret() = unexpected result (-want +got)\n%s\n", diff)
			}

			gotValue, _ := security.Decrypt(got.Value, _testKey.Value)
			if test.wantValue != string(gotValue) {
				t.Errorf("NewSecret() = unexpected value, want: %s, got: %s\n", test.wantValue, string(gotValue))
			}

			if diff := cmp.Diff(test.wantErr, gotErr); diff != "" {
				t.Errorf("NewSecret() = unexpected error (-want +got)\n%s\n", diff)
			}
		})
	}
}

var (
	_testValue   = "value"
	_testKey, _  = security.NewKeyFromPassword([]byte("test"))
	_testCreated = time.Date(2023, 7, 30, 13, 30, 0, 0, time.Local)
	_testUpdated = time.Date(2023, 8, 2, 13, 30, 0, 0, time.Local)
)
