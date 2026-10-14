package rc4

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex %q: %v", value, err)
	}
	return decoded
}

func TestRC4KnownVectors(t *testing.T) {
	tests := []struct {
		name       string
		key        []byte
		plaintext  []byte
		ciphertext []byte
	}{
		{
			name:       "RFC 6229 key stream prefix",
			key:        mustDecodeHex(t, "0102030405"),
			plaintext:  make([]byte, 16),
			ciphertext: mustDecodeHex(t, "b2396305f03dc027ccc3524a0a1118a8"),
		},
		{
			name:       "Wikipedia key and plaintext",
			key:        []byte("Wiki"),
			plaintext:  []byte("pedia"),
			ciphertext: mustDecodeHex(t, "1021bf0420"),
		},
		{
			name:       "Wikipedia second key and plaintext",
			key:        []byte("Key"),
			plaintext:  []byte("Plaintext"),
			ciphertext: mustDecodeHex(t, "bbf316e8d940af0ad3"),
		},
		{
			name:       "Wikipedia third key and plaintext",
			key:        []byte("Secret"),
			plaintext:  []byte("Attack at dawn"),
			ciphertext: mustDecodeHex(t, "45a01f645fc35b383552544b9bf5"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := append([]byte(nil), tt.plaintext...)

			got := RC4(append([]byte(nil), tt.key...), data)

			if !bytes.Equal(got, tt.ciphertext) {
				t.Errorf("RC4() = %x, want %x", got, tt.ciphertext)
			}
			if !bytes.Equal(data, tt.ciphertext) {
				t.Errorf("RC4() did not encrypt data in place: got %x, want %x", data, tt.ciphertext)
			}
		})
	}
}

func TestRC4RoundTrip(t *testing.T) {
	key := []byte("secret key")
	plaintext := []byte("RC4 encrypts and decrypts with the same operation")
	ciphertext := RC4(append([]byte(nil), key...), append([]byte(nil), plaintext...))

	got := RC4(append([]byte(nil), key...), ciphertext)

	if !bytes.Equal(got, plaintext) {
		t.Errorf("RC4 round trip = %q, want %q", got, plaintext)
	}
}
