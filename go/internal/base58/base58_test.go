package base58

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestEncode_Empty(t *testing.T) {
	if got := Encode([]byte{}); got != "" {
		t.Errorf("Encode(empty) = %q, want %q", got, "")
	}
}

func TestDecode_Empty(t *testing.T) {
	got := Decode("")
	if len(got) != 0 {
		t.Errorf("Decode(empty) = %v, want empty", got)
	}
}

func TestEncode_SingleZeroByte(t *testing.T) {
	if got := Encode([]byte{0}); got != "1" {
		t.Errorf("Encode([0]) = %q, want %q", got, "1")
	}
}

func TestDecode_SingleOne(t *testing.T) {
	got := Decode("1")
	if !bytes.Equal(got, []byte{0}) {
		t.Errorf("Decode(\"1\") = %v, want [0]", got)
	}
}

func TestEncode_LeadingZeroBytes(t *testing.T) {
	// Two leading zero bytes
	input := []byte{0, 0, 1}
	got := Encode(input)
	if got[:2] != "11" {
		t.Errorf("Encode(%v) should start with '11', got %q", input, got)
	}
	decoded := Decode(got)
	if !bytes.Equal(decoded, input) {
		t.Errorf("roundtrip failed: got %v, want %v", decoded, input)
	}
}

// Bitcoin wiki test vectors.
var testVectors = []struct {
	hex     string
	base58  string
}{
	{"", ""},
	{"61", "2g"},
	{"626262", "a3gV"},
	{"636363", "aPEr"},
	{"73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"},
	{"00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"},
	{"00000000000000000000", "1111111111"},
}

func TestKnownVectors(t *testing.T) {
	for _, tc := range testVectors {
		input, err := hex.DecodeString(tc.hex)
		if err != nil {
			t.Fatalf("bad test hex %q: %v", tc.hex, err)
		}

		got := Encode(input)
		if got != tc.base58 {
			t.Errorf("Encode(%s) = %q, want %q", tc.hex, got, tc.base58)
		}

		decoded := Decode(tc.base58)
		if !bytes.Equal(decoded, input) {
			t.Errorf("Decode(%q) = %x, want %x", tc.base58, decoded, input)
		}
	}
}

func TestDecode_InvalidCharacter(t *testing.T) {
	if got := Decode("0OIl"); got != nil {
		t.Errorf("Decode with invalid chars should return nil, got %v", got)
	}
}

func TestRoundtrip(t *testing.T) {
	inputs := [][]byte{
		{1, 2, 3, 4, 5},
		{0, 0, 0, 42},
		{255, 255, 255, 255},
		bytes.Repeat([]byte{0xAB}, 32),
	}
	for _, input := range inputs {
		encoded := Encode(input)
		decoded := Decode(encoded)
		if !bytes.Equal(decoded, input) {
			t.Errorf("roundtrip failed for %x: encoded=%q decoded=%x", input, encoded, decoded)
		}
	}
}
