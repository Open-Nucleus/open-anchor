// Package base58 implements Base58btc encoding and decoding using the Bitcoin alphabet.
package base58

import "math/big"

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var bigZero = big.NewInt(0)
var bigRadix = big.NewInt(58)

// decodeMap maps ASCII byte values to their alphabet index (0–57), or -1 if invalid.
var decodeMap [256]int8

func init() {
	for i := range decodeMap {
		decodeMap[i] = -1
	}
	for i, c := range alphabet {
		decodeMap[c] = int8(i)
	}
}

// Encode encodes a byte slice to a Base58btc string.
func Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}

	// Count leading zero bytes — they map to '1' characters.
	var leadingZeros int
	for _, b := range input {
		if b != 0 {
			break
		}
		leadingZeros++
	}

	// Convert the byte slice to a big.Int and repeatedly divide by 58.
	x := new(big.Int).SetBytes(input)
	mod := new(big.Int)

	var encoded []byte
	for x.Cmp(bigZero) > 0 {
		x.DivMod(x, bigRadix, mod)
		encoded = append(encoded, alphabet[mod.Int64()])
	}

	// Add leading '1' characters for each leading zero byte.
	for i := 0; i < leadingZeros; i++ {
		encoded = append(encoded, alphabet[0])
	}

	// Reverse the result (we built it in little-endian order).
	for i, j := 0, len(encoded)-1; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}

	return string(encoded)
}

// Decode decodes a Base58btc string to a byte slice.
// Returns nil if the input contains invalid characters.
func Decode(input string) []byte {
	if len(input) == 0 {
		return []byte{}
	}

	// Count leading '1' characters — they map to leading zero bytes.
	var leadingOnes int
	for _, c := range input {
		if c != rune(alphabet[0]) {
			break
		}
		leadingOnes++
	}

	// Convert from base58 to big.Int.
	x := new(big.Int)
	for _, c := range input {
		if c > 255 || decodeMap[c] == -1 {
			return nil
		}
		x.Mul(x, bigRadix)
		x.Add(x, big.NewInt(int64(decodeMap[c])))
	}

	decoded := x.Bytes()

	// Prepend leading zero bytes.
	result := make([]byte, leadingOnes+len(decoded))
	copy(result[leadingOnes:], decoded)

	return result
}
