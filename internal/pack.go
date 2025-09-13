package internal

import "fmt"

// Pack concatenates version|salt|nonce|ciphertext
// It returns the packed byte slice.
func Pack(ver byte, salt, nonce, ct []byte) []byte {
	out := make([]byte, 1+len(salt)+len(nonce)+len(ct))
	out[0] = ver
	copy(out[1:1+len(salt)], salt)
	copy(out[1+len(salt):1+len(salt)+len(nonce)], nonce)
	copy(out[1+len(salt)+len(nonce):], ct)
	return out
}

// Unpack separates version|salt|nonce|ciphertext
// It returns version, salt, nonce, ciphertext, error
func Unpack(in []byte, nonceSize, saltSize int) (byte, []byte, []byte, []byte, error) {
	min := 1 + saltSize + nonceSize
	if len(in) < min {
		return 0, nil, nil, nil, fmt.Errorf("insufficient data")
	}
	ver := in[0]
	s := in[1 : 1+saltSize]
	n := in[1+saltSize : 1+saltSize+nonceSize]
	ct := in[1+saltSize+nonceSize:]
	return ver, s, n, ct, nil
}
