package internal

import "crypto/rand"

// RandBytes generates a slice of n random bytes using crypto/rand.
// It returns the byte slice and any error encountered.
func RandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}
