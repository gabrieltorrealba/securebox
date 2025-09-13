package nonce

import "crypto/rand"


// randomSource is a NonceSource that generates nonces using crypto/rand.
type randomSource struct{}

// NewRandom creates a new NonceSource that generates random nonces.
func NewRandom() NonceSource { return &randomSource{} }

// Next generates the next nonce of the given size in bytes.
func (randomSource) Next(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)
	return b, err
}
