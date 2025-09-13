package nonce

// NonceSource represents a source of nonces.
type NonceSource interface {
    // Next generates the next nonce of the given size in bytes.
	Next(size int) ([]byte, error)
}
