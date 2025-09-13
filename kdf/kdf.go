package kdf

// KDF represents a Key Derivation Function.
type KDF interface {
    // SaltSize returns the size of the salt in bytes.
	SaltSize() int
    // Derive derives a key from the given password and salt.
	Derive(password, salt []byte, outKeyLen int) ([]byte, error)
}
