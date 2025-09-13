package kdf

import "golang.org/x/crypto/argon2"

// argon2id implements the Argon2id key derivation function.
type argon2id struct {
	t    uint32
	m    uint32
	p    uint8
	salt int
}

// NewArgon2id creates a new Argon2id KDF instance with default parameters.
func NewArgon2id() KDF {
	return &argon2id{t: 3, m: 64 * 1024, p: 4, salt: 16}
}

// SaltSize returns the salt size in bytes for Argon2id.
func (a *argon2id) SaltSize() int { return a.salt }

// Derive derives a key from the given password and salt using Argon2id.
func (a *argon2id) Derive(password, salt []byte, outKeyLen int) ([]byte, error) {
	key := argon2.IDKey(password, salt, a.t, a.m, a.p, uint32(outKeyLen))
	return key, nil
}
