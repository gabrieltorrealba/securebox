package aead

import (
	"golang.org/x/crypto/chacha20poly1305"
)

// xchacha implements the XChaCha20-Poly1305 AEAD cipher.
type xchacha struct{}

// NewXChaCha20Poly1305 creates a new XChaCha20-Poly1305 AEAD instance.
func NewXChaCha20Poly1305() AEAD { return &xchacha{} }

// KeySize returns the key size in bytes for XChaCha20-Poly1305.
func (x *xchacha) KeySize() int   { return chacha20poly1305.KeySize }
// NonceSize returns the nonce size in bytes for XChaCha20-Poly1305.
func (x *xchacha) NonceSize() int { return chacha20poly1305.NonceSizeX }

// Seal encrypts and authenticates plaintext with the given key, nonce, and additional associated data (aad).
// It returns the resulting ciphertext, which includes the authentication tag.
func (x *xchacha) Seal(key, nonce, plaintext, aad []byte) []byte {
	a, _ := chacha20poly1305.NewX(key)
	return a.Seal(nil, nonce, plaintext, aad)
}

// Open decrypts and authenticates ciphertext with the given key, nonce, and additional associated data (aad).
// It returns the resulting plaintext if the authentication is successful; otherwise, it returns an error.
func (x *xchacha) Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return a.Open(nil, nonce, ciphertext, aad)
}
