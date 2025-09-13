package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// aesgcm implements the AEAD interface using AES in Galois/Counter Mode (GCM).
type aesgcm struct{}

// NewAESGCM creates a new instance of AES-GCM AEAD.
func NewAESGCM() AEAD { return &aesgcm{} }

// AES-256 GCM uses a 32-byte (256-bit) key
func (a *aesgcm) KeySize() int   { return 32 } 
// AES GCM standard nonce size is 12 bytes (96 bits)
func (a *aesgcm) NonceSize() int { return 12 } 

// Seal encrypts and authenticates plaintext with the given key, nonce, and additional associated data (aad).
// It returns the resulting ciphertext, which includes the authentication tag.
func (a *aesgcm) Seal(key, nonce, plaintext, aad []byte) []byte {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCMWithNonceSize(block, a.NonceSize())
	return gcm.Seal(nil, nonce, plaintext, aad)
}

// Open decrypts and authenticates ciphertext with the given key, nonce, and additional associated data (aad).
// It returns the resulting plaintext if the authentication is successful; otherwise, it returns an error.
func (a *aesgcm) Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCMWithNonceSize(block, a.NonceSize())
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("gcm open: %w", err)
	}
	return pt, nil
}
