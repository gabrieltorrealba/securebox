package aead

// AEAD represents an Authenticated Encryption with Associated Data cipher.
// It provides methods for sealing (encrypting) and opening (decrypting) data
// with authentication, using a symmetric key and a nonce.
type AEAD interface {
	// KeySize returns the key size in bytes required by the AEAD cipher.
	KeySize() int
	// NonceSize returns the nonce size in bytes required by the AEAD cipher.
	NonceSize() int
	// Seal encrypts and authenticates plaintext with the given key, nonce, and additional associated data (aad).
	// It returns the resulting ciphertext, which includes the authentication tag.
	Seal(key, nonce, plaintext, aad []byte) []byte
	// Open decrypts and authenticates ciphertext with the given key, nonce, and additional associated data (aad).
	// It returns the resulting plaintext if the authentication is successful; otherwise, it returns an error.
	Open(key, nonce, ciphertext, aad []byte) ([]byte, error)
}
