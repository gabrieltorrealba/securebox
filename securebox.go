package securebox

import (
	"encoding/base64"
	"fmt"

	"github.com/gabrieltorrealba/securebox/aead"
	adderr "github.com/gabrieltorrealba/securebox/errors"
	"github.com/gabrieltorrealba/securebox/internal"
	"github.com/gabrieltorrealba/securebox/kdf"
	"github.com/gabrieltorrealba/securebox/nonce"
)

const versionByte byte = 0x01

// Box provides methods to encrypt and decrypt data using password-based encryption.
type Box struct {
	// AEAD is the Authenticated Encryption with Associated Data cipher to use.
	AEAD aead.AEAD
	// KDF is the Key Derivation Function to use.
	KDF kdf.KDF
	// NonceSource is the source of nonces to use.
	NonceSource nonce.NonceSource
	// ValidatePW indicates whether to enforce password validation.
	ValidatePW bool
}

// New creates a new Box with the provided options.
// It sets default implementations for AEAD (AES-GCM), KDF (Argon2id), and NonceSource (random nonces).
// The ValidatePW option is enabled by default.
func New(opts ...Option) *Box {
	b := &Box{
		AEAD:        aead.NewAESGCM(),
		KDF:         kdf.NewArgon2id(),
		NonceSource: nonce.NewRandom(),
		ValidatePW:  true,
	}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Encrypt => base64(version|salt|nonce|ciphertext)
// It returns the encrypted data as a base64-encoded string or an error if encryption fails.
func (b *Box) Encrypt(password string, plaintext, aad []byte) (string, error) {
	if b.ValidatePW {
		if err := internal.ValidatePassword(password); err != nil {
			return "", err
		}
	}

	salt := b.KDF.SaltSize()
	s, err := internal.RandBytes(salt)
	if err != nil {
		return "", err
	}

	key, err := b.KDF.Derive([]byte(password), s, b.AEAD.KeySize())
	if err != nil {
		return "", err
	}

	n, err := b.NonceSource.Next(b.AEAD.NonceSize())
	if err != nil {
		return "", err
	}
	if len(n) != b.AEAD.NonceSize() {
		return "", fmt.Errorf("nonce size mismatch: got %d want %d", len(n), b.AEAD.NonceSize())
	}

	ct := b.AEAD.Seal(key, n, plaintext, aad)
	pkg := internal.Pack(versionByte, s, n, ct)
	return base64.StdEncoding.EncodeToString(pkg), nil
}

// Decrypt => base64(version|salt|nonce|ciphertext)
// It returns the decrypted plaintext or an error if decryption fails.
func (b *Box) Decrypt(password, encoded string, aad []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, adderr.ErrBadBase64
	}

	ver, s, n, ct, err := internal.Unpack(raw, b.AEAD.NonceSize(), b.KDF.SaltSize())
	if err != nil {
		return nil, err
	}
	if ver != versionByte {
		return nil, adderr.ErrUnsupportedVers
	}

	key, err := b.KDF.Derive([]byte(password), s, b.AEAD.KeySize())
	if err != nil {
		return nil, err
	}

	pt, err := b.AEAD.Open(key, n, ct, aad)
	if err != nil {
		return nil, adderr.ErrDecryptFailed
	}
	return pt, nil
}
