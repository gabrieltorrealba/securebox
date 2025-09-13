
# Securebox

Securebox is a Go library for secure encryption and decryption of sensitive data. It provides:

- **AEAD ciphers:** AES-GCM and XChaCha20-Poly1305
- **Key derivation:** Argon2id (password-based)
- **Associated Authenticated Data (AAD):** Contextual data binding
- **Nonce management:** Random or counter-based nonces
- **Versioning:** For key rotation and future upgrades
- **Password policy enforcement:** Strong password requirements

## Installation

Add Securebox to your Go project:

```sh
go get github.com/gabrieltorrealba/securebox
```

## Features

- Encrypt and decrypt data using password-based keys
- Support for AES-GCM and XChaCha20-Poly1305 AEAD ciphers
- Argon2id for secure key derivation
- Configurable nonce sources (random or auditable counter)
- Associated Authenticated Data (AAD) for context binding
- Strong password validation (min 12 chars, upper/lower/digit/symbol)
- Custom error handling

## Usage Example

```go
package main

import (
	"fmt"
	"log"
	"github.com/gabrieltorrealba/securebox"
	"github.com/gabrieltorrealba/securebox/aead"
	"github.com/gabrieltorrealba/securebox/nonce"
)

func main() {
	// Create a Box with AES-GCM and counter nonce
	ns := nonce.NewCounter([4]byte{0xA1, 0xB2, 0xC3, 0xD4}, 0)
	box := securebox.New(
		securebox.WithAEAD(aead.NewAESGCM()),
		securebox.WithNonceSource(ns),
		securebox.WithPasswordValidation(true),
	)

	password := "SuperSecurePassword2025!"
	aad := []byte("table=users;field=email;tenant=acme")
	pii := []byte("DNI=12345678;Email=jhondoe@example.com")

	enc, err := box.Encrypt(password, pii, aad)
	if err != nil {
		log.Fatal("Encrypt:", err)
	}
	fmt.Println("BLOB:", enc)

	dec, err := box.Decrypt(password, enc, aad)
	if err != nil {
		log.Fatal("Decrypt:", err)
	}
	fmt.Println("Plain:", string(dec))

	// Persist ns.Current() in your transactional storage
	current := ns.Current()
	fmt.Printf("Nonce Counter: %d\n", current)
}
```

## API Overview

### Box struct

```go
type Box struct {
	AEAD        aead.AEAD         // AEAD cipher (AES-GCM or XChaCha20-Poly1305)
	KDF         kdf.KDF           // Key Derivation Function (Argon2id)
	NonceSource nonce.NonceSource // Nonce generator (random or counter)
	ValidatePW  bool              // Enforce password validation
}
```

### Creating a Box

```go
box := securebox.New(
	securebox.WithAEAD(aead.NewAESGCM()),
	securebox.WithKDF(kdf.NewArgon2id()),
	securebox.WithNonceSource(nonce.NewRandom()),
	securebox.WithPasswordValidation(true),
)
```

### Encrypt

```go
enc, err := box.Encrypt(password, plaintext, aad)
```
- Returns a base64 string containing version, salt, nonce, and ciphertext.

### Decrypt

```go
dec, err := box.Decrypt(password, encoded, aad)
```
- Returns the decrypted plaintext.

### Password Policy

- Minimum 12 characters
- At least one uppercase, one lowercase, one digit, and one symbol

## Error Handling

Custom errors are provided for weak passwords, invalid base64, corrupt data, unsupported version, and decryption failures.

## License

MIT
