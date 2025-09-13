package main

import (
	"fmt"
	"log"

	"github.com/gabrieltorrealba/securebox"
	"github.com/gabrieltorrealba/securebox/aead"
	"github.com/gabrieltorrealba/securebox/nonce"
)

func main() {
	// Choose AES-GCM with a counter nonce (auditable)
	ns := nonce.NewCounter([4]byte{0xA1, 0xB2, 0xC3, 0xD4}, 0)
	box := securebox.New(
		securebox.WithAEAD(aead.NewAESGCM()),
		securebox.WithNonceSource(ns),
		securebox.WithPasswordValidation(true),
	)

	// Or Create a Box using XChaCha20-Poly1305 instead of AES-GCM
	// box := securebox.New(
	//   securebox.WithAEAD(aead.NewXChaCha20Poly1305()),
	//)

	password := "ClaveSúperSegura2025!"
    // Contextual AAD (Associated Authenticated Data) can be nil
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
