package tests

import (
	"testing"

	"github.com/gabrieltorrealba/securebox"
)

func TestEncryptDecrypt_Random(t *testing.T) {
	box := securebox.New()
	pw := "ClaveSúperSegura2025!"
	aad := []byte("ctx")
	msg := []byte("hola mundo")

	enc, err := box.Encrypt(pw, msg, aad)
	if err != nil {
		t.Fatal(err)
	}

	dec, err := box.Decrypt(pw, enc, aad)
	if err != nil {
		t.Fatal(err)
	}

	if string(dec) != string(msg) {
		t.Fatalf("got %q want %q", dec, msg)
	}
}
