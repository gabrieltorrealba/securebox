package tests

import (
	"testing"

	"github.com/gabrieltorrealba/securebox"
)

func TestAADMismatchFails(t *testing.T) {
	box := securebox.New()
	pw := "ClaveSúperSegura2025!"
	msg := []byte("hola mundo")

	enc, err := box.Encrypt(pw, msg, []byte("A"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := box.Decrypt(pw, enc, []byte("B")); err == nil {
		t.Fatal("expected error with AAD mismatch")
	}
}
