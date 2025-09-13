package internal

import (
	"unicode"

	geterr "github.com/gabrieltorrealba/securebox/errors"
)

// ValidatePassword checks if the provided password meets the minimum security requirements.
// Requirements:
// - Minimum length of 12 characters
// - At least one uppercase letter
// - At least one lowercase letter
// - At least one digit
// - At least one symbol (punctuation or special character)
// Returns an error if the password is weak, otherwise returns nil.
func ValidatePassword(pw string) error {
	if len(pw) < 12 {
		return geterr.ErrWeakPassword
	}
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, ch := range pw {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch), unicode.IsSymbol(ch):
			hasSymbol = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit || !hasSymbol {
		return geterr.ErrWeakPassword
	}
	return nil
}
