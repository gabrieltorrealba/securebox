package securebox

import "errors"

var (
	ErrWeakPassword    = errors.New("password does not meet the minimum policy requirements")
	ErrBadBase64       = errors.New("invalid base64 string")
	ErrCorruptData     = errors.New("corrupt or incomplete data")
	ErrUnsupportedVers = errors.New("unsupported version")
	ErrDecryptFailed   = errors.New("decryption failed (incorrect key/nonce/salt/AAD or tampered data)")
)
