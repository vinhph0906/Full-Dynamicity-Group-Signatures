package nizk

import "errors"

// Errors
var (
	ErrInvalidCiphertext = errors.New("invalid ciphertext format")
	ErrInvalidProof      = errors.New("invalid proof structure")
	ErrInvalidChallenge  = errors.New("invalid challenge value")
	ErrInvalidResponse   = errors.New("invalid response value")
)
