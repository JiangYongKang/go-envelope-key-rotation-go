package kms

import "errors"

// errCiphertextTooShort is an internal sentinel; it is always mapped to an
// apperr category before crossing package boundaries.
var errCiphertextTooShort = errors.New("ciphertext shorter than nonce")
