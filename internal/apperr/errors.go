// Package apperr defines the externally visible, distinguishable error
// categories used across the managed-key service.
//
// Internal/crypto-level errors are deliberately never leaked to callers:
// every boundary-facing function maps them to one of the Category* values
// below so that callers can react programmatically while logs retain the
// underlying cause.
package apperr

import "errors"

// Category identifies a stable, caller-facing reason for a failure.
type Category string

const (
	// CategoryNone is the zero value.
	CategoryNone Category = ""
	// CategoryMalformedMetadata means the envelope header/metadata could not
	// be parsed or failed structural validation.
	CategoryMalformedMetadata Category = "malformed_metadata"
	// CategoryTamperedCiphertext means the envelope was structurally valid but
	// integrity verification of the ciphertext or header failed.
	CategoryTamperedCiphertext Category = "tampered_ciphertext"
	// CategoryKeyMismatch means the data key was not encrypted by the key
	// version named in the envelope (outer unwrap failed).
	CategoryKeyMismatch Category = "key_mismatch"
	// CategoryVersionNotFound means no key version with the given ID exists.
	CategoryVersionNotFound Category = "version_not_found"
	// CategoryVersionInactive means the version is deactivated and may no
	// longer serve the requested operation.
	CategoryVersionInactive Category = "version_inactive"
	// CategoryVersionRetired means the version has been retired (key material
	// destroyed); data under it can never be decrypted again.
	CategoryVersionRetired Category = "version_retired"
	// CategoryMigrationPending means retirement was refused because records
	// encrypted under the version have not completed migration.
	CategoryMigrationPending Category = "migration_pending"
	// CategoryConflict means an optimistic-concurrency / state conflict.
	CategoryConflict Category = "conflict"
	// CategoryRecordNotFound means the named stored record does not exist.
	CategoryRecordNotFound Category = "record_not_found"
	// CategoryInternal means an unexpected internal failure.
	CategoryInternal Category = "internal"
)

// Error is the only error type allowed to cross package/service boundaries.
// It carries a stable Category and a safe message; it never contains key
// material or raw crypto errors.
type Error struct {
	Category Category
	Message  string
	cause    error
}

// New builds a boundary-facing error.
func New(cat Category, msg string) *Error {
	return &Error{Category: cat, Message: msg}
}

// Wrap behaves like New but retains an internal cause for logging.
func Wrap(cat Category, msg string, cause error) *Error {
	return &Error{Category: cat, Message: msg, cause: cause}
}

// Error implements error.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Category == CategoryNone {
		return e.Message
	}
	return string(e.Category) + ": " + e.Message
}

// Unwrap exposes the internal cause (for logging via errors.Is/As only).
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// From extracts a boundary *Error from err, mapping anything else to
// CategoryInternal so callers never see leaked internals.
func From(err error) *Error {
	if err == nil {
		return nil
	}
	var ae *Error
	if asError(err, &ae) {
		return ae
	}
	return New(CategoryInternal, "internal error")
}

func asError(err error, target **Error) bool {
	return errors.As(err, target)
}
