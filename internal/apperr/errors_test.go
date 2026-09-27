package apperr

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorStringAndWrap(t *testing.T) {
	base := errors.New("gcm: message authentication failed")
	e := Wrap(CategoryTamperedCiphertext, "ciphertext integrity check failed", base)
	if e.Category != CategoryTamperedCiphertext {
		t.Fatalf("category=%s", e.Category)
	}
	if !errors.Is(e, base) {
		t.Fatalf("Unwrap must retain the internal cause for logging")
	}
	if got := e.Error(); got != "tampered_ciphertext: ciphertext integrity check failed" {
		t.Fatalf("Error()=%q", got)
	}
	t.Logf("external=%q", e.Error())
}

func TestFromMapsUnknownErrorsToInternal(t *testing.T) {
	ae := From(fmt.Errorf("some raw internal failure"))
	if ae.Category != CategoryInternal {
		t.Fatalf("unknown error mapped to %s, want %s", ae.Category, CategoryInternal)
	}
	if ae.Message != "internal error" {
		t.Fatalf("unexpected message %q", ae.Message)
	}
	if From(nil) != nil {
		t.Fatalf("From(nil) must be nil")
	}
	t.Logf("unknown-error category=%s message=%q", ae.Category, ae.Message)
}
