package kms

import "strings"

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// testAAD is the additional authenticated data used by KMS-level tests.
var testAAD = []byte("kms-test-header")
