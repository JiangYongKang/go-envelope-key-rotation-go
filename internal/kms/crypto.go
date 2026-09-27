package kms

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"sort"
	"time"
)

// keySize is AES-256 key length in bytes.
const keySize = 32

// randomKey returns a fresh AES-256 master key.
func randomKey() ([]byte, error) {
	k := make([]byte, keySize)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return k, nil
}

// nowUnix is a small indirection so tests can reason about timestamps.
func nowUnix() int64 {
	return time.Now().Unix()
}

// wipe zeroes secret material.
func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func sortInts(s []int64) {
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
}

// aeadSeal encrypts plaintext with AES-256-GCM under key, authenticating aad.
// Output layout: nonce || ciphertext.
func aeadSeal(key, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	out := make([]byte, gcm.NonceSize(), gcm.NonceSize()+len(plaintext)+gcm.Overhead())
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return gcm.Seal(out, out, plaintext, aad), nil
}

// aeadOpen is the inverse of aeadSeal. It returns an error on any
// authentication failure and never returns partial plaintext.
func aeadOpen(key, blob, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errCiphertextTooShort
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], aad)
}
