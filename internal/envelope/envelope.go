// Package envelope implements envelope encryption on top of kms: a random
// per-message data key is wrapped by the currently active master-key version,
// and the message is encrypted with AES-256-GCM under the data key.
//
// Wire format (all integers big-endian), version 1:
//
//	offset  size  field
//	0       4     magic "ENV1" (also serves as format identifier)
//	4       1     format version, currently 1
//	5       8     master key version ID (uint64)
//	13      4     length N of the wrapped data key (uint32)
//	17      N     wrapped data key = nonce || AES-GCM(32-byte data key)
//	17+N    12    inner nonce
//	29+N    ...   inner ciphertext = AES-GCM(plaintext)
//
// Integrity: the fixed 17-byte header is authenticated as AAD by the outer
// (master-key) GCM, and the header plus the wrapped data key are authenticated
// as AAD by the inner (data-key) GCM. Swapping the wrapped key between
// envelopes, rewriting the version field, or flipping ciphertext bits all
// fail verification and produce distinguishable error categories:
//
//   - malformed_metadata  : not an ENV1 v1 blob, or truncated/mis-sized fields
//   - key_mismatch        : outer unwrap failed (wrapped key vs named version)
//   - tampered_ciphertext : inner GCM verification failed
//
// Open never returns partial plaintext.
package envelope

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"

	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/apperr"
	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/kms"
)

var (
	magic         = [4]byte{'E', 'N', 'V', '1'}
	formatVersion = byte(1)

	headerSize    = 17 // magic(4) + version(1) + keyID(8) + wrappedLen(4)
	gcmNonceSize  = 12
	dataKeyLength = 32
	// wrappedKeyLength is nonce(12) + 32-byte key + GCM tag(16) for AES-256-GCM.
	wrappedKeyLength = gcmNonceSize + dataKeyLength + 16
)

// errMalformed is the internal sentinel for structural parse failures.
var errMalformed = errors.New("malformed envelope")

// Service performs seal/open operations against a KMS.
type Service struct {
	kms *kms.KMS
}

// New creates an envelope service bound to k.
func New(k *kms.KMS) *Service {
	return &Service{kms: k}
}

// sealMaxAttempts bounds retries when a rotation lands between reading the
// active version and wrapping the data key.
const sealMaxAttempts = 4

// Seal encrypts plaintext under the KMS's current active key version and
// returns the serialized envelope. If a concurrent rotation demotes the
// version in the tiny window between selecting it and wrapping, Seal retries
// against the new active version, so a successful return is always sealed by
// the then-current version and callers never observe the race.
func (s *Service) Seal(ctx context.Context, plaintext []byte) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < sealMaxAttempts; attempt++ {
		out, err := s.sealOnce(ctx, plaintext)
		if err == nil {
			return out, nil
		}
		var ae *apperr.Error
		if errors.As(err, &ae) && ae.Category == apperr.CategoryVersionInactive {
			lastErr = err
			continue // active version rotated underneath us; retry
		}
		return nil, err
	}
	return nil, lastErr
}

func (s *Service) sealOnce(ctx context.Context, plaintext []byte) ([]byte, error) {
	activeID, err := s.kms.ActiveVersion(ctx)
	if err != nil {
		return nil, err // already a boundary error
	}

	dataKey := make([]byte, dataKeyLength)
	if _, err := rand.Read(dataKey); err != nil {
		return nil, apperr.Wrap(apperr.CategoryInternal, "failed to generate data key", err)
	}

	// Build the fixed header first; the outer wrap authenticates it as AAD so
	// the wrapped data key is cryptographically bound to the magic, format
	// version, the naming master-key version and the declared wrapped length.
	header := make([]byte, headerSize)
	copy(header[0:4], magic[:])
	header[4] = formatVersion
	binary.BigEndian.PutUint64(header[5:13], uint64(activeID))
	binary.BigEndian.PutUint32(header[13:17], uint32(wrappedKeyLength))

	wrapped, err := s.kms.EncryptDataKey(ctx, activeID, dataKey, header)
	if err != nil {
		return nil, err
	}
	if len(wrapped) != wrappedKeyLength {
		return nil, apperr.New(apperr.CategoryInternal, "unexpected wrapped data key length")
	}

	gcm, err := newGCM(dataKey)
	if err != nil {
		return nil, apperr.Wrap(apperr.CategoryInternal, "failed to initialize data-key cipher", err)
	}

	innerNonce := make([]byte, gcmNonceSize)
	if _, err := rand.Read(innerNonce); err != nil {
		return nil, apperr.Wrap(apperr.CategoryInternal, "failed to generate nonce", err)
	}

	// Inner AAD binds the ciphertext to the full header and to the exact
	// wrapped data key it belongs with.
	innerAAD := make([]byte, 0, headerSize+len(wrapped))
	innerAAD = append(innerAAD, header...)
	innerAAD = append(innerAAD, wrapped...)
	sealed := gcm.Seal(nil, innerNonce, plaintext, innerAAD)

	out := make([]byte, 0, len(header)+len(wrapped)+len(innerNonce)+len(sealed))
	out = append(out, header...)
	out = append(out, wrapped...)
	out = append(out, innerNonce...)
	out = append(out, sealed...)
	return out, nil
}

// Open verifies and decrypts a serialized envelope using the key version
// recorded inside it. On any failure the returned plaintext is nil.
func (s *Service) Open(ctx context.Context, blob []byte) ([]byte, error) {
	versionID, header, wrapped, rest, err := parse(blob)
	if err != nil {
		return nil, err
	}

	// Outer unwrap: the fixed header is verified as AAD against the named
	// master key. Failure means the wrapped key was not (or is no longer)
	// bound to this version/header — a key mismatch, not a payload-tamper.
	dataKey, err := s.kms.DecryptDataKey(ctx, versionID, wrapped, header)
	if err != nil {
		return nil, err // already categorized (not_found/retired/inactive/mismatch)
	}

	gcm, err := newGCM(dataKey)
	if err != nil {
		return nil, apperr.Wrap(apperr.CategoryInternal, "failed to initialize data-key cipher", err)
	}
	if len(rest) < gcmNonceSize {
		return nil, apperr.New(apperr.CategoryMalformedMetadata, "envelope truncated before inner nonce")
	}
	innerNonce := rest[:gcmNonceSize]
	ciphertext := rest[gcmNonceSize:]

	innerAAD := make([]byte, 0, headerSize+len(wrapped))
	innerAAD = append(innerAAD, header...)
	innerAAD = append(innerAAD, wrapped...)

	plaintext, err := gcm.Open(nil, innerNonce, ciphertext, innerAAD)
	if err != nil {
		return nil, apperr.Wrap(apperr.CategoryTamperedCiphertext,
			"ciphertext integrity check failed", err)
	}
	return plaintext, nil
}

// KeyVersionID returns the key version recorded in an envelope without
// decrypting it.
func KeyVersionID(blob []byte) (int64, error) {
	versionID, _, _, _, err := parse(blob)
	return versionID, err
}

// KeyVersionActive returns the KMS's currently active key version ID.
func (s *Service) KeyVersionActive(ctx context.Context) (int64, error) {
	return s.kms.ActiveVersion(ctx)
}

// MarkVersionMigrated records in the KMS that data under a version has been
// re-encrypted away from it.
func (s *Service) MarkVersionMigrated(ctx context.Context, id int64) error {
	return s.kms.MarkMigrated(ctx, id)
}

// parse structurally validates the blob and returns its pieces. It performs
// no cryptographic verification.
func parse(blob []byte) (versionID int64, header, wrapped, rest []byte, err error) {
	if len(blob) < headerSize {
		return 0, nil, nil, nil, apperr.New(apperr.CategoryMalformedMetadata,
			"envelope shorter than fixed header")
	}
	header = blob[:headerSize]
	if string(header[0:4]) != string(magic[:]) {
		return 0, nil, nil, nil, apperr.New(apperr.CategoryMalformedMetadata,
			"not an envelope blob (bad magic)")
	}
	if header[4] != formatVersion {
		return 0, nil, nil, nil, apperr.New(apperr.CategoryMalformedMetadata,
			"unsupported envelope format version")
	}
	versionID = int64(binary.BigEndian.Uint64(header[5:13]))
	n := int(binary.BigEndian.Uint32(header[13:17]))
	if n == 0 {
		return 0, nil, nil, nil, apperr.New(apperr.CategoryMalformedMetadata,
			"wrapped data key length is zero")
	}
	if len(blob) < headerSize+n+gcmNonceSize {
		return 0, nil, nil, nil, apperr.New(apperr.CategoryMalformedMetadata,
			"envelope truncated: declared wrapped key does not fit")
	}
	wrapped = blob[headerSize : headerSize+n]
	rest = blob[headerSize+n:]
	return versionID, header, wrapped, rest, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
