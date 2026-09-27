package envelope

import (
	"context"
	"errors"
	"testing"

	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/apperr"
	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/kms"
)

func cat(err error) apperr.Category {
	return apperr.From(err).Category
}

func newRotated(t *testing.T) (*kms.KMS, *Service) {
	t.Helper()
	k := kms.New()
	ctx := context.Background()
	if _, err := k.Rotate(ctx); err != nil {
		t.Fatalf("initial rotate: %v", err)
	}
	return k, New(k)
}

func TestSealOpenRoundtrip(t *testing.T) {
	ctx := context.Background()
	_, svc := newRotated(t)
	plaintext := []byte("the quick brown envelope jumps over lazy KMS")

	blob, err := svc.Seal(ctx, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	got, err := svc.Open(ctx, blob)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("plaintext mismatch: %q", got)
	}
	active, _ := svc.KeyVersionActive(ctx)
	ver, _ := KeyVersionID(blob)
	t.Logf("sealed under active version=%d roundtrip=ok category=%s", ver, apperr.CategoryNone)
	if ver != active {
		t.Fatalf("envelope version=%d want active=%d", ver, active)
	}
}

func TestDecryptAfterRotation(t *testing.T) {
	ctx := context.Background()
	k, svc := newRotated(t)
	v1, _ := k.ActiveVersion(ctx)
	oldPlaintext := []byte("written before the rotation happened")

	oldBlob, err := svc.Seal(ctx, oldPlaintext)
	if err != nil {
		t.Fatalf("seal under v1: %v", err)
	}

	v2, err := k.Rotate(ctx)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	t.Logf("rotated %d -> %d; old data retained", v1, v2)

	// Historical blob stays decryptable under the retained old version.
	got, err := svc.Open(ctx, oldBlob)
	if err != nil {
		t.Fatalf("open pre-rotation blob after rotate, version=%d category=%s: %v",
			v1, cat(err), err)
	}
	if string(got) != string(oldPlaintext) {
		t.Fatalf("historical plaintext mismatch: %q", got)
	}
	t.Logf("version=%d status=decrypt-ok (pre-rotation data)", v1)

	// New writes use the new active version.
	newBlob, _ := svc.Seal(ctx, []byte("fresh"))
	nv, _ := KeyVersionID(newBlob)
	if nv != v2 {
		t.Fatalf("new write version=%d want %d", nv, v2)
	}
	t.Logf("version=%d status=new-writes-ok", v2)
}

func TestMalformedMetadata(t *testing.T) {
	ctx := context.Background()
	_, svc := newRotated(t)
	good, _ := svc.Seal(ctx, []byte("hello"))

	cases := []struct {
		name string
		blob []byte
	}{
		{"empty", []byte{}},
		{"short header", good[:10]},
		{"bad magic", mutate(clone(good), 0, 'X')},
		{"bad format version", mutate(clone(good), 4, 9)},
		{"declared length too large", mutateU32(clone(good), 13, 999999)},
	}
	for _, tc := range cases {
		_, err := svc.Open(ctx, tc.blob)
		if cat(err) != apperr.CategoryMalformedMetadata {
			t.Fatalf("%s: category=%s want %s", tc.name, cat(err), apperr.CategoryMalformedMetadata)
		}
		t.Logf("case=%s status=rejected category=%s", tc.name, apperr.CategoryMalformedMetadata)
	}
}

func TestTamperedCiphertext(t *testing.T) {
	ctx := context.Background()
	_, svc := newRotated(t)
	blob, _ := svc.Seal(ctx, []byte("integrity matters"))

	// Flip a byte deep in the ciphertext region (past header+wrapped key+nonce).
	tampered := clone(blob)
	tampered[len(tampered)-1] ^= 0xFF
	got, err := svc.Open(ctx, tampered)
	if cat(err) != apperr.CategoryTamperedCiphertext {
		t.Fatalf("flipped ciphertext byte: category=%s want %s, plaintext=%v",
			cat(err), apperr.CategoryTamperedCiphertext, got)
	}
	if got != nil {
		t.Fatalf("failure path returned partial plaintext: %x", got)
	}
	t.Logf("case=flip-ciphertext-byte status=rejected category=%s plaintext=nil",
		apperr.CategoryTamperedCiphertext)

	// Tamper the inner nonce as well.
	tamperedNonce := clone(blob)
	// header is 17 bytes; skip the variable wrapped key using declared length.
	n := int(blob[13])<<24 | int(blob[14])<<16 | int(blob[15])<<8 | int(blob[16])
	tamperedNonce[17+n] ^= 0x01
	if _, err := svc.Open(ctx, tamperedNonce); cat(err) != apperr.CategoryTamperedCiphertext {
		t.Fatalf("flipped nonce: category=%s want %s", cat(err), apperr.CategoryTamperedCiphertext)
	}
	t.Logf("case=flip-inner-nonce status=rejected category=%s", apperr.CategoryTamperedCiphertext)
}

func TestWrappedKeySwapIsKeyMismatch(t *testing.T) {
	ctx := context.Background()
	k, svc := newRotated(t)

	blobA, _ := svc.Seal(ctx, []byte("message A"))
	v2, _ := k.Rotate(ctx)
	blobB, _ := svc.Seal(ctx, []byte("message B"))

	// Splice B's (v2-wrapped) data key into A's header/body. A's header names
	// v1, so the outer unwrap happens under v1 but the wrapped key belongs to
	// v2: this must be key_mismatch, never a successful decrypt.
	nA := u32(blobA[13:17])
	nB := u32(blobB[13:17])
	if nA != nB {
		// Lengths are constant for AES-GCM of a 32-byte key; keep the guard.
		t.Fatalf("wrapped key lengths differ: %d vs %d", nA, nB)
	}
	spliced := clone(blobA)
	copy(spliced[17:17+nA], blobB[17:17+nB])

	got, err := svc.Open(ctx, spliced)
	if cat(err) != apperr.CategoryKeyMismatch {
		t.Fatalf("wrapped-key swap: category=%s want %s plaintext=%v",
			cat(err), apperr.CategoryKeyMismatch, got)
	}
	if got != nil {
		t.Fatalf("key-mismatch path returned plaintext: %x", got)
	}
	t.Logf("case=swap-wrapped-key presented-version=1 actual-wrapper=%d status=rejected category=%s",
		v2, apperr.CategoryKeyMismatch)

	// Rewriting the version field to point at v2 while keeping A's v1-wrapped
	// key is also a key mismatch.
	rewritten := clone(blobA)
	setU64(rewritten[5:13], uint64(v2))
	if _, err := svc.Open(ctx, rewritten); cat(err) != apperr.CategoryKeyMismatch {
		t.Fatalf("rewritten version field: category=%s want %s", cat(err), apperr.CategoryKeyMismatch)
	}
	t.Logf("case=rewrite-version-field to=%d status=rejected category=%s",
		v2, apperr.CategoryKeyMismatch)
}

func TestRetiredAndDeactivatedRejected(t *testing.T) {
	ctx := context.Background()
	k, svc := newRotated(t)
	v1, _ := k.ActiveVersion(ctx)
	blob, _ := svc.Seal(ctx, []byte("doomed"))

	v2, _ := k.Rotate(ctx) // v1 retained
	if err := k.Deactivate(ctx, v1); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if _, err := svc.Open(ctx, blob); cat(err) != apperr.CategoryVersionInactive {
		t.Fatalf("deactivated open: category=%s want %s", cat(err), apperr.CategoryVersionInactive)
	}
	t.Logf("version=%d state=deactivated status=open-denied category=%s",
		v1, apperr.CategoryVersionInactive)

	// A deactivated-but-not-migrated version cannot retire.
	if err := k.Retire(ctx, v1); cat(err) != apperr.CategoryMigrationPending {
		t.Fatalf("retire pending: category=%s want %s", cat(err), apperr.CategoryMigrationPending)
	}
	t.Logf("version=%d status=retire-denied category=%s", v1, apperr.CategoryMigrationPending)

	_ = k.MarkMigrated(ctx, v1)
	_ = k.Retire(ctx, v1)
	if _, err := svc.Open(ctx, blob); cat(err) != apperr.CategoryVersionRetired {
		t.Fatalf("retired open: category=%s want %s", cat(err), apperr.CategoryVersionRetired)
	}
	t.Logf("version=%d state=retired active=%d status=open-denied category=%s",
		v1, v2, apperr.CategoryVersionRetired)
}

func TestNoInternalErrorLeak(t *testing.T) {
	ctx := context.Background()
	_, svc := newRotated(t)
	blob, _ := svc.Seal(ctx, []byte("x"))
	tampered := clone(blob)
	tampered[len(tampered)-1] ^= 0xFF
	_, err := svc.Open(ctx, tampered)
	var ae *apperr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("expected *apperr.Error, got %T", err)
	}
	for _, leaked := range []string{"gcm", "cipher:", "chacha"} {
		if contains(ae.Error(), leaked) {
			t.Fatalf("internal crypto detail leaked: %q", ae.Error())
		}
	}
}

// --- small byte helpers ---

func clone(b []byte) []byte { return append([]byte(nil), b...) }

func mutate(b []byte, idx int, v byte) []byte {
	b[idx] = v
	return b
}

func mutateU32(b []byte, idx int, v uint32) []byte {
	b[idx] = byte(v >> 24)
	b[idx+1] = byte(v >> 16)
	b[idx+2] = byte(v >> 8)
	b[idx+3] = byte(v)
	return b
}

func u32(b []byte) int {
	return int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
}

func setU64(b []byte, v uint64) {
	for i := 0; i < 8; i++ {
		b[i] = byte(v >> (56 - 8*i))
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
