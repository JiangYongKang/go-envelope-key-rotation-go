package kms

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/apperr"
)

type wrapResult struct {
	id      int64
	wrapped []byte
}

func cat(err error) apperr.Category {
	return apperr.From(err).Category
}

func TestRotateAndDecryptHistory(t *testing.T) {
	ctx := context.Background()
	k := New()

	v1, err := k.Rotate(ctx)
	if err != nil {
		t.Fatalf("rotate v1: %v", err)
	}
	dk := []byte("0123456789abcdef0123456789abcdef")
	wrapped1, err := k.EncryptDataKey(ctx, v1, dk, testAAD)
	if err != nil {
		t.Fatalf("wrap under v1: %v", err)
	}

	v2, err := k.Rotate(ctx)
	if err != nil {
		t.Fatalf("rotate v2: %v", err)
	}
	t.Logf("rotated: active=%d previous=%d(retained)", v2, v1)

	if active, _ := k.ActiveVersion(ctx); active != v2 {
		t.Fatalf("active = %d, want %d", active, v2)
	}
	// Historical data still decrypts under the retained v1.
	got, err := k.DecryptDataKey(ctx, v1, wrapped1, testAAD)
	if err != nil {
		t.Fatalf("decrypt historical data key under retained v1, category=%s: %v", cat(err), err)
	}
	if string(got) != string(dk) {
		t.Fatalf("data key mismatch after decrypt")
	}
	t.Logf("version=%d status=decrypt-ok category=%s", v1, apperr.CategoryNone)

	// New wrapping must use the active v2; encrypting under v1 is refused.
	if _, err := k.EncryptDataKey(ctx, v1, dk, testAAD); cat(err) != apperr.CategoryVersionInactive {
		t.Fatalf("encrypt under retained v1: category=%s want %s", cat(err), apperr.CategoryVersionInactive)
	}
	t.Logf("version=%d status=encrypt-denied category=%s", v1, apperr.CategoryVersionInactive)
}

func TestVersionLifecycleDenials(t *testing.T) {
	ctx := context.Background()
	k := New()
	v1, _ := k.Rotate(ctx)
	dk := []byte("0123456789abcdef0123456789abcdef")
	wrapped, _ := k.EncryptDataKey(ctx, v1, dk, testAAD)
	v2, _ := k.Rotate(ctx) // v1 now retained

	// Missing version.
	if _, err := k.DecryptDataKey(ctx, 999, wrapped, testAAD); cat(err) != apperr.CategoryVersionNotFound {
		t.Fatalf("missing version decrypt: category=%s want %s", cat(err), apperr.CategoryVersionNotFound)
	}
	t.Logf("version=999 status=decrypt-denied category=%s", apperr.CategoryVersionNotFound)

	// Retained version can be deactivated; afterwards decrypt is denied.
	if err := k.Deactivate(ctx, v1); err != nil {
		t.Fatalf("deactivate retained v1: %v", err)
	}
	if _, err := k.DecryptDataKey(ctx, v1, wrapped, testAAD); cat(err) != apperr.CategoryVersionInactive {
		t.Fatalf("deactivated decrypt: category=%s want %s", cat(err), apperr.CategoryVersionInactive)
	}
	t.Logf("version=%d state=deactivated status=decrypt-denied category=%s", v1, apperr.CategoryVersionInactive)

	// Retirement while migration is still pending is refused.
	if err := k.Retire(ctx, v1); cat(err) != apperr.CategoryMigrationPending {
		t.Fatalf("retire with pending migration: category=%s want %s", cat(err), apperr.CategoryMigrationPending)
	}
	t.Logf("version=%d status=retire-denied category=%s", v1, apperr.CategoryMigrationPending)

	if err := k.MarkMigrated(ctx, v1); err != nil {
		t.Fatalf("mark migrated: %v", err)
	}
	if err := k.Retire(ctx, v1); err != nil {
		t.Fatalf("retire after migration: category=%s: %v", cat(err), err)
	}
	t.Logf("version=%d state=retired status=retire-ok", v1)

	// Retired version: decrypt gives the distinct retired category.
	if _, err := k.DecryptDataKey(ctx, v1, wrapped, testAAD); cat(err) != apperr.CategoryVersionRetired {
		t.Fatalf("retired decrypt: category=%s want %s", cat(err), apperr.CategoryVersionRetired)
	}
	t.Logf("version=%d state=retired status=decrypt-denied category=%s", v1, apperr.CategoryVersionRetired)

	// Active version cannot be retired directly.
	if err := k.Retire(ctx, v2); cat(err) != apperr.CategoryConflict {
		t.Fatalf("retire active: category=%s want %s", cat(err), apperr.CategoryConflict)
	}
	t.Logf("version=%d state=active status=retire-denied category=%s", v2, apperr.CategoryConflict)
}

func TestKeyMismatch(t *testing.T) {
	ctx := context.Background()
	k := New()
	v1, _ := k.Rotate(ctx)
	dk := []byte("0123456789abcdef0123456789abcdef")
	wrapped, _ := k.EncryptDataKey(ctx, v1, dk, testAAD)
	v2, _ := k.Rotate(ctx)

	// Wrapped under v1, presented to v2: distinct key mismatch, and the
	// internal crypto error must not leak.
	_, err := k.DecryptDataKey(ctx, v2, wrapped, testAAD)
	if cat(err) != apperr.CategoryKeyMismatch {
		t.Fatalf("cross-version unwrap: category=%s want %s", cat(err), apperr.CategoryKeyMismatch)
	}
	var ae *apperr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("expected *apperr.Error")
	}
	if containsAny(ae.Message, "gcm", "cipher:") {
		t.Fatalf("internal crypto error leaked: %q", ae.Message)
	}
	t.Logf("wrapped-by=%d presented-as=%d category=%s", v1, v2, apperr.CategoryKeyMismatch)
}

func TestConcurrentRotateAndWrap(t *testing.T) {
	ctx := context.Background()
	k := New()
	first, _ := k.Rotate(ctx)

	const writers = 16
	var wg sync.WaitGroup
	errCh := make(chan error, writers)
	results := make(chan wrapResult, 4096)

	// Writers run for a short window while rotations interleave.
	deadline := time.Now().Add(60 * time.Millisecond)
	dk := []byte("0123456789abcdef0123456789abcdef")
	sealOne := func() (wrapResult, error) {
		id, err := k.ActiveVersion(ctx)
		if err != nil {
			return wrapResult{}, err
		}
		wrapped, err := k.EncryptDataKey(ctx, id, dk, testAAD)
		if err != nil {
			// VersionInactive means a rotation landed between ActiveVersion
			// and Encrypt: a legitimate, explainable race — retry once under
			// the freshly active version.
			if cat(err) == apperr.CategoryVersionInactive {
				id, _ = k.ActiveVersion(ctx)
				wrapped, err = k.EncryptDataKey(ctx, id, dk, testAAD)
				if err != nil {
					return wrapResult{}, err
				}
			} else {
				return wrapResult{}, err
			}
		}
		return wrapResult{id: id, wrapped: append([]byte(nil), wrapped...)}, nil
	}

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				res, err := sealOne()
				if err != nil {
					errCh <- err
					return
				}
				results <- res
			}
		}()
	}

	// Collect results concurrently so fast writers never block on a full
	// channel (collecting only after wg.Wait would deadlock).
	var collected []wrapResult
	doneCollecting := make(chan struct{})
	go func() {
		for res := range results {
			collected = append(collected, res)
		}
		close(doneCollecting)
	}()

	// Rotator: rotations paced across the writers' window.
	for i := 0; i < 12; i++ {
		if _, err := k.Rotate(ctx); err != nil {
			t.Fatalf("rotate: %v", err)
		}
		time.Sleep(6 * time.Millisecond)
	}
	wg.Wait()
	close(errCh)
	close(results)
	<-doneCollecting

	for err := range errCh {
		t.Fatalf("concurrent wrap failed, category=%s: %v", cat(err), err)
	}

	// No version was retired during the test, so every wrapped data key must
	// still decrypt under the exact version that sealed it — proving no
	// half-writes or corruption occurred during rotation.
	seen := map[int64]int{}
	for _, res := range collected {
		seen[res.id]++
		got, err := k.DecryptDataKey(ctx, res.id, res.wrapped, testAAD)
		if err != nil {
			t.Fatalf("post-rotation decrypt failed version=%d category=%s: %v",
				res.id, cat(err), err)
		}
		if string(got) != string(dk) {
			t.Fatalf("version=%d decrypted data key mismatch", res.id)
		}
	}
	if len(seen) < 2 {
		t.Fatalf("expected wraps spread across rotating versions, got %v", seen)
	}
	t.Logf("first=%d versions-used=%d wraps=%d status=all-decryptable",
		first, len(seen), len(collected))
}
