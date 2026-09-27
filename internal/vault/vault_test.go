package vault

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/apperr"
	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/envelope"
	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/kms"
)

func cat(err error) apperr.Category { return apperr.From(err).Category }

func setup(t *testing.T) (*kms.KMS, *envelope.Service, *Vault) {
	t.Helper()
	k := kms.New()
	ctx := context.Background()
	if _, err := k.Rotate(ctx); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	svc := envelope.New(k)
	return k, svc, New(svc)
}

func TestPutGetRoundtrip(t *testing.T) {
	ctx := context.Background()
	_, _, v := setup(t)
	pt := []byte("secret record value")
	rec, err := v.Put(ctx, "doc-1", pt)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := v.Get(ctx, "doc-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != string(pt) {
		t.Fatalf("plaintext mismatch: %q", got)
	}
	t.Logf("record=doc-1 version=%d status=roundtrip-ok", rec.VersionID)

	if _, err := v.Get(ctx, "missing"); cat(err) != apperr.CategoryRecordNotFound {
		t.Fatalf("missing record: category=%s want %s", cat(err), apperr.CategoryRecordNotFound)
	}
	t.Logf("record=missing status=denied category=%s", apperr.CategoryRecordNotFound)
}

func TestConcurrentReadWriteDuringRotation(t *testing.T) {
	ctx := context.Background()
	k, _, v := setup(t)

	const records = 40
	// Seed records under v1.
	for i := 0; i < records; i++ {
		name := fmt.Sprintf("rec-%02d", i)
		if _, err := v.Put(ctx, name, []byte("v1:"+name)); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 64)
	var failMu sync.Mutex
	failCats := map[apperr.Category]int{}
	recordFail := func(err error) {
		failMu.Lock()
		failCats[cat(err)]++
		failMu.Unlock()
	}

	deadline := time.Now().Add(80 * time.Millisecond)

	// Writers: partition records so each record has a single writer; that
	// writer's last value is therefore authoritative for the final map state.
	const writersN = 8
	lastWritten := make([]string, records)
	for w := 0; w < writersN; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			i := 0
			for time.Now().Before(deadline) {
				idx := w
				for idx < records {
					name := fmt.Sprintf("rec-%02d", idx)
					i++
					val := fmt.Sprintf("w%d-%d:%s", w, i, name)
					if _, err := v.Put(ctx, name, []byte(val)); err != nil {
						errCh <- err
						return
					}
					lastWritten[idx] = val
					idx += writersN
				}
			}
		}(w)
	}

	// Readers: every successful Get must return a value that actually belongs
	// to the record (never a torn/half value, never another record's value).
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			i := 0
			for time.Now().Before(deadline) {
				idx := i % records
				i++
				name := fmt.Sprintf("rec-%02d", idx)
				got, err := v.Get(ctx, name)
				if err != nil {
					// A Get can only fail for lifecycle reasons (versions are
					// only rotated, never retired here); treat anything else
					// as corruption.
					recordFail(err)
					continue
				}
				s := string(got)
				// Value must be the seed or a writer marker "wW-i:name" and
				// must end with the record name. A torn/half write would
				// violate this shape.
				if !endsWith(s, ":"+name) ||
					(!startsWith(s, "v1:") && !markerLike(s)) {
					errCh <- fmt.Errorf("corrupt read for %s: %q", name, s)
					return
				}
				if markerLike(s) && !endsWith(s, ":"+name) {
					errCh <- fmt.Errorf("marker belongs to another record: %q", s)
					return
				}
			}
		}()
	}

	// Rotator.
	rotDone := make(chan struct{})
	go func() {
		for time.Now().Before(deadline) {
			id, err := k.Rotate(ctx)
			if err != nil {
				errCh <- err
				return
			}
			t.Logf("rotation active-version=%d", id)
			time.Sleep(7 * time.Millisecond)
		}
		close(rotDone)
	}()

	wg.Wait()
	<-rotDone
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent r/w error: %v", err)
	}
	if len(failCats) != 0 {
		t.Fatalf("unexpected Get failures during rotation-only window: %v", failCats)
	}

	// Final consistency: each record reads back as its last written value.
	for i := 0; i < records; i++ {
		name := fmt.Sprintf("rec-%02d", i)
		got, err := v.Get(ctx, name)
		if err != nil {
			t.Fatalf("final get %s: category=%s: %v", name, cat(err), err)
		}
		want := lastWritten[i]
		if want == "" {
			want = "v1:" + name
		}
		if string(got) != want {
			t.Fatalf("record %s final value=%q want %q (lost/half write)", name, got, want)
		}
		rec, _ := v.ReadRecord(ctx, name)
		t.Logf("record=%s final-version=%d status=consistent", name, rec.VersionID)
	}
}
func TestMigrationAndRetirementBoundary(t *testing.T) {
	ctx := context.Background()
	k, _, v := setup(t)
	v1, _ := k.ActiveVersion(ctx)

	if _, err := v.Put(ctx, "old-1", []byte("old data one")); err != nil {
		t.Fatalf("put old-1: %v", err)
	}
	if _, err := v.Put(ctx, "old-2", []byte("old data two")); err != nil {
		t.Fatalf("put old-2: %v", err)
	}

	v2, _ := k.Rotate(ctx)
	if _, err := v.Put(ctx, "new-1", []byte("new data")); err != nil {
		t.Fatalf("put new-1: %v", err)
	}
	t.Logf("versions: old=%d(retained) active=%d", v1, v2)

	// Old data still readable while v1 is retained.
	if got, err := v.Get(ctx, "old-1"); err != nil || string(got) != "old data one" {
		t.Fatalf("pre-migration read old-1: %v %q", err, got)
	}

	// Deactivation suspends decryption immediately, with a distinct reason.
	if err := k.Deactivate(ctx, v1); err != nil {
		t.Fatalf("deactivate retained v1: %v", err)
	}
	if _, err := v.Get(ctx, "old-1"); cat(err) != apperr.CategoryVersionInactive {
		t.Fatalf("read under deactivated v1: category=%s want %s",
			cat(err), apperr.CategoryVersionInactive)
	}
	t.Logf("version=%d state=deactivated status=read-denied category=%s",
		v1, apperr.CategoryVersionInactive)

	// Retiring a deactivated version that still guards data is refused.
	if err := k.Retire(ctx, v1); cat(err) != apperr.CategoryMigrationPending {
		t.Fatalf("retire with unmigrated data: category=%s want %s",
			cat(err), apperr.CategoryMigrationPending)
	}
	t.Logf("version=%d status=retire-denied category=%s", v1, apperr.CategoryMigrationPending)

	// Migration must be able to finish: re-enable v1 (does not change the
	// active encrypting version), migrate all records, then deactivate again.
	if err := k.Reenable(ctx, v1); err != nil {
		t.Fatalf("reenable v1: %v", err)
	}
	if active, _ := k.ActiveVersion(ctx); active != v2 {
		t.Fatalf("reenable changed active version to %d, want %d", active, v2)
	}
	n, err := v.MigrateAll(ctx)
	if err != nil {
		t.Fatalf("migrate all: category=%s: %v", cat(err), err)
	}
	t.Logf("migrated records=%d; active stays=%d", n, v2)
	if n != 2 {
		t.Fatalf("expected 2 rewrites, got %d", n)
	}

	for _, name := range []string{"old-1", "old-2"} {
		rec, err := v.ReadRecord(ctx, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if rec.VersionID != v2 {
			t.Fatalf("%s still on version=%d after migration", name, rec.VersionID)
		}
		t.Logf("record=%s migrated-to-version=%d status=ok", name, rec.VersionID)
	}

	// A second MigrateAll must be a no-op.
	if n, _ := v.MigrateAll(ctx); n != 0 {
		t.Fatalf("second MigrateAll rewrote %d records, want 0", n)
	}

	// Now v1 guards no data: deactivate and retire succeed. MigrateAll has
	// already cleared the migration flag.
	if err := k.Deactivate(ctx, v1); err != nil {
		t.Fatalf("deactivate v1 after migration: %v", err)
	}
	snap, _ := k.GetVersion(ctx, v1)
	if snap.MigrationPending {
		if err := k.MarkMigrated(ctx, v1); err != nil {
			t.Fatalf("mark migrated: %v", err)
		}
	}
	if err := k.Retire(ctx, v1); err != nil {
		t.Fatalf("retire after migration: category=%s: %v", cat(err), err)
	}
	t.Logf("version=%d state=retired status=retire-ok (no data references it)", v1)

	// Current data remains readable under v2 after v1 is retired.
	if got, err := v.Get(ctx, "old-1"); err != nil || string(got) != "old data one" {
		t.Fatalf("post-retire read old-1: category=%s %q %v", cat(err), got, err)
	}
}

func TestMigrateRecordAgainstConcurrentPut(t *testing.T) {
	ctx := context.Background()
	k, _, v := setup(t)
	v1, _ := k.ActiveVersion(ctx)
	if _, err := v.Put(ctx, "hot", []byte("initial")); err != nil {
		t.Fatalf("put: %v", err)
	}
	v2, _ := k.Rotate(ctx)

	var wg sync.WaitGroup
	errCh := make(chan error, 16)
	stop := make(chan struct{})

	// Hammer Puts that keep the record on whichever version Seal picks (all
	// new writes use v2 here).
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			i++
			if _, err := v.Put(ctx, "hot", []byte(fmt.Sprintf("put-%d", i))); err != nil {
				errCh <- err
				return
			}
		}
	}()

	// Concurrently migrate; it must never install a stale blob over a newer Put.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_, _ = v.MigrateRecord(ctx, "hot")
		}
	}()

	time.Sleep(40 * time.Millisecond)
	close(stop)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent put/migrate error: %v", err)
	}

	rec, err := v.ReadRecord(ctx, "hot")
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	if rec.VersionID != v2 {
		t.Fatalf("record ended on version=%d, want active %d", rec.VersionID, v2)
	}
	got, err := v.Get(ctx, "hot")
	if err != nil {
		t.Fatalf("final get: category=%s: %v", cat(err), err)
	}
	if len(got) == 0 {
		t.Fatalf("record lost/empty after concurrent put/migrate")
	}
	t.Logf("record=hot final-version=%d (v1=%d retired-eligible) value-len=%d status=no-lost-update",
		rec.VersionID, v1, len(got))
}

// --- tiny string helpers (avoid pulling strings just for two checks) ---

func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

// markerLike reports whether s begins with a "w<digits>-<digits>:" writer marker.
func markerLike(s string) bool {
	if len(s) < 5 || s[0] != 'w' {
		return false
	}
	i := 1
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i >= len(s) || s[i] != '-' {
		return false
	}
	i++
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return i > start && i < len(s) && s[i] == ':'
}
