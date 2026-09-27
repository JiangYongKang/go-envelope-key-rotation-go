// Package vault stores named ciphertext records and provides the migration
// workflow that re-encrypts records from old key versions to the active one.
//
// Concurrency: the record map is guarded by an RWMutex. Cryptographic work
// (seal/open) happens outside the lock; writers install results atomically.
// MigrateRecord uses compare-and-install semantics so that a record updated by
// a concurrent Put cannot be overwritten with stale re-encryption — such a
// race is reported as a conflict and retried by MigrateAll.
package vault

import (
	"bytes"
	"context"
	"sync"

	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/apperr"
	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/envelope"
)

// Record is a stored ciphertext record.
type Record struct {
	Name      string
	Blob      []byte
	VersionID int64
}

// Vault is a concurrency-safe local record store.
type Vault struct {
	svc *envelope.Service

	mu      sync.RWMutex
	records map[string]Record
}

// New creates an empty vault bound to the envelope service.
func New(svc *envelope.Service) *Vault {
	return &Vault{
		svc:     svc,
		records: make(map[string]Record),
	}
}

// Put seals plaintext under the active key version and stores it. The map
// update is a single assignment, so concurrent readers never observe a
// half-written record: they see either the previous blob or the new one.
func (v *Vault) Put(ctx context.Context, name string, plaintext []byte) (Record, error) {
	blob, err := v.svc.Seal(ctx, plaintext)
	if err != nil {
		return Record{}, err
	}
	versionID, err := envelope.KeyVersionID(blob)
	if err != nil {
		return Record{}, err
	}
	rec := Record{Name: name, Blob: cloneBytes(blob), VersionID: versionID}
	v.mu.Lock()
	v.records[name] = rec
	v.mu.Unlock()
	return rec, nil
}

// Get fetches and decrypts a record by name.
func (v *Vault) Get(ctx context.Context, name string) ([]byte, error) {
	v.mu.RLock()
	rec, ok := v.records[name]
	v.mu.RUnlock()
	if !ok {
		return nil, apperr.New(apperr.CategoryRecordNotFound, "record not found")
	}
	// Decrypt a private copy: Open never mutates its input, and a tampered or
	// otherwise failed open yields nil plaintext.
	return v.svc.Open(ctx, cloneBytes(rec.Blob))
}

// ReadRecord returns a copy of the stored record without decrypting.
func (v *Vault) ReadRecord(ctx context.Context, name string) (Record, error) {
	v.mu.RLock()
	rec, ok := v.records[name]
	v.mu.RUnlock()
	if !ok {
		return Record{}, apperr.New(apperr.CategoryRecordNotFound, "record not found")
	}
	rec.Blob = cloneBytes(rec.Blob)
	return rec, nil
}

// migrateMaxAttempts bounds compare-and-install retries under heavy contention.
const migrateMaxAttempts = 16

// MigrateRecord re-encrypts a record from its current key version to the
// active key version when they differ. It returns true when a rewrite happened.
// If the record changed between read and install (a concurrent Put), the
// attempt is retried; exhausting retries reports a conflict with no write.
func (v *Vault) MigrateRecord(ctx context.Context, name string) (bool, error) {
	for attempt := 0; attempt < migrateMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return false, apperr.Wrap(apperr.CategoryInternal, "operation cancelled", err)
		}

		v.mu.RLock()
		rec, ok := v.records[name]
		v.mu.RUnlock()
		if !ok {
			return false, apperr.New(apperr.CategoryRecordNotFound, "record not found")
		}
		oldBlob := cloneBytes(rec.Blob)
		oldVersion := rec.VersionID

		activeID, err := v.svc.KeyVersionActive(ctx)
		if err != nil {
			return false, err
		}
		if oldVersion == activeID {
			return false, nil
		}

		// Re-encryption path: open under the old (retained) version, then seal
		// under the active one. Open never returns partial plaintext.
		plaintext, err := v.svc.Open(ctx, oldBlob)
		if err != nil {
			return false, err
		}
		newBlob, err := v.svc.Seal(ctx, plaintext)
		if err != nil {
			return false, err
		}
		newVersion, err := envelope.KeyVersionID(newBlob)
		if err != nil {
			return false, err
		}

		installed := v.compareAndInstall(name, oldBlob, Record{
			Name:      name,
			Blob:      cloneBytes(newBlob),
			VersionID: newVersion,
		})
		if installed {
			return true, nil
		}
		// Lost the race against a concurrent Put; retry on the fresh value.
	}
	return false, apperr.New(apperr.CategoryConflict,
		"record kept changing during migration; no partial write was kept")
}

// compareAndInstall installs next only when the stored blob still equals
// expected. Returns whether the install happened.
func (v *Vault) compareAndInstall(name string, expected []byte, next Record) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	cur, ok := v.records[name]
	if !ok || !bytes.Equal(cur.Blob, expected) {
		return false
	}
	v.records[name] = next
	return true
}

// MigrateAll re-encrypts every record still under an old key version and
// marks the originating versions migrated in the KMS once no record references
// them. It returns the number of records rewritten.
func (v *Vault) MigrateAll(ctx context.Context) (int, error) {
	names := v.snapshotNames()

	// Count records per old key version as they exist before this run so we
	// can later decide which versions became unreferenced.
	referenced := make(map[int64]struct{})
	v.mu.RLock()
	for _, rec := range v.records {
		referenced[rec.VersionID] = struct{}{}
	}
	v.mu.RUnlock()

	rewritten := 0
	for _, name := range names {
		changed, err := v.MigrateRecord(ctx, name)
		if err != nil {
			return rewritten, err
		}
		if changed {
			rewritten++
		}
	}

	// After rewriting, mark any version that is no longer referenced by any
	// record as migrated (except the active one). Marking is best-effort
	// metadata and never affects the already-committed record rewrites.
	activeID, err := v.svc.KeyVersionActive(ctx)
	if err != nil {
		return rewritten, nil
	}
	stillReferenced := make(map[int64]struct{})
	v.mu.RLock()
	for _, rec := range v.records {
		stillReferenced[rec.VersionID] = struct{}{}
	}
	v.mu.RUnlock()
	for id := range referenced {
		if id == activeID {
			continue
		}
		if _, used := stillReferenced[id]; used {
			continue
		}
		_ = v.svc.MarkVersionMigrated(ctx, id) // ignore already-retired/unknown
	}
	return rewritten, nil
}

func (v *Vault) snapshotNames() []string {
	v.mu.RLock()
	names := make([]string, 0, len(v.records))
	for name := range v.records {
		names = append(names, name)
	}
	v.mu.RUnlock()
	return names
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
