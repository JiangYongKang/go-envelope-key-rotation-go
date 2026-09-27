// Package kms simulates a managed key service with a local, durable key
// store. It owns the lifecycle of master-key versions: generate, activate,
// rotate, deactivate and retire.
//
// Concurrency: all operations are serialized under an internal mutex, and
// Persist writes a fresh temp file and renames it atomically, so a crash or
// concurrent caller can never observe a half-written key store.
package kms

import (
	"context"
	"sync"

	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/apperr"
)

// State is the lifecycle state of a key version.
type State string

const (
	// StatePrepared: generated but never activated; cannot encrypt or decrypt.
	StatePrepared State = "prepared"
	// StateActive: the current encrypting version; also decrypts.
	StateActive State = "active"
	// StateRetained: a former active version; retained for decrypting old data.
	StateRetained State = "retained"
	// StateDeactivated: administratively disabled; denied every operation.
	StateDeactivated State = "deactivated"
	// StateRetired: key material destroyed; cannot be undone.
	StateRetired State = "retired"
)

// Version describes one master-key version. Key material is never exposed
// outside this package except through EncryptDataKey/DecryptDataKey.
type Version struct {
	ID               int64  `json:"id"`
	State            State  `json:"state"`
	MigrationPending bool   `json:"migration_pending"`
	CreatedAtUnix    int64  `json:"created_at_unix"`
	key              []byte `json:"-"`
}

// Snapshot is a copy of version metadata safe to return to callers.
type Snapshot struct {
	ID               int64
	State            State
	MigrationPending bool
	CreatedAtUnix    int64
}

func (v Version) snapshot() Snapshot {
	return Snapshot{
		ID:               v.ID,
		State:            v.State,
		MigrationPending: v.MigrationPending,
		CreatedAtUnix:    v.CreatedAtUnix,
	}
}

// KMS is the managed-key service.
type KMS struct {
	mu       sync.RWMutex
	path     string
	seq      int64
	activeID int64
	versions map[int64]*Version
}

// New creates an empty KMS (no active version until Rotate/Activate).
func New() *KMS {
	return &KMS{
		seq:      0,
		activeID: 0,
		versions: make(map[int64]*Version),
	}
}

// GenerateVersion creates a new version in StatePrepared and returns its ID.
func (k *KMS) GenerateVersion(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, apperr.Wrap(apperr.CategoryInternal, "operation cancelled", err)
	}
	key, err := randomKey()
	if err != nil {
		return 0, apperr.Wrap(apperr.CategoryInternal, "failed to generate key material", err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.seq++
	v := &Version{
		ID:               k.seq,
		State:            StatePrepared,
		MigrationPending: false,
		CreatedAtUnix:    nowUnix(),
		key:              key,
	}
	k.versions[v.ID] = v
	return v.ID, nil
}

// ActivateVersion moves a prepared (or retained) version to active, demoting
// the previously active version to retained. At most one version is active.
func (k *KMS) ActivateVersion(ctx context.Context, id int64) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CategoryInternal, "operation cancelled", err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.versions[id]
	if !ok {
		return apperr.New(apperr.CategoryVersionNotFound, "key version does not exist")
	}
	switch v.State {
	case StateActive:
		return nil // already active: idempotent no-op
	case StatePrepared, StateRetained:
		// allowed
	default:
		return apperr.New(apperr.CategoryVersionInactive,
			"version cannot be activated from its current state")
	}
	if k.activeID != 0 && k.activeID != id {
		if old, ok := k.versions[k.activeID]; ok && old.State == StateActive {
			old.State = StateRetained
			old.MigrationPending = true
		}
	}
	v.State = StateActive
	k.activeID = id
	return nil
}

// Rotate generates a fresh version and atomically activates it; the previous
// active version becomes retained. Returns the new active version ID.
func (k *KMS) Rotate(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, apperr.Wrap(apperr.CategoryInternal, "operation cancelled", err)
	}
	key, err := randomKey()
	if err != nil {
		return 0, apperr.Wrap(apperr.CategoryInternal, "failed to generate key material", err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.seq++
	id := k.seq
	if k.activeID != 0 {
		if old, ok := k.versions[k.activeID]; ok && old.State == StateActive {
			old.State = StateRetained
			old.MigrationPending = true
		}
	}
	k.versions[id] = &Version{
		ID:               id,
		State:            StateActive,
		MigrationPending: false,
		CreatedAtUnix:    nowUnix(),
		key:              key,
	}
	k.activeID = id
	return id, nil
}

// Deactivate moves a retained version to deactivated. A deactivated version
// is denied all crypto operations but its material is retained until Retire.
func (k *KMS) Deactivate(ctx context.Context, id int64) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CategoryInternal, "operation cancelled", err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.versions[id]
	if !ok {
		return apperr.New(apperr.CategoryVersionNotFound, "key version does not exist")
	}
	switch v.State {
	case StateDeactivated:
		return nil
	case StateRetained:
		v.State = StateDeactivated
		return nil
	default:
		return apperr.New(apperr.CategoryConflict,
			"only a retained version can be deactivated")
	}
}

// Reenable reverses a Deactivate: a deactivated (but not retired) version
// returns to retained and may again decrypt historical data. This lets an
// operator suspend use of a version and still complete migration afterwards.
// It never changes which version is the active encrypting version.
func (k *KMS) Reenable(ctx context.Context, id int64) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CategoryInternal, "operation cancelled", err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.versions[id]
	if !ok {
		return apperr.New(apperr.CategoryVersionNotFound, "key version does not exist")
	}
	switch v.State {
	case StateDeactivated:
		v.State = StateRetained
		return nil
	case StateRetained:
		return nil
	case StateRetired:
		return apperr.New(apperr.CategoryVersionRetired,
			"a retired version cannot be re-enabled")
	default:
		return apperr.New(apperr.CategoryConflict,
			"only a deactivated version can be re-enabled")
	}
}

// Retire destroys key material of a deactivated version whose data has been
// fully migrated. Retiring an active/retained version, or one with pending
// migration, is refused with a distinguishable error.
func (k *KMS) Retire(ctx context.Context, id int64) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CategoryInternal, "operation cancelled", err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.versions[id]
	if !ok {
		return apperr.New(apperr.CategoryVersionNotFound, "key version does not exist")
	}
	switch {
	case v.State == StateRetired:
		return nil
	case v.State == StateActive:
		return apperr.New(apperr.CategoryConflict,
			"the active version cannot be retired; rotate first")
	case v.State == StateRetained:
		return apperr.New(apperr.CategoryMigrationPending,
			"retained version is still required to decrypt existing data; deactivate and migrate first")
	case v.State == StatePrepared:
		// A prepared version protects no data: retire (drop) it directly.
	case v.State == StateDeactivated:
		if v.MigrationPending {
			return apperr.New(apperr.CategoryMigrationPending,
				"records encrypted under this version have not finished migration")
		}
	}
	v.State = StateRetired
	v.MigrationPending = false
	wipe(v.key)
	v.key = nil
	return nil
}

// MarkMigrated records that data previously encrypted under the version has
// been re-encrypted to the current active version.
func (k *KMS) MarkMigrated(ctx context.Context, id int64) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CategoryInternal, "operation cancelled", err)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.versions[id]
	if !ok {
		return apperr.New(apperr.CategoryVersionNotFound, "key version does not exist")
	}
	if v.State == StateRetired {
		return apperr.New(apperr.CategoryVersionRetired, "version is already retired")
	}
	v.MigrationPending = false
	return nil
}

// ActiveVersion returns the currently active version ID.
func (k *KMS) ActiveVersion(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, apperr.Wrap(apperr.CategoryInternal, "operation cancelled", err)
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.activeID == 0 {
		return 0, apperr.New(apperr.CategoryVersionNotFound, "no active key version")
	}
	return k.activeID, nil
}

// GetVersion returns a snapshot of one version.
func (k *KMS) GetVersion(ctx context.Context, id int64) (Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return Snapshot{}, apperr.Wrap(apperr.CategoryInternal, "operation cancelled", err)
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	v, ok := k.versions[id]
	if !ok {
		return Snapshot{}, apperr.New(apperr.CategoryVersionNotFound, "key version does not exist")
	}
	return v.snapshot(), nil
}

// ListVersions returns snapshots of all versions ordered by ID.
func (k *KMS) ListVersions(ctx context.Context) ([]Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CategoryInternal, "operation cancelled", err)
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	ids := make([]int64, 0, len(k.versions))
	for id := range k.versions {
		ids = append(ids, id)
	}
	sortInts(ids)
	out := make([]Snapshot, 0, len(ids))
	for _, id := range ids {
		out = append(out, k.versions[id].snapshot())
	}
	return out, nil
}

// EncryptDataKey wraps a data key under the named version, authenticating aad
// (the envelope binds its fixed header here). Only the active version may
// encrypt.
func (k *KMS) EncryptDataKey(ctx context.Context, versionID int64, dataKey, aad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CategoryInternal, "operation cancelled", err)
	}
	k.mu.RLock()
	v, ok := k.versions[versionID]
	if !ok {
		k.mu.RUnlock()
		return nil, apperr.New(apperr.CategoryVersionNotFound, "key version does not exist")
	}
	state, key := v.State, v.key
	k.mu.RUnlock()
	if state != StateActive {
		return nil, apperr.New(apperr.CategoryVersionInactive,
			"only the active key version may encrypt")
	}
	wrapped, err := aeadSeal(key, dataKey, aad)
	if err != nil {
		return nil, apperr.Wrap(apperr.CategoryInternal, "failed to wrap data key", err)
	}
	return wrapped, nil
}

// DecryptDataKey unwraps a data key previously wrapped under the named
// version, verifying the same aad bound at wrap time. Active and retained
// versions may decrypt; deactivated, retired or missing versions are rejected
// with distinguishable errors.
func (k *KMS) DecryptDataKey(ctx context.Context, versionID int64, wrapped, aad []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CategoryInternal, "operation cancelled", err)
	}
	k.mu.RLock()
	v, ok := k.versions[versionID]
	if !ok {
		k.mu.RUnlock()
		return nil, apperr.New(apperr.CategoryVersionNotFound, "key version does not exist")
	}
	state, key := v.State, v.key
	k.mu.RUnlock()
	switch state {
	case StateActive, StateRetained:
		// allowed
	case StateDeactivated, StatePrepared:
		return nil, apperr.New(apperr.CategoryVersionInactive,
			"key version is deactivated and cannot decrypt")
	case StateRetired:
		return nil, apperr.New(apperr.CategoryVersionRetired,
			"key version is retired; its data can no longer be decrypted")
	default:
		return nil, apperr.New(apperr.CategoryVersionInactive, "key version is not usable")
	}
	dataKey, err := aeadOpen(key, wrapped, aad)
	if err != nil {
		// The outer unwrap failing means either the wrapped key was not
		// produced by this version, or the header it is bound to changed:
		// both are a key mismatch, not a payload-tamper case.
		return nil, apperr.Wrap(apperr.CategoryKeyMismatch,
			"data key is not wrapped by the named key version", err)
	}
	return dataKey, nil
}

// mustEncryptWith is a test/helper hook-free internal guard kept for clarity.
var _ = apperr.CategoryInternal
