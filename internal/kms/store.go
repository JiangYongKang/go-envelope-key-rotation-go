package kms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/apperr"
)

// storeFormatVersion is the on-disk envelope version of the key store itself
// (independent of master-key versions).
const storeFormatVersion = 1

type storedVersion struct {
	ID               int64  `json:"id"`
	State            State  `json:"state"`
	MigrationPending bool   `json:"migration_pending"`
	CreatedAtUnix    int64  `json:"created_at_unix"`
	KeyBase64        string `json:"key"`
}

type storeFile struct {
	FormatVersion int             `json:"format_version"`
	Seq           int64           `json:"seq"`
	ActiveID      int64           `json:"active_id"`
	Versions      []storedVersion `json:"versions"`
}

// LoadFile restores a KMS persisted at path. If the file does not exist yet an
// empty KMS bound to that path is returned; it is written on the first
// Persist call.
func LoadFile(ctx context.Context, path string) (*KMS, error) {
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CategoryInternal, "operation cancelled", err)
	}
	k := New()
	k.path = path

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return k, nil
		}
		return nil, apperr.Wrap(apperr.CategoryInternal, "failed to read key store", err)
	}
	var sf storeFile
	if err := json.Unmarshal(data, &sf); err != nil {
		return nil, apperr.Wrap(apperr.CategoryMalformedMetadata,
			"key store is corrupted: malformed metadata", err)
	}
	if sf.FormatVersion != storeFormatVersion {
		return nil, apperr.New(apperr.CategoryMalformedMetadata,
			fmt.Sprintf("unsupported key store format version %d", sf.FormatVersion))
	}

	k.seq = sf.Seq
	k.activeID = sf.ActiveID
	activeExists := false
	for _, sv := range sf.Versions {
		if !validState(sv.State) {
			return nil, apperr.New(apperr.CategoryMalformedMetadata,
				"key store contains unknown version state")
		}
		var key []byte
		if sv.State != StateRetired {
			key, err = base64.StdEncoding.DecodeString(sv.KeyBase64)
			if err != nil || len(key) != keySize {
				return nil, apperr.Wrap(apperr.CategoryMalformedMetadata,
					"key store contains invalid key material encoding", err)
			}
		}
		if sv.ID == k.activeID {
			if sv.State != StateActive {
				return nil, apperr.New(apperr.CategoryMalformedMetadata,
					"key store active pointer does not match version state")
			}
			activeExists = true
		}
		k.versions[sv.ID] = &Version{
			ID:               sv.ID,
			State:            sv.State,
			MigrationPending: sv.MigrationPending,
			CreatedAtUnix:    sv.CreatedAtUnix,
			key:              key,
		}
	}
	if k.activeID != 0 && !activeExists {
		return nil, apperr.New(apperr.CategoryMalformedMetadata,
			"key store active pointer references a missing version")
	}
	return k, nil
}

func validState(s State) bool {
	switch s {
	case StatePrepared, StateActive, StateRetained, StateDeactivated, StateRetired:
		return true
	}
	return false
}

// Persist atomically writes the key store: serialize to a temp file in the
// same directory, fsync it, then rename it over the destination. Readers
// therefore always see either the previous or the next complete store.
func (k *KMS) Persist(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return apperr.Wrap(apperr.CategoryInternal, "operation cancelled", err)
	}
	if k.path == "" {
		return apperr.New(apperr.CategoryInternal, "in-memory KMS has no store path")
	}

	k.mu.RLock()
	sf := storeFile{
		FormatVersion: storeFormatVersion,
		Seq:           k.seq,
		ActiveID:      k.activeID,
		Versions:      make([]storedVersion, 0, len(k.versions)),
	}
	ids := make([]int64, 0, len(k.versions))
	for id := range k.versions {
		ids = append(ids, id)
	}
	sortInts(ids)
	for _, id := range ids {
		v := k.versions[id]
		sv := storedVersion{
			ID:               v.ID,
			State:            v.State,
			MigrationPending: v.MigrationPending,
			CreatedAtUnix:    v.CreatedAtUnix,
		}
		if v.key != nil {
			sv.KeyBase64 = base64.StdEncoding.EncodeToString(v.key)
		}
		sf.Versions = append(sf.Versions, sv)
	}
	k.mu.RUnlock()

	data, err := json.MarshalIndent(&sf, "", "  ")
	if err != nil {
		return apperr.Wrap(apperr.CategoryInternal, "failed to serialize key store", err)
	}

	dir := filepath.Dir(k.path)
	tmp, err := os.CreateTemp(dir, ".keystore-*")
	if err != nil {
		return apperr.Wrap(apperr.CategoryInternal, "failed to create temp key store", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return apperr.Wrap(apperr.CategoryInternal, "failed to write key store", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return apperr.Wrap(apperr.CategoryInternal, "failed to fsync key store", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return apperr.Wrap(apperr.CategoryInternal, "failed to close key store", err)
	}
	if err := os.Rename(tmpName, k.path); err != nil {
		cleanup()
		return apperr.Wrap(apperr.CategoryInternal, "failed to commit key store", err)
	}
	return nil
}
