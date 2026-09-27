package kms

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/apperr"
)

func TestPersistLoadRoundtrip(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")

	k, err := LoadFile(ctx, path)
	if err != nil {
		t.Fatalf("load missing file: %v", err)
	}
	v1, _ := k.Rotate(ctx)
	dk := []byte("0123456789abcdef0123456789abcdef")
	wrapped1, _ := k.EncryptDataKey(ctx, v1, dk, testAAD)
	v2, _ := k.Rotate(ctx)
	if err := k.Persist(ctx); err != nil {
		t.Fatalf("persist: %v", err)
	}
	t.Logf("persisted versions: active=%d retained=%d", v2, v1)

	k2, err := LoadFile(ctx, path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if active, _ := k2.ActiveVersion(ctx); active != v2 {
		t.Fatalf("active after reload=%d want %d", active, v2)
	}
	// Historical wrapped data key still decrypts after reload.
	got, err := k2.DecryptDataKey(ctx, v1, wrapped1, testAAD)
	if err != nil {
		t.Fatalf("historical decrypt after reload version=%d category=%s: %v",
			v1, cat(err), err)
	}
	if string(got) != string(dk) {
		t.Fatalf("reloaded key material mismatch")
	}
	t.Logf("version=%d status=historical-decrypt-after-reload category=%s", v1, apperr.CategoryNone)

	// Retire v1 on the reloaded store, persist, reload: retired state and
	// destroyed material must survive.
	if err := k2.MarkMigrated(ctx, v1); err != nil {
		t.Fatalf("mark migrated: %v", err)
	}
	if err := k2.Deactivate(ctx, v1); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	if err := k2.Retire(ctx, v1); err != nil {
		t.Fatalf("retire: %v", err)
	}
	if err := k2.Persist(ctx); err != nil {
		t.Fatalf("persist retire: %v", err)
	}
	k3, err := LoadFile(ctx, path)
	if err != nil {
		t.Fatalf("reload after retire: %v", err)
	}
	if _, err := k3.DecryptDataKey(ctx, v1, wrapped1, testAAD); cat(err) != apperr.CategoryVersionRetired {
		t.Fatalf("retired after reload: category=%s want %s", cat(err), apperr.CategoryVersionRetired)
	}
	t.Logf("version=%d state=retired-survives-reload category=%s", v1, apperr.CategoryVersionRetired)
}

func TestLoadCorruptedStore(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")

	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadFile(ctx, path); cat(err) != apperr.CategoryMalformedMetadata {
		t.Fatalf("garbage store: category=%s want %s", cat(err), apperr.CategoryMalformedMetadata)
	}
	t.Logf("case=garbage-json category=%s", apperr.CategoryMalformedMetadata)

	if err := os.WriteFile(path, []byte(`{"format_version":99}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadFile(ctx, path); cat(err) != apperr.CategoryMalformedMetadata {
		t.Fatalf("bad format version: category=%s want %s", cat(err), apperr.CategoryMalformedMetadata)
	}
	t.Logf("case=unsupported-format category=%s", apperr.CategoryMalformedMetadata)
}
