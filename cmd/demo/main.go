// Command demo walks a key version through its full lifecycle against the
// local simulated managed-key service and prints the category of every
// outcome so the behavior is directly observable.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/apperr"
	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/envelope"
	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/kms"
	"github.com/highcumontoa/go-envelope-key-rotation-go/internal/vault"
)

func main() {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "envelope-demo-")
	must(err)
	defer os.RemoveAll(dir)

	storePath := filepath.Join(dir, "keystore.json")
	k, err := kms.LoadFile(ctx, storePath)
	must(err)
	svc := envelope.New(k)
	v := vault.New(svc)

	report := func(step string, err error) {
		if err == nil {
			fmt.Printf("[%-28s] ok\n", step)
			return
		}
		fmt.Printf("[%-28s] category=%-20s %s\n", step, apperr.From(err).Category, safeMsg(err))
	}

	v1, err := k.Rotate(ctx)
	must(err)
	fmt.Printf("activated version v%d\n", v1)

	_, err = v.Put(ctx, "report-2026", []byte("quarterly figures written under v1"))
	report("write under v1", err)

	v2, err := k.Rotate(ctx)
	must(err)
	fmt.Printf("rotated: active is now v%d; v%d retained for historical reads\n", v2, v1)

	_, err = v.Put(ctx, "report-2026-q3", []byte("new quarter written under v2"))
	report("write under v2", err)

	_, err = v.Get(ctx, "report-2026")
	report("read pre-rotation data (v1 retained)", err)

	must(k.Persist(ctx))
	fmt.Printf("key store persisted to %s\n", storePath)

	// Deactivation suspends decryption; retirement is refused while data
	// still depends on v1.
	report("deactivate v1", k.Deactivate(ctx, v1))
	_, err = v.Get(ctx, "report-2026")
	report("read under deactivated v1", err)
	report("retire v1 with data pending", k.Retire(ctx, v1))

	// Re-enable to finish migration, migrate, then deactivate+retire.
	report("re-enable v1 for migration", k.Reenable(ctx, v1))
	n, err := v.MigrateAll(ctx)
	report(fmt.Sprintf("migrate %d record(s) to v%d", n, v2), err)
	report("deactivate v1 after migration", k.Deactivate(ctx, v1))
	report("retire v1 after migration", k.Retire(ctx, v1))

	_, err = v.Get(ctx, "report-2026")
	report("read migrated record (now on v2)", err)

	must(k.Persist(ctx))
	fmt.Println("final key states:")
	list, err := k.ListVersions(ctx)
	must(err)
	for _, s := range list {
		fmt.Printf("  v%-2d state=%-11s migrationPending=%-5v\n",
			s.ID, s.State, s.MigrationPending)
	}
}

func safeMsg(err error) string {
	if ae := apperr.From(err); ae != nil {
		return ae.Message
	}
	return ""
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}
