package envelope

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

// TestConcurrentMigrationRotateWrite 验证在线迁移与轮换、新写入同时进行：
//   - 迁移期间新写入始终使用当前激活版本，不被迁移卡住；
//   - 迁移最终全部完成，每条迁后信封明文与原文一致；
//   - 并发轮换产生的新版本不破坏迁移（重试会落到最新激活版本）；
//   - 全部结束后引用总数守恒，源版本引用为零并可退役。
func TestConcurrentMigrationRotateWrite(t *testing.T) {
	s, v1 := newServiceWithKey(t)

	const seed = 60
	plain, items := makeOldEnvelopes(t, s, v1, seed)

	if _, err := s.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	m, err := s.BeginMigration(v1, items)
	if err != nil {
		t.Fatalf("begin migration: %v", err)
	}

	// migrated 收集 sink 交付的新信封。
	var mu sync.Mutex
	migrated := make(map[string][]byte)
	var deliveryCount int
	sink := func(r MigratedRecord) error {
		mu.Lock()
		defer mu.Unlock()
		if _, dup := migrated[r.ID]; dup {
			t.Errorf("record %s delivered twice during concurrent run", r.ID)
		}
		migrated[r.ID] = r.New
		deliveryCount++
		return nil
	}

	// 新写入方：迁移期间持续写入，这些数据使用 v2/v3...，不能被迁移阻塞。
	const writers, perWriter = 4, 40
	newCTs := make(chan []byte, writers*perWriter)
	errCh := make(chan error, writers*perWriter+16)
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWriter; i++ {
				ct, err := s.Encrypt([]byte(fmt.Sprintf("live-w%d-%d", w, i)))
				if err != nil {
					errCh <- fmt.Errorf("live encrypt: %w", err)
					return
				}
				newCTs <- ct
			}
		}(w)
	}

	// 轮换方：迁移进行中再轮换，产生 v3，迁移重试/后续条目应落到激活版本。
	var rotWG sync.WaitGroup
	rotWG.Add(1)
	go func() {
		defer rotWG.Done()
		for i := 0; i < 3; i++ {
			v, err := s.Rotate()
			t.Logf("scenario=migration-concurrent op=rotate version=%d err=%v", v, err)
			if err != nil {
				errCh <- fmt.Errorf("rotate during migration: %w", err)
			}
		}
	}()

	// 迁移方：Run 循环重试直到全部完成（轮换/停用竞态下个别条目可能 transient failed）。
	var migWG sync.WaitGroup
	migWG.Add(1)
	go func() {
		defer migWG.Done()
		for i := 0; i < 20; i++ {
			if err := m.Run(sink); err == nil {
				return
			}
		}
	}()

	rotWG.Wait()
	migWG.Wait()
	close(newCTs)
	wg.Wait()

	p := m.Progress()
	t.Logf("scenario=migration-concurrent source=%d total=%d done=%d failed=%d deliveries=%d",
		v1, p.Total, p.Done, p.Failed, deliveryCount)
	if !p.Complete || p.Done != seed {
		t.Fatalf("migration did not complete: %+v failed=%v", p, m.Failed())
	}
	if deliveryCount != seed {
		t.Fatalf("deliveries=%d, want %d (no double counting under concurrency)", deliveryCount, seed)
	}

	// 校验迁后信封：版本不是源版本，且明文与原始输入一致。
	for _, it := range items {
		newRaw, ok := migrated[it.ID]
		if !ok {
			t.Fatalf("item %s missing from migration output", it.ID)
		}
		env, err := decode(newRaw)
		if err != nil {
			t.Fatalf("decode migrated %s: %v", it.ID, err)
		}
		if env.Version == v1 {
			t.Fatalf("item %s still on source version %d", it.ID, v1)
		}
		pt, err := s.Decrypt(newRaw)
		if err != nil || string(pt) != plain[it.ID] {
			t.Fatalf("migrated item %s: pt=%q err=%v", it.ID, pt, err)
		}
	}

	// 校验迁移期间的新写入：每条都可解密，且都不是源版本 v1。
	var liveCount int
	for ct := range newCTs {
		liveCount++
		env, _ := decode(ct)
		if env.Version == v1 {
			t.Fatalf("live write landed on retired-pending source v1")
		}
		pt, err := s.Decrypt(ct)
		if err != nil {
			t.Fatalf("decrypt live write version=%d: %v", env.Version, err)
		}
		if !bytes.HasPrefix(pt, []byte("live-")) {
			t.Fatalf("live plaintext mismatch: %q", pt)
		}
	}
	t.Logf("scenario=migration-concurrent op=live-writes count=%d result=ok", liveCount)
	if liveCount != writers*perWriter {
		t.Fatalf("live writes=%d, want %d (migration blocked writes?)", liveCount, writers*perWriter)
	}

	// 引用守恒：迁移转移 seed 条到目标版本族，实时写入各自计入激活版本；
	// 源版本必须为零且此时允许退役。
	if s.Refs(v1) != 0 {
		t.Fatalf("source refs=%d, want 0 after concurrent migration", s.Refs(v1))
	}
	if err := s.Retire(v1); err != nil {
		t.Fatalf("retire source after concurrent migration: kind=%s err=%v", KindOf(err), err)
	}
	t.Logf("scenario=migration-concurrent op=retire version=%d result=ok", v1)

	close(errCh)
	for e := range errCh {
		t.Error(e)
	}
}
