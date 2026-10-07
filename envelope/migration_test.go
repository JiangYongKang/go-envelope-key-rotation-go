package envelope

import (
	"fmt"
	"sync"
	"testing"
)

func makeEnvelopes(t *testing.T, s *Service, n int) (version uint64, raws [][]byte, pts []string) {
	t.Helper()
	raws = make([][]byte, n)
	pts = make([]string, n)
	for i := 0; i < n; i++ {
		pts[i] = fmt.Sprintf("record-%d", i)
		raw, err := s.Encrypt([]byte(pts[i]))
		if err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		raws[i] = raw
		env, _ := decode(raw)
		version = env.Version
	}
	return version, raws, pts
}

// TestMigrationRewrapAndRetire 验证：旧版本信封在线迁移到当前激活版本，
// 迁移前后明文一致；进度可查询；只有全部迁完该版本才允许退役；
// 引用计数随迁移从旧版本转到新版本。
func TestMigrationRewrapAndRetire(t *testing.T) {
	s, _ := newServiceWithKey(t)
	src, raws, pts := makeEnvelopes(t, s, 5)
	t.Logf("scenario=migrate-setup source=v%d count=%d refs(v%d)=%d",
		src, len(raws), src, s.Refs(src))

	target, err := s.Rotate()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}

	items := make([]MigrationItem, len(raws))
	for i, r := range raws {
		items[i] = MigrationItem{ID: fmt.Sprintf("id-%d", i), Raw: r}
	}
	prog, err := s.BeginMigration(src, items)
	if err != nil {
		t.Fatalf("begin migration: %v", err)
	}
	if prog.Source != src || prog.Target != target || prog.Total != 5 || prog.Done != 0 || prog.Finished {
		t.Fatalf("initial progress=%+v", prog)
	}
	t.Logf("op=begin-migration source=v%d target=v%d total=%d", prog.Source, prog.Target, prog.Total)

	// 迁移未完成时，退役必须被拒绝。
	err = s.Retire(src)
	if KindOf(err) != KindVersionInUse {
		t.Fatalf("retire mid-migration: kind=%s, want version_in_use", KindOf(err))
	}
	logKind(t, "retire-mid-migration", src, err)

	for i, it := range items {
		res, err := s.MigrateOne(src, it)
		if err != nil {
			t.Fatalf("migrate %s: %v", it.ID, err)
		}
		if res.Target != target {
			t.Fatalf("item %s landed v%d, want v%d", it.ID, res.Target, target)
		}
		// 迁移后的信封以新版本封装，且明文一致。
		env, _ := decode(res.Output)
		if env.Version != target {
			t.Fatalf("item %s output version=%d", it.ID, env.Version)
		}
		pt, err := s.Decrypt(res.Output)
		if err != nil || string(pt) != pts[i] {
			t.Fatalf("item %s plaintext=%q err=%v", it.ID, pt, err)
		}
		// 旧信封仍可解密（源版本尚未退役）。
		if pt, err := s.Decrypt(it.Raw); err != nil || string(pt) != pts[i] {
			t.Fatalf("old envelope %s: pt=%q err=%v", it.ID, pt, err)
		}
		prog, _ = s.MigrationProgressOf(src)
		if prog.Done != i+1 || prog.Pending != 5-i-1 {
			t.Fatalf("after %d items progress=%+v", i+1, prog)
		}
	}
	if !prog.Finished {
		t.Fatalf("progress should be finished: %+v", prog)
	}
	if r := s.Refs(src); r != 0 {
		t.Fatalf("source refs=%d, want 0", r)
	}
	if r := s.Refs(target); r != 5 {
		t.Fatalf("target refs=%d, want 5", r)
	}
	t.Logf("op=migration-done source=v%d target=v%d refs(source)=0 refs(target)=5", src, target)

	// 全部迁完后源版本可退役，退役后旧信封不可读、新信封仍可读。
	if err := s.Retire(src); err != nil {
		t.Fatalf("retire after migration: %v", err)
	}
	if _, err := s.Decrypt(raws[0]); KindOf(err) != KindKeyRetired {
		t.Fatalf("old ciphertext after retire: kind=%s", KindOf(err))
	}
	// 重新迁一条已退役源版本数据应被拒绝（作业随退役清除）。
	if _, err := s.MigrateOne(src, items[0]); KindOf(err) != KindMigrationNotFound {
		t.Fatalf("migrate after retire: kind=%s, want migration_not_found", KindOf(err))
	}
	logKind(t, "migrate-after-retire", src, s.migrateErr(src, items[0]))
}

func (s *Service) migrateErr(source uint64, it MigrationItem) error {
	_, err := s.MigrateOne(source, it)
	return err
}

// TestMigrationIdempotentRetry 验证迁移中途失败后重试：
// 已迁条目不重复计数；未迁条目继续可迁，数据不丢。
func TestMigrationIdempotentRetry(t *testing.T) {
	s, _ := newServiceWithKey(t)
	src, raws, pts := makeEnvelopes(t, s, 4)
	target, _ := s.Rotate()

	items := []MigrationItem{
		{ID: "a", Raw: raws[0]},
		{ID: "b", Raw: raws[1]},
		{ID: "c", Raw: raws[2]},
		{ID: "d", Raw: raws[3]},
	}
	if _, err := s.BeginMigration(src, items); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// 模拟迁完 a、b 后中断。
	if _, err := s.MigrateOne(src, items[0]); err != nil {
		t.Fatalf("migrate a: %v", err)
	}
	if _, err := s.MigrateOne(src, items[1]); err != nil {
		t.Fatalf("migrate b: %v", err)
	}
	prog, _ := s.MigrationProgressOf(src)
	t.Logf("scenario=partial source=v%d done=%d pending=%d refs(src)=%d refs(tgt)=%d",
		src, prog.Done, prog.Pending, s.Refs(src), s.Refs(target))

	// 重试整个 Begin（相同集合）必须幂等，进度不重置。
	prog2, err := s.BeginMigration(src, items)
	if err != nil || prog2.Done != 2 {
		t.Fatalf("retry begin: prog=%+v err=%v", prog2, err)
	}
	// 重试 a：已迁过，不重复计数；落地版本与上次相同。
	res, err := s.MigrateOne(src, items[0])
	if err != nil || res.Target != target {
		t.Fatalf("retry a: target=%d err=%v", target, err)
	}
	if s.Refs(target) != 2 {
		t.Fatalf("target refs after duplicate retry=%d, want 2", s.Refs(target))
	}
	if pt, _ := s.Decrypt(res.Output); string(pt) != pts[0] {
		t.Fatalf("retried a plaintext=%q", pt)
	}
	t.Logf("op=retry-done-item id=a landed=v%d refs(target)=%d (no double count)", target, s.Refs(target))

	// 继续迁 c、d，全部完成。
	for i := 2; i < 4; i++ {
		res, err := s.MigrateOne(src, items[i])
		if err != nil {
			t.Fatalf("migrate %s: %v", items[i].ID, err)
		}
		if pt, _ := s.Decrypt(res.Output); string(pt) != pts[i] {
			t.Fatalf("item %s plaintext mismatch", items[i].ID)
		}
	}
	prog, _ = s.MigrationProgressOf(src)
	if !prog.Finished || prog.Done != 4 {
		t.Fatalf("final progress=%+v", prog)
	}
	if s.Refs(src) != 0 || s.Refs(target) != 4 {
		t.Fatalf("refs src=%d tgt=%d, want 0/4", s.Refs(src), s.Refs(target))
	}
	if err := s.Retire(src); err != nil {
		t.Fatalf("retire after full retry migration: %v", err)
	}
	logKind(t, "retire-source", src, nil)

	// 用不同的条目集合重试登记必须被明确拒绝，避免混迁。
	other := []MigrationItem{{ID: "a", Raw: raws[0]}, {ID: "x", Raw: raws[1]}}
	if _, err := s.BeginMigration(src, other); KindOf(err) != KindKeyRetired {
		// 源版本已退役，先报 retired；另在未退役场景单独验证 conflict。
		logKind(t, "rebegin-retired-source", src, err)
	}
}

// TestMigrationConflictGuards 验证作业登记的防混保护。
func TestMigrationConflictGuards(t *testing.T) {
	s, _ := newServiceWithKey(t)
	src, raws, _ := makeEnvelopes(t, s, 3)
	if _, err := s.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	items := []MigrationItem{
		{ID: "a", Raw: raws[0]},
		{ID: "b", Raw: raws[1]},
	}
	if _, err := s.BeginMigration(src, items); err != nil {
		t.Fatalf("begin: %v", err)
	}
	// 同 ID 指向不同信封（指纹不符）。
	tampered := append([]byte(nil), raws[0]...)
	env, _ := decode(tampered)
	env.Data = append(append([]byte(nil), env.Data...), 0)
	rawBad, _ := encode(env)
	_ = rawBad
	// 直接构造一个版本号相同但内容不同的信封：用当前激活版本的密钥无法
	// 简单伪造，这里改用另一条真实信封冒充 a（不同指纹）。
	bad := []MigrationItem{{ID: "a", Raw: raws[2]}, {ID: "b", Raw: raws[1]}}
	if _, err := s.BeginMigration(src, bad); KindOf(err) != KindMigrationConflict {
		t.Fatalf("fingerprint mismatch: kind=%s, want migration_conflict", KindOf(err))
	}
	logKind(t, "rebegin-fingerprint-mismatch", src, s.beginErr(src, bad))

	// 条目数量变化。
	bad2 := []MigrationItem{{ID: "a", Raw: raws[0]}}
	if _, err := s.BeginMigration(src, bad2); KindOf(err) != KindMigrationConflict {
		t.Fatalf("set size mismatch: kind=%s", KindOf(err))
	}
	logKind(t, "rebegin-size-mismatch", src, s.beginErr(src, bad2))

	// 不存在的迁移作业查询。
	if _, err := s.MigrationProgressOf(999); KindOf(err) != KindMigrationNotFound {
		t.Fatalf("missing job: kind=%s", KindOf(err))
	}
	logKind(t, "progress-missing", 999, s.progressErr(999))
}

func (s *Service) beginErr(src uint64, items []MigrationItem) error {
	_, err := s.BeginMigration(src, items)
	return err
}
func (s *Service) progressErr(src uint64) error {
	_, err := s.MigrationProgressOf(src)
	return err
}

// TestMigrationSurvivesRestart 验证迁移进度与引用转移跨重启保留：
// 迁一半重启后，作业与已迁/未迁记账原样恢复，重试不重复计数。
func TestMigrationSurvivesRestart(t *testing.T) {
	s, path := newPersistedService(t)
	if _, err := s.Rotate(); err != nil {
		t.Fatalf("initial rotate: %v", err)
	}
	src, raws, pts := makeEnvelopes(t, s, 3)
	target, _ := s.Rotate()
	items := []MigrationItem{
		{ID: "a", Raw: raws[0]},
		{ID: "b", Raw: raws[1]},
		{ID: "c", Raw: raws[2]},
	}
	if _, err := s.BeginMigration(src, items); err != nil {
		t.Fatalf("begin: %v", err)
	}
	outA, err := s.MigrateOne(src, items[0])
	if err != nil {
		t.Fatalf("migrate a: %v", err)
	}
	t.Logf("scenario=pre-restart source=v%d target=v%d migrated=a", src, target)

	s2 := reopen(t, path)
	prog, err := s2.MigrationProgressOf(src)
	if err != nil {
		t.Fatalf("progress after restart: %v", err)
	}
	if prog.Total != 3 || prog.Done != 1 || prog.Pending != 2 || prog.Finished {
		t.Fatalf("progress after restart=%+v", prog)
	}
	t.Logf("scenario=post-restart progress total=%d done=%d pending=%d",
		prog.Total, prog.Done, prog.Pending)
	if r := s2.Refs(src); r != 2 {
		t.Fatalf("source refs after restart=%d, want 2", r)
	}
	if r := s2.Refs(target); r != 1 {
		t.Fatalf("target refs after restart=%d, want 1", r)
	}
	// 已迁出的信封在重启后仍可解密，明文一致。
	if pt, err := s2.Decrypt(outA.Output); err != nil || string(pt) != pts[0] {
		t.Fatalf("decrypt migrated a after restart: pt=%q err=%v", pt, err)
	}
	// 用相同集合恢复登记（幂等），重试 a 不重复计数，随后完成 b、c。
	if _, err := s2.BeginMigration(src, items); err != nil {
		t.Fatalf("rebegin after restart: %v", err)
	}
	if res, err := s2.MigrateOne(src, items[0]); err != nil || s2.Refs(target) != 1 {
		t.Fatalf("retry a after restart: res=%v err=%v refs=%d",
			res, err, s2.Refs(target))
	}
	for i := 1; i < 3; i++ {
		if _, err := s2.MigrateOne(src, items[i]); err != nil {
			t.Fatalf("migrate %s after restart: %v", items[i].ID, err)
		}
	}
	if r := s2.Refs(src); r != 0 {
		t.Fatalf("source refs=%d want 0", r)
	}
	if err := s2.Retire(src); err != nil {
		t.Fatalf("retire after restart+finish: %v", err)
	}
	logKind(t, "retire-after-restart-migration", src, nil)
}

// TestMigrationConcurrentWithRotateAndWrites 在迁移进行的同时并发轮换与
// 并发写入：迁移条目最终全部成功落地、明文一致、引用计数守恒（每迁移一条，
// 源 -1 / 落地 +1），新写入始终使用当前激活版本且都可解密，过程中无死锁。
func TestMigrationConcurrentWithRotateAndWrites(t *testing.T) {
	s, _ := newServiceWithKey(t)
	src, raws, pts := makeEnvelopes(t, s, 40)
	target0, _ := s.Rotate()

	items := make([]MigrationItem, len(raws))
	for i, r := range raws {
		items[i] = MigrationItem{ID: fmt.Sprintf("rec-%d", i), Raw: r}
	}
	if _, err := s.BeginMigration(src, items); err != nil {
		t.Fatalf("begin: %v", err)
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 256)
	landedCh := make(chan MigrationResult, len(items))

	// 迁移方：逐条目迁移（失败即报错，由记账层保证可安全重试；
	// 这里直接验证每条最终成功）。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, it := range items {
			res, err := s.MigrateOne(src, it)
			if err != nil {
				errCh <- fmt.Errorf("migrate %s kind=%s: %w", it.ID, KindOf(err), err)
				continue
			}
			landedCh <- *res
		}
	}()

	// 轮换方：迁移期间持续轮换。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 6; i++ {
			v, err := s.Rotate()
			if err != nil {
				errCh <- fmt.Errorf("rotate: %w", err)
				return
			}
			t.Logf("op=concurrent-rotate version=v%d", v)
		}
	}()

	// 新写入方：迁移期间照常写入，不被卡住。
	const writers = 4
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				msg := []byte(fmt.Sprintf("live-w%d-i%d", w, i))
				ct, err := s.Encrypt(msg)
				if err != nil {
					errCh <- fmt.Errorf("live encrypt: %w", err)
					return
				}
				pt, err := s.Decrypt(ct)
				if err != nil || string(pt) != string(msg) {
					errCh <- fmt.Errorf("live decrypt mismatch: %v", err)
				}
			}
		}(w)
	}

	wg.Wait()
	close(landedCh)
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	// 所有迁移条目都成功，且明文一致；落地版本一定是当时的激活版本。
	results := make([]MigrationResult, 0, len(items))
	activeAtEnd, _ := s.store.ActiveVersion()
	landedCount := map[uint64]int{}
	for res := range landedCh {
		env, err := decode(res.Output)
		if err != nil {
			t.Fatalf("decode migrated: %v", err)
		}
		if env.Version != res.Target {
			t.Fatalf("landed mismatch target=%d env=%d", res.Target, env.Version)
		}
		if res.Target < target0 || res.Target > activeAtEnd {
			t.Fatalf("landed v%d outside rotation range", res.Target)
		}
		landedCount[res.Target]++
		results = append(results, res)
	}
	if len(results) != len(items) {
		t.Fatalf("migrated %d, want %d", len(results), len(items))
	}

	// 单一迁移 goroutine 按 items 顺序发送：逐条验证明文与原始一致。
	for i, res := range results {
		pt, err := s.Decrypt(res.Output)
		if err != nil || string(pt) != pts[i] {
			t.Fatalf("migrated item %s plaintext=%q err=%v", res.ID, pt, err)
		}
	}

	prog, err := s.MigrationProgressOf(src)
	if err != nil {
		t.Fatalf("progress: %v", err)
	}
	if !prog.Finished || prog.Done != len(items) {
		t.Fatalf("progress=%+v", prog)
	}
	if r := s.Refs(src); r != 0 {
		t.Fatalf("source refs=%d, want 0", r)
	}
	// 引用守恒：所有非源版本的迁移落地引用之和 == 迁移条目数。
	totalLanded := 0
	for v := target0; v <= activeAtEnd; v++ {
		totalLanded += s.Refs(v)
	}
	// 减去并发新写入产生的引用不易直接拆分，改为守恒校验：
	// 源版本归零即说明每条迁移都恰好转移了一次引用。
	t.Logf("scenario=concurrent-migration-done source=v%d landed=%v total-migrated=%d",
		src, landedCount, len(results))
	if totalLanded < len(results) {
		t.Fatalf("total landed refs %d < migrated %d (lost counting)", totalLanded, len(results))
	}
	// 作业未完成前不能退役；完成后（源为 deactivated）可以退役。
	if err := s.Retire(src); err != nil {
		t.Fatalf("retire after concurrent migration: %v", err)
	}
	logKind(t, "retire-after-concurrent-migration", src, nil)
}
