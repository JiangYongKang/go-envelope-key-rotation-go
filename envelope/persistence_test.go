package envelope

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// reopenService 模拟进程重启：用同一个状态文件打开全新服务。
func reopenService(t *testing.T, path string) *Service {
	t.Helper()
	s, err := OpenService(path)
	if err != nil {
		t.Fatalf("reopen service: kind=%s err=%v", KindOf(err), err)
	}
	return s
}

// TestPersistRestartRecoversVersions 验证密钥材料、各版本状态与激活版本
// 跨重启原样恢复，且重启前写的历史密文仍可解密。
func TestPersistRestartRecoversVersions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kek.json")

	s, err := OpenService(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	v1, err := s.Rotate()
	if err != nil {
		t.Fatalf("rotate v1: %v", err)
	}
	ctV1, err := s.Encrypt([]byte("written-on-v1"))
	if err != nil {
		t.Fatalf("encrypt v1: %v", err)
	}
	t.Logf("scenario=persist-restart op=encrypt version=%d result=ok", v1)

	v2, err := s.Rotate()
	if err != nil {
		t.Fatalf("rotate v2: %v", err)
	}
	ctV2, err := s.Encrypt([]byte("written-on-v2"))
	if err != nil {
		t.Fatalf("encrypt v2: %v", err)
	}

	// 第一次重启：激活版本、旧版本状态、历史密文都必须恢复。
	s = reopenService(t, path)
	if active, _ := s.store.ActiveVersion(); active != v2 {
		t.Fatalf("after restart active=%d, want %d", active, v2)
	}
	if st, _ := s.store.State(v1); st != StateDeactivated {
		t.Fatalf("v1 state after restart=%s, want deactivated", st)
	}
	if pt, err := s.Decrypt(ctV1); err != nil || string(pt) != "written-on-v1" {
		t.Fatalf("decrypt v1 history after restart: pt=%q err=%v", pt, err)
	}
	t.Logf("scenario=persist-restart op=decrypt-history version=%d result=ok", v1)
	if pt, err := s.Decrypt(ctV2); err != nil || string(pt) != "written-on-v2" {
		t.Fatalf("decrypt v2 after restart: pt=%q err=%v", pt, err)
	}

	// 第二次重启前再轮换一次，确认 next 计数器也持久化（版本号不重用）。
	v3, err := s.Rotate()
	if err != nil {
		t.Fatalf("rotate v3: %v", err)
	}
	ctV3, err := s.Encrypt([]byte("written-on-v3"))
	if err != nil {
		t.Fatalf("encrypt v3: %v", err)
	}
	s = reopenService(t, path)
	if active, _ := s.store.ActiveVersion(); active != v3 {
		t.Fatalf("active=%d, want %d", active, v3)
	}
	for _, tc := range []struct {
		v  uint64
		ct []byte
		pt string
	}{
		{v1, ctV1, "written-on-v1"},
		{v2, ctV2, "written-on-v2"},
		{v3, ctV3, "written-on-v3"},
	} {
		pt, err := s.Decrypt(tc.ct)
		if err == nil {
			t.Logf("scenario=persist-restart op=decrypt version=%d result=ok", tc.v)
		} else {
			t.Logf("scenario=persist-restart op=decrypt version=%d kind=%s", tc.v, KindOf(err))
		}
		if err != nil || string(pt) != tc.pt {
			t.Fatalf("decrypt v%d: pt=%q err=%v", tc.v, pt, err)
		}
	}
}

// TestPersistRetiredDisabledBoundariesSurviveRestart 验证停用/退役的边界结论
// 与重启前一致：退役版本仍然拒绝解密（key_retired），停用版本保持 key_disabled，
// 不会在重启后把退役版本当成可用，也不会找不到版本。
func TestPersistRetiredDisabledBoundariesSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kek.json")
	s, err := OpenService(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	v1, _ := s.Rotate()
	ct1, _ := s.Encrypt([]byte("will-be-retired"))
	v2, _ := s.Rotate()
	ct2, _ := s.Encrypt([]byte("will-be-disabled"))
	v3, _ := s.Rotate()
	_ = v3

	// v1 引用清零后退役（材料销毁必须落盘）。
	s.Forget(v1)
	if err := s.Retire(v1); err != nil {
		t.Fatalf("retire v1: %v", err)
	}
	// v2 手动停用。
	if err := s.Deactivate(v2); err != nil {
		t.Fatalf("deactivate v2: %v", err)
	}

	s = reopenService(t, path)
	if st, _ := s.store.State(v1); st != StateRetired {
		t.Fatalf("v1 state=%s, want retired", st)
	}
	if st, _ := s.store.State(v2); st != StateDisabled {
		t.Fatalf("v2 state=%s, want disabled", st)
	}
	_, err = s.Decrypt(ct1)
	t.Logf("scenario=persist-boundary op=decrypt-retired version=%d kind=%s", v1, KindOf(err))
	if KindOf(err) != KindKeyRetired {
		t.Fatalf("retired after restart: kind=%s, want key_retired", KindOf(err))
	}
	_, err = s.Decrypt(ct2)
	t.Logf("scenario=persist-boundary op=decrypt-disabled version=%d kind=%s", v2, KindOf(err))
	if KindOf(err) != KindKeyDisabled {
		t.Fatalf("disabled after restart: kind=%s, want key_disabled", KindOf(err))
	}
	// 已退役版本不会被“找不到”：状态查询明确返回 retired 而非 not_found。
	if _, err := s.store.decryptKey(v1); KindOf(err) != KindKeyRetired {
		t.Fatalf("retired material after restart kind=%s", KindOf(err))
	}
	// 重启后继续轮换，版本号接着推进，不与历史版本冲突。
	v4, err := s.Rotate()
	if err != nil || v4 <= v3 {
		t.Fatalf("rotate after restart: v4=%d err=%v", v4, err)
	}
}

// TestPersistAtomicWriteLeavesNoTempFiles 验证原子写不留下临时文件，
// 目录里始终只有目标状态文件。
func TestPersistAtomicWriteLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "kek.json")
	s, err := OpenService(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := s.Rotate(); err != nil {
			t.Fatalf("rotate %d: %v", i, err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		pattern := filepath.Base(e.Name())
		if pattern != filepath.Base(path) {
			t.Fatalf("unexpected leftover file %q (atomic write temp not cleaned)", pattern)
		}
	}
}

// TestPersistConcurrentLifecycleAndReopen 在持久化模式下并发执行轮换、写入，
// 结束后重开文件，断言：激活版本一致、版本集合一致、每条密文均可解密。
func TestPersistConcurrentLifecycleAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kek.json")
	s, err := OpenService(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	v1, _ := s.Rotate()

	cts := make(chan []byte, 120)
	var wg sync.WaitGroup
	// 写方。
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				ct, err := s.Encrypt([]byte("p" + itoa(uint64(w*100+i))))
				if err != nil {
					t.Errorf("encrypt: %v", err)
					return
				}
				cts <- ct
			}
		}(w)
	}
	// 轮换方：轮换会把旧版本转 deactivated 并落盘。
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 4; i++ {
			if v, err := s.Rotate(); err != nil {
				t.Errorf("rotate: %v", err)
			} else {
				t.Logf("scenario=persist-concurrent op=rotate version=%d", v)
			}
		}
	}()
	wg.Wait()
	close(cts)

	wantActive, err := s.store.ActiveVersion()
	if err != nil {
		t.Fatalf("active before reopen: %v", err)
	}
	var collected [][]byte
	for ct := range cts {
		collected = append(collected, ct)
	}

	// “重启”：全新服务从同一份文件恢复。
	s2 := reopenService(t, path)
	if active, _ := s2.store.ActiveVersion(); active != wantActive {
		t.Fatalf("active on disk=%d, in memory=%d", active, wantActive)
	}
	if s2.store.next != s.store.next {
		t.Fatalf("next counter disk=%d memory=%d", s2.store.next, s.store.next)
	}
	for _, ct := range collected {
		if _, err := s2.Decrypt(ct); err != nil {
			t.Fatalf("decrypt after concurrent rotation+reopen: kind=%s", KindOf(err))
		}
	}
	// v1 在轮换后应恢复为 deactivated（未退役、可解密），与重启前结论一致。
	if st, _ := s2.store.State(v1); st != StateDeactivated {
		t.Fatalf("v1 state after reopen=%s, want deactivated", st)
	}
	t.Logf("scenario=persist-concurrent verified=%d active=%d result=ok", len(collected), wantActive)
}
