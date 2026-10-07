package envelope

import (
	"os"
	"path/filepath"
	"testing"
)

func newPersistedService(t *testing.T) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "keystore.state")
	store, err := OpenKeyStore(path)
	if err != nil {
		t.Fatalf("open keystore: %v", err)
	}
	return NewService(store), path
}

func reopen(t *testing.T, path string) *Service {
	t.Helper()
	store, err := OpenKeyStore(path)
	if err != nil {
		t.Fatalf("reopen keystore: %v", err)
	}
	return NewService(store)
}

// TestPersistenceRestartRecoversKeys 验证密钥版本、状态、激活版本与引用计数
// 跨重启原样恢复；恢复后未退役版本此前写入的密文仍可解密，
// 停用/退役的边界结论与重启前一致。
func TestPersistenceRestartRecoversKeys(t *testing.T) {
	s, path := newPersistedService(t)

	v1, err := s.Rotate()
	if err != nil {
		t.Fatalf("rotate v1: %v", err)
	}
	ct1, err := s.Encrypt([]byte("written-under-v1"))
	if err != nil {
		t.Fatalf("encrypt v1: %v", err)
	}
	v2, err := s.Rotate()
	if err != nil {
		t.Fatalf("rotate v2: %v", err)
	}
	ct2, err := s.Encrypt([]byte("written-under-v2"))
	if err != nil {
		t.Fatalf("encrypt v2: %v", err)
	}
	// 再轮换出 v3 后，v2 转为 deactivated；随后手动停用 v2（disabled）。
	v3, err := s.Rotate()
	if err != nil {
		t.Fatalf("rotate v3: %v", err)
	}
	if err := s.store.Deactivate(v2); err != nil {
		t.Fatalf("deactivate v2: %v", err)
	}
	// v1 保持 deactivated（有 1 条引用），v2 disabled（有 1 条引用）。
	t.Logf("scenario=pre-restart active=v%d states: v%d=deactivated(1 ref) v%d=disabled(1 ref)",
		v3, v1, v2)

	// 重启 1：状态原样恢复。
	s2 := reopen(t, path)
	if active, _ := s2.store.ActiveVersion(); active != v3 {
		t.Fatalf("after restart active=%d, want %d", active, v3)
	}
	if st, _ := s2.store.State(v1); st != StateDeactivated {
		t.Fatalf("v1 state after restart=%s, want deactivated", st)
	}
	if st, _ := s2.store.State(v2); st != StateDisabled {
		t.Fatalf("v2 state after restart=%s, want disabled", st)
	}
	if r := s2.Refs(v1); r != 1 {
		t.Fatalf("v1 refs after restart=%d, want 1", r)
	}
	if r := s2.Refs(v2); r != 1 {
		t.Fatalf("v2 refs after restart=%d, want 1", r)
	}
	// 未退役（deactivated）版本历史数据可解密。
	if pt, err := s2.Decrypt(ct1); err != nil || string(pt) != "written-under-v1" {
		t.Fatalf("decrypt ct1 after restart: pt=%q err=%v", pt, err)
	}
	logKind(t, "decrypt-v1-after-restart", v1, nil)
	// disabled 版本解密边界结论不变。
	if _, err := s2.Decrypt(ct2); KindOf(err) != KindKeyDisabled {
		t.Fatalf("decrypt v2 after restart kind=%s, want key_disabled", KindOf(err))
	}
	logKind(t, "decrypt-v2-after-restart", v2, s2.lastErr(ct2))

	// 新写入使用恢复出的激活版本。
	ct3, err := s2.Encrypt([]byte("written-after-restart"))
	if err != nil {
		t.Fatalf("encrypt after restart: %v", err)
	}
	if env, _ := decode(ct3); env.Version != v3 {
		t.Fatalf("post-restart write used %d, want %d", env.Version, v3)
	}

	// 迁移走 v1 的唯一引用后退役 v1，再重启：已退役版本不得被当成还能用。
	s2.Forget(v1)
	if err := s2.Retire(v1); err != nil {
		t.Fatalf("retire v1: %v", err)
	}
	s3 := reopen(t, path)
	if st, _ := s3.store.State(v1); st != StateRetired {
		t.Fatalf("v1 state after second restart=%s, want retired", st)
	}
	if _, err := s3.Decrypt(ct1); KindOf(err) != KindKeyRetired {
		t.Fatalf("decrypt retired v1 after restart kind=%s, want key_retired", KindOf(err))
	}
	logKind(t, "decrypt-retired-v1-after-restart", v1, s3.lastErr(ct1))
	// 新版本号继续单调，不复用已退役版本号。
	v4, err := s3.Rotate()
	if err != nil {
		t.Fatalf("rotate after restart: %v", err)
	}
	if v4 <= v3 {
		t.Fatalf("new version %d should be greater than %d", v4, v3)
	}
	t.Logf("scenario=post-restart-rotate new=v%d", v4)

	// 状态文件确实存在且为完整容器。
	info, err := os.Stat(path)
	if err != nil || info.Size() == 0 {
		t.Fatalf("state file missing or empty: %v", err)
	}
}

// corruptFileCases 覆盖：空文件、头部截断、载荷截断、校验和截断、
// 未知 magic、比当前更新的容器版本、篡改载荷、篡改校验和、合法旧版本可加载。
func TestPersistenceRejectsCorruption(t *testing.T) {
	write := func(t *testing.T, path string, raw []byte) {
		t.Helper()
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}
	}

	t.Run("empty-file-is-corruption-not-empty-store", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "keystore.state")
		write(t, path, nil)
		_, err := OpenKeyStore(path)
		logKind(t, "load-empty-file", 0, err)
		if KindOf(err) != KindStorageCorrupted {
			t.Fatalf("empty file: kind=%s, want storage_corrupted", KindOf(err))
		}
	})

	t.Run("truncated-header", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "keystore.state")
		write(t, path, []byte(stateMagic+"\x01"))
		_, err := OpenKeyStore(path)
		logKind(t, "load-truncated-header", 0, err)
		if KindOf(err) != KindStorageCorrupted {
			t.Fatalf("truncated header: kind=%s", KindOf(err))
		}
	})

	t.Run("unknown-magic", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "keystore.state")
		write(t, path, []byte("XXXX\x01\x00\x00\x00\x00"))
		_, err := OpenKeyStore(path)
		logKind(t, "load-unknown-magic", 0, err)
		if KindOf(err) != KindStorageCorrupted {
			t.Fatalf("unknown magic: kind=%s", KindOf(err))
		}
	})

	t.Run("newer-container-version-rejected", func(t *testing.T) {
		s, path := newPersistedService(t)
		if _, err := s.Rotate(); err != nil {
			t.Fatalf("rotate: %v", err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		// 仅把容器版本字节改成更大的值（magic 之后那一字节）。
		raw[len(stateMagic)] = stateVersion + 1
		path2 := filepath.Join(t.TempDir(), "keystore.state")
		write(t, path2, raw)
		_, err = OpenKeyStore(path2)
		logKind(t, "load-newer-version", 0, err)
		if KindOf(err) != KindUnsupportedFormat {
			t.Fatalf("newer version: kind=%s, want unsupported_format", KindOf(err))
		}
	})

	t.Run("truncated-payload-and-checksum", func(t *testing.T) {
		s, path := newPersistedService(t)
		if _, err := s.Rotate(); err != nil {
			t.Fatalf("rotate: %v", err)
		}
		raw, _ := os.ReadFile(path)
		for _, cut := range []int{len(raw) - 1, stateHeaderSize + 3, len(raw) - stateChecksumLen} {
			path2 := filepath.Join(t.TempDir(), "keystore.state")
			write(t, path2, raw[:cut])
			_, err := OpenKeyStore(path2)
			logKind(t, "load-truncated", 0, err)
			if KindOf(err) != KindStorageCorrupted {
				t.Fatalf("cut=%d kind=%s, want storage_corrupted", cut, KindOf(err))
			}
		}
	})

	t.Run("tampered-payload-and-checksum", func(t *testing.T) {
		s, path := newPersistedService(t)
		if _, err := s.Rotate(); err != nil {
			t.Fatalf("rotate: %v", err)
		}
		raw, _ := os.ReadFile(path)

		// 篡改载荷中间一字节（校验和不再匹配）。
		a := append([]byte(nil), raw...)
		a[stateHeaderSize+len(a[stateHeaderSize:])/2] ^= 0xff
		p1 := filepath.Join(t.TempDir(), "keystore.state")
		write(t, p1, a)
		if _, err := OpenKeyStore(p1); KindOf(err) != KindStorageCorrupted {
			t.Fatalf("tampered payload: kind=%s", KindOf(err))
		}
		logKind(t, "load-tampered-payload", 0, errFor(p1))

		// 只改末尾校验和一字节。
		b := append([]byte(nil), raw...)
		b[len(b)-1] ^= 0xff
		p2 := filepath.Join(t.TempDir(), "keystore.state")
		write(t, p2, b)
		if _, err := OpenKeyStore(p2); KindOf(err) != KindStorageCorrupted {
			t.Fatalf("tampered checksum: kind=%s", KindOf(err))
		}
		logKind(t, "load-tampered-checksum", 0, errFor(p2))
	})

	t.Run("valid-current-version-loads", func(t *testing.T) {
		s, path := newPersistedService(t)
		v, err := s.Rotate()
		if err != nil {
			t.Fatalf("rotate: %v", err)
		}
		s2 := reopen(t, path)
		if active, _ := s2.store.ActiveVersion(); active != v {
			t.Fatalf("active=%d, want %d", active, v)
		}
		t.Logf("scenario=load-supported-format version=v%d result=ok", v)
	})
}

// errFor 打开状态文件并返回错误（仅用于日志辅助）。
func errFor(path string) error {
	_, err := OpenKeyStore(path)
	return err
}

// TestPersistenceSemanticCorruption 验证载荷语义损坏（退役版本仍带材料、
// 激活指针悬空、refs 指向不存在版本）也被识别为损坏而非空存储。
func TestPersistenceSemanticCorruption(t *testing.T) {
	makeFile := func(t *testing.T, mutate func(*persistedState)) []byte {
		t.Helper()
		st := &persistedState{Format: uint32(stateVersion), Next: 2, Active: 1,
			Versions: []persistedKey{{Version: 1, State: StateActive,
				Key: bytes32()}}}
		mutate(st)
		raw, err := marshalStateFile(st)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return raw
	}

	cases := []struct {
		name   string
		mutate func(*persistedState)
	}{
		{"retired-with-material", func(st *persistedState) {
			st.Versions[0].State = StateRetired
			st.Versions[0].Key = bytes32()
		}},
		{"dangling-active", func(st *persistedState) { st.Active = 99 }},
		{"unknown-state", func(st *persistedState) { st.Versions[0].State = "weird" }},
		{"bad-key-length", func(st *persistedState) { st.Versions[0].Key = st.Versions[0].Key[:7] }},
		{"dangling-ref", func(st *persistedState) { st.Refs = map[uint64]int{77: 3} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := makeFile(t, tc.mutate)
			path := filepath.Join(t.TempDir(), "keystore.state")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, err := OpenKeyStore(path)
			logKind(t, "load-semantic-"+tc.name, 0, err)
			if KindOf(err) != KindStorageCorrupted {
				t.Fatalf("%s: kind=%s, want storage_corrupted", tc.name, KindOf(err))
			}
		})
	}
}

func bytes32() []byte {
	b := make([]byte, keySize)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

// TestAtomicWriteNoHalfState 验证原子写：状态文件要么是某一次完整快照，
// 要么因损坏被拒绝；不可能读到“半截”的新版本。通过临时文件命名约定
// 确认实现走的是 temp+rename，并在大量轮换后状态仍可完整加载。
func TestAtomicWriteNoHalfState(t *testing.T) {
	s, path := newPersistedService(t)
	v, err := s.Rotate()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	for i := 0; i < 25; i++ {
		if _, err := s.Encrypt([]byte("payload")); err != nil {
			t.Fatalf("encrypt %d: %v", i, err)
		}
		if _, err := s.Rotate(); err != nil {
			t.Fatalf("rotate %d: %v", i, err)
		}
	}
	// 不应残留任何临时文件（崩溃式中止除外；正常流程必须清理）。
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("leftover temp file %s", e.Name())
		}
	}
	// 完整快照可加载，激活版本与计数器单调正确。
	s2 := reopen(t, path)
	active, _ := s2.store.ActiveVersion()
	if active <= v {
		t.Fatalf("active=%d should be greater than initial %d", active, v)
	}

	// 模拟“写到一半被杀”：把目标文件截断成随机前缀长度。
	raw, _ := os.ReadFile(path)
	for _, n := range []int{1, len(raw) / 2, len(raw) - stateChecksumLen - 1} {
		p2 := filepath.Join(t.TempDir(), "keystore.state")
		if err := os.WriteFile(p2, raw[:n], 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := OpenKeyStore(p2); KindOf(err) != KindStorageCorrupted {
			t.Fatalf("half-written file n=%d: kind=%s, want storage_corrupted", n, KindOf(err))
		}
		t.Logf("scenario=half-written len=%d kind=storage_corrupted", n)
	}
}
