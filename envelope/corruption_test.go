package envelope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeStateRaw 直接把字节写进状态文件路径，绕过正常原子写，用于注入损坏内容。
func writeStateRaw(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("inject state file: %v", err)
	}
}

// buildStateFileWith 构造一个指定外层 format 与 body 的状态信封，
// 可选择是否带正确校验和。
func buildStateFileWith(t *testing.T, format uint32, body stateBody, fixChecksum bool) []byte {
	t.Helper()
	body.Format = format
	body.Magic = stateMagic
	rawBody, err := json.Marshal(&body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	file := stateFile{
		Magic:  stateMagic,
		Format: format,
		Body:   json.RawMessage(rawBody),
	}
	if fixChecksum {
		sum := sha256.Sum256(rawBody)
		file.SHA256 = hex.EncodeToString(sum[:])
	}
	raw, err := json.Marshal(&file)
	if err != nil {
		t.Fatalf("marshal file: %v", err)
	}
	return raw
}

func validBody() stateBody {
	key := make([]byte, keySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return stateBody{
		Next:   2,
		Active: 1,
		Versions: []storedVersion{
			{Version: 1, State: StateActive, Material: key},
		},
	}
}

// TestRejectUnknownNewerFormat 验证比当前更新的格式被明确拒绝（unsupported_format），
// 即使校验和完全正确、内容本身可解析，也不能加载或当成空存储。
func TestRejectUnknownNewerFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kek.json")
	writeStateRaw(t, path, buildStateFileWith(t, 99, validBody(), true))

	s, err := OpenService(path)
	t.Logf("scenario=corrupt op=open-newer-format kind=%s", KindOf(err))
	if err == nil {
		_ = s
		t.Fatalf("expected rejection of newer format, got service")
	}
	if KindOf(err) != KindUnsupportedFormat {
		t.Fatalf("kind=%s, want unsupported_format", KindOf(err))
	}
	if _, statErr := os.Stat(path); statErr != nil {
		t.Fatalf("rejected state file must not be deleted: %v", statErr)
	}
}

// TestRejectCorruptAndTruncated 验证各类损坏给出 storage_corrupt，
// 且彼此可区分于“未知格式”，也不会被当成空存储。
func TestRejectCorruptAndTruncated(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{"not-json", []byte("{this is not json")},
		{"empty-file", []byte{}},
		{"random-bytes", []byte("Z\xc3\x28\x00\x01broken\xff")},
		{"bad-outer-magic", buildStateFileWith(t, 1, validBody(), true) /* 修正 magic */},
		{"checksum-mismatch", buildStateFileWith(t, 1, validBody(), false)},
		{"truncated-json", []byte(buildStateFileWith(t, 1, validBody(), true))[:40]},
	}
	// bad-outer-magic 单独改写 magic。
	badMagic := buildStateFileWith(t, 1, validBody(), true)
	var f stateFile
	_ = json.Unmarshal(badMagic, &f)
	f.Magic = "OTHER"
	cases[3].raw, _ = json.Marshal(&f)
	// checksum-mismatch：给一个错误但合法的十六进制串。
	cm := buildStateFileWith(t, 1, validBody(), false)
	var fc stateFile
	_ = json.Unmarshal(cm, &fc)
	fc.SHA256 = hex.EncodeToString(make([]byte, sha256.Size))
	cases[4].raw, _ = json.Marshal(&fc)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "kek.json")
			writeStateRaw(t, path, tc.raw)
			s, err := OpenService(path)
			t.Logf("scenario=corrupt case=%s kind=%s err=%v", tc.name, KindOf(err), err)
			if err == nil {
				_ = s
				t.Fatalf("expected storage_corrupt, got service (treated as empty?)")
			}
			if KindOf(err) != KindStorageCorrupt {
				t.Fatalf("case=%s kind=%s, want storage_corrupt", tc.name, KindOf(err))
			}
			if _, statErr := os.Stat(path); statErr != nil {
				t.Fatalf("corrupt file must remain on disk for forensics: %v", statErr)
			}
		})
	}
}

// TestRejectSemanticallyCorruptBody 验证内容能解析、校验和正确，
// 但语义自相矛盾（退役版本却带材料、激活指针缺失）时同样被拒绝。
func TestRejectSemanticallyCorruptBody(t *testing.T) {
	cases := map[string]stateBody{
		"retired-with-material": {
			Next: 2, Active: 0,
			Versions: []storedVersion{
				{Version: 1, State: StateRetired, Material: make([]byte, keySize)},
			},
		},
		"active-pointer-missing": {
			Next: 3, Active: 2,
			Versions: []storedVersion{
				{Version: 1, State: StateDeactivated, Material: make([]byte, keySize)},
			},
		},
		"non-retired-without-material": {
			Next: 2, Active: 1,
			Versions: []storedVersion{
				{Version: 1, State: StateActive, Material: nil},
			},
		},
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "kek.json")
			writeStateRaw(t, path, buildStateFileWith(t, 1, body, true))
			_, err := OpenService(path)
			t.Logf("scenario=corrupt-semantic case=%s kind=%s", name, KindOf(err))
			if KindOf(err) != KindStorageCorrupt {
				t.Fatalf("kind=%s, want storage_corrupt", KindOf(err))
			}
		})
	}
}

// TestLoadKnownOlderFormat 验证当前可识别的格式版本能正常加载（前向兼容承诺）。
func TestLoadKnownOlderFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kek.json")
	writeStateRaw(t, path, buildStateFileWith(t, stateFormatV1, validBody(), true))
	s, err := OpenService(path)
	if err != nil {
		t.Fatalf("load format v1: kind=%s err=%v", KindOf(err), err)
	}
	if active, _ := s.store.ActiveVersion(); active != 1 {
		t.Fatalf("active=%d, want 1", active)
	}
	t.Logf("scenario=compat op=load-format version=%d result=ok", stateFormatV1)
}

// TestOpenMissingFileStartsFresh 验证文件不存在时按全新存储启动，
// 且首次轮换后能正常落盘并再次打开。
func TestOpenMissingFileStartsFresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.json")
	s, err := OpenService(path)
	if err != nil {
		t.Fatalf("open missing: %v", err)
	}
	v, err := s.Rotate()
	if err != nil || v != 1 {
		t.Fatalf("first rotate: v=%d err=%v", v, err)
	}
	s2, err := OpenService(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if active, _ := s2.store.ActiveVersion(); active != 1 {
		t.Fatalf("active=%d, want 1", active)
	}
}

// TestPersistWriteFailureRollsBackMemory 验证落盘失败时内存结论回滚，
// 内存与磁盘保持同一个旧状态（不会出现“内存已轮换、磁盘没轮换”的分叉）。
func TestPersistWriteFailureRollsBackMemory(t *testing.T) {
	// 指向一个不存在的目录，临时文件无法创建，落盘必然失败。
	path := filepath.Join(t.TempDir(), "no-such-dir", "kek.json")
	s, err := OpenService(path)
	if err != nil {
		t.Fatalf("open (file absent): %v", err)
	}
	_, err = s.Rotate()
	t.Logf("scenario=persist-rollback op=rotate kind=%s", KindOf(err))
	if KindOf(err) != KindInternal {
		t.Fatalf("rotate against unwritable path: kind=%s, want internal", KindOf(err))
	}
	if _, err := s.store.ActiveVersion(); KindOf(err) != KindKeyNotFound {
		t.Fatalf("memory not rolled back: active lookup kind=%s", KindOf(err))
	}
	if s.store.next != 1 {
		t.Fatalf("next counter=%d, want rolled back to 1", s.store.next)
	}
}
