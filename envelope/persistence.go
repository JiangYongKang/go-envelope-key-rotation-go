package envelope

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// 本地状态文件采用带外封装的二进制容器，容器头携带自身格式版本，
// 载荷为 JSON，末尾附 SHA-256 校验和：
//
//	magic   : 固定 "EKSF"（Envelope Key Store File），4 字节
//	version : 容器格式版本，1 字节
//	length  : 载荷长度，4 字节大端
//	payload : length 字节的 JSON 载荷（persistedState）
//	checksum: SHA-256(magic || version || length || payload)，32 字节
//
// 容器版本与载荷内的 Format 字段相互印证：容器版本决定如何切分字节，
// 载荷 Format 决定如何解释 JSON。遇到更新版本直接拒绝，不做猜测性解析。
const (
	stateMagic       = "EKSF"
	stateVersion     = uint8(1)
	stateHeaderSize  = 4 + 1 + 4
	stateChecksumLen = 32
)

// persistedKey 是一个主密钥版本在磁盘上的表示。
// 退役版本的 Key 为 nil（材料已销毁）。
type persistedKey struct {
	Version uint64   `json:"version"`
	State   KeyState `json:"state"`
	Key     []byte   `json:"key,omitempty"`
}

// persistedMigrationItem 是迁移作业中一个条目的持久化记账。
// Fingerprint 为原始信封原始字节的 SHA-256，用于重试时确认
// “同一个 ID 指向同一份数据”，避免把迁过与没迁的混在一起。
// Landed 记录该条目实际落到的主密钥版本；Done 为是否已迁完。
type persistedMigrationItem struct {
	ID          string `json:"id"`
	Fingerprint []byte `json:"fingerprint"`
	Landed      uint64 `json:"landed,omitempty"`
	Done        bool   `json:"done"`
}

// persistedMigration 是以某个源版本为单位的迁移作业。
type persistedMigration struct {
	Source uint64                   `json:"source"`
	Target uint64                   `json:"target"`
	Items  []persistedMigrationItem `json:"items"`
}

// persistedState 是落盘的完整状态快照。
type persistedState struct {
	Format     uint32                         `json:"format"`
	Versions   []persistedKey                 `json:"versions"`
	Active     uint64                         `json:"active"`
	Next       uint64                         `json:"next"`
	Refs       map[uint64]int                 `json:"refs,omitempty"`
	Migrations map[uint64]*persistedMigration `json:"migrations,omitempty"`
}

// marshalStateFile 将状态快照编码为带校验和的完整文件内容。
func marshalStateFile(st *persistedState) ([]byte, error) {
	if st == nil {
		return nil, newError(KindInternal, 0, "nil state snapshot")
	}
	st.Format = uint32(stateVersion)
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, newError(KindInternal, 0, "encode state payload failed")
	}

	buf := make([]byte, 0, stateHeaderSize+len(payload)+stateChecksumLen)
	buf = append(buf, stateMagic...)
	buf = append(buf, stateVersion)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(payload)))
	buf = append(buf, payload...)
	sum := sha256.Sum256(buf)
	buf = append(buf, sum[:]...)
	return buf, nil
}

// unmarshalStateFile 解析状态文件，依次校验魔数、容器版本、长度、
// 校验和与载荷语义；未知新版本返回 KindUnsupportedFormat，
// 截断/损坏返回 KindStorageCorrupted。
func unmarshalStateFile(raw []byte) (*persistedState, error) {
	// 文件存在但为空：与“文件不存在”明确区分，不当作空存储。
	if len(raw) == 0 {
		return nil, newError(KindStorageCorrupted, 0, "state file is empty")
	}
	if len(raw) < stateHeaderSize {
		return nil, newError(KindStorageCorrupted, 0, "state file truncated in header")
	}
	if string(raw[:len(stateMagic)]) != stateMagic {
		return nil, newError(KindStorageCorrupted, 0, "state file has unknown magic")
	}
	version := raw[len(stateMagic)]
	if version != stateVersion {
		// 比当前更新的未知格式必须明确拒绝并说清原因，绝不猜测解析。
		return nil, newError(KindUnsupportedFormat, 0,
			fmt.Sprintf("state file format version %d is newer than supported version %d", version, stateVersion))
	}
	payloadLen := int(binary.BigEndian.Uint32(raw[len(stateMagic)+1 : stateHeaderSize]))
	end := stateHeaderSize + payloadLen
	if end+stateChecksumLen != len(raw) {
		return nil, newError(KindStorageCorrupted, 0,
			fmt.Sprintf("state file length mismatch: header declares %d payload bytes, file has %d bytes",
				payloadLen, len(raw)-stateHeaderSize-stateChecksumLen))
	}
	payload := raw[stateHeaderSize:end]
	wantSum := sha256.Sum256(raw[:end])
	if !equalBytes(wantSum[:], raw[end:]) {
		return nil, newError(KindStorageCorrupted, 0, "state file checksum mismatch")
	}

	var st persistedState
	if err := json.Unmarshal(payload, &st); err != nil {
		return nil, newError(KindStorageCorrupted, 0, "state payload is not valid json")
	}
	if st.Format != uint32(stateVersion) {
		return nil, newError(KindUnsupportedFormat, 0,
			fmt.Sprintf("state payload format %d is not supported (want %d)", st.Format, stateVersion))
	}
	if err := validateState(&st); err != nil {
		return nil, err
	}
	return &st, nil
}

// validateState 校验载荷语义自洽：版本号唯一、状态合法、材料长度正确、
// 激活版本指向合法条目。损坏一律报 KindStorageCorrupted。
func validateState(st *persistedState) error {
	corrupt := func(format string, args ...any) error {
		return newError(KindStorageCorrupted, 0, "state payload invalid: "+fmt.Sprintf(format, args...))
	}
	seen := make(map[uint64]bool, len(st.Versions))
	for i := range st.Versions {
		kv := &st.Versions[i]
		if kv.Version == 0 {
			return corrupt("zero version id")
		}
		if seen[kv.Version] {
			return corrupt("duplicate version %d", kv.Version)
		}
		seen[kv.Version] = true
		switch kv.State {
		case StateActive, StateDeactivated, StateDisabled, StateRetired:
		default:
			return corrupt("unknown state %q for version %d", kv.State, kv.Version)
		}
		if kv.State == StateRetired {
			if len(kv.Key) != 0 {
				return corrupt("retired version %d still carries key material", kv.Version)
			}
		} else if len(kv.Key) != keySize {
			return corrupt("version %d key length = %d, want %d", kv.Version, len(kv.Key), keySize)
		}
	}
	if st.Active != 0 {
		kv, ok := findPersistedKey(st.Versions, st.Active)
		if !ok {
			return corrupt("active version %d missing from versions", st.Active)
		}
		if kv.State != StateActive {
			return corrupt("active pointer %d is in state %s", st.Active, kv.State)
		}
	} else if len(st.Versions) != 0 {
		return corrupt("versions exist but no active version is set")
	}
	if st.Next == 0 && len(st.Versions) != 0 {
		return corrupt("next version counter is zero while versions exist")
	}
	for v, n := range st.Refs {
		if !seen[v] || n <= 0 {
			return corrupt("refs entry for %d is inconsistent (exists=%v count=%d)", v, seen[v], n)
		}
	}
	for src, m := range st.Migrations {
		if m == nil || m.Source != src {
			return corrupt("migration map key %d inconsistent with job", src)
		}
		if !seen[m.Source] || !seen[m.Target] || m.Source == m.Target {
			return corrupt("migration %d->%d references invalid versions", m.Source, m.Target)
		}
		ids := make(map[string]bool, len(m.Items))
		for _, it := range m.Items {
			if it.ID == "" || len(it.Fingerprint) != sha256.Size {
				return corrupt("migration item %q of source %d invalid", it.ID, src)
			}
			if ids[it.ID] {
				return corrupt("duplicate migration item id %q for source %d", it.ID, src)
			}
			ids[it.ID] = true
			if it.Done && !seen[it.Landed] {
				return corrupt("migrated item %q landed on missing version %d", it.ID, it.Landed)
			}
		}
	}
	return nil
}

func findPersistedKey(versions []persistedKey, v uint64) (persistedKey, bool) {
	for _, kv := range versions {
		if kv.Version == v {
			return kv, true
		}
	}
	return persistedKey{}, false
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// atomicWriteState 将数据原子写入 path：先写同目录临时文件并 fsync，
// 再 rename 替换，最后 fsync 目录；崩溃后目标文件只可能是上一次或
// 本次的完整内容，不会出现半截文件。
func atomicWriteState(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".keystore-*.tmp")
	if err != nil {
		return newError(KindInternal, 0, "create temp state file failed")
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return newError(KindInternal, 0, "write temp state file failed")
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return newError(KindInternal, 0, "fsync temp state file failed")
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return newError(KindInternal, 0, "close temp state file failed")
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return newError(KindInternal, 0, "replace state file failed")
	}
	// fsync 目录，保证 rename 在崩溃后仍然落盘。
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// saveStateFile 编码并原子写入状态快照。
func saveStateFile(path string, st *persistedState) error {
	data, err := marshalStateFile(st)
	if err != nil {
		return err
	}
	return atomicWriteState(path, data)
}

// loadStateFile 读取并解析状态文件；文件不存在视为全新空存储（nil, nil），
// 文件存在但为空/截断/损坏则返回可区分错误。
func loadStateFile(path string) (*persistedState, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, newError(KindInternal, 0, "read state file failed")
	}
	return unmarshalStateFile(raw)
}
