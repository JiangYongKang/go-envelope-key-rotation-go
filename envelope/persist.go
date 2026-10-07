package envelope

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// 磁盘状态文件格式（v1）：
//
// 顶层是一个带校验和的信封（stateFile）：
//   - magic    : 固定标识 stateMagic，识别“这是不是本服务的状态文件”
//   - format   : 状态格式版本号；大于当前程序支持的版本一律拒绝加载
//   - body     : stateBody 的原始 JSON（RawMessage 原样写出），校验和针对这段字节计算
//   - sha256   : body 的 SHA-256（十六进制），用于识别截断/损坏
//
// 写入采用“同目录临时文件 + fsync + rename”原子替换，
// 崩溃后要么看到上一次完整状态，要么看到本次完整状态。
const (
	stateMagic     = "KEKSTORE"
	stateFormatV1  = uint32(1)
	stateFormatMax = stateFormatV1
)

// storedVersion 是单个主密钥版本在磁盘上的表示。
// 已退役版本不写材料（Material 为空），其余状态必须携带 32 字节材料。
type storedVersion struct {
	Version  uint64   `json:"version"`
	State    KeyState `json:"state"`
	Material []byte   `json:"material,omitempty"`
}

// stateBody 是校验和保护的实际状态负载。
type stateBody struct {
	Magic    string          `json:"magic"`
	Format   uint32          `json:"format"`
	Next     uint64          `json:"next"`
	Active   uint64          `json:"active"`
	Versions []storedVersion `json:"versions"`
}

// stateFile 是磁盘文件的外层信封。
type stateFile struct {
	Magic  string          `json:"magic"`
	Format uint32          `json:"format"`
	Body   json.RawMessage `json:"body"`
	SHA256 string          `json:"sha256"`
}

func corrupt(version uint64, msg string) *Error {
	return newError(KindStorageCorrupt, version, msg)
}

// marshalStateFile 把内存状态序列化为完整状态文件字节。
// body 先独立序列化（校验和覆盖它），再作为 RawMessage 嵌入外层信封，
// 避免“先 marshal 再 unmarshal”的双重转义。
func marshalStateFile(versions []storedVersion, active, next uint64) ([]byte, error) {
	body := stateBody{
		Magic:    stateMagic,
		Format:   stateFormatV1,
		Next:     next,
		Active:   active,
		Versions: versions,
	}
	rawBody, err := json.Marshal(&body)
	if err != nil {
		return nil, newError(KindInternal, 0, "encode state body failed")
	}
	file := stateFile{
		Magic:  stateMagic,
		Format: stateFormatV1,
		Body:   json.RawMessage(rawBody),
		SHA256: hex.EncodeToString(sha256Bytes(rawBody)),
	}
	// 注意：必须用普通 Marshal（不能 MarshalIndent），
	// 否则编码器会重新缩进内部的 RawMessage body，使落盘字节与校验和不一致。
	raw, err := json.Marshal(&file)
	if err != nil {
		return nil, newError(KindInternal, 0, "encode state file failed")
	}
	return raw, nil
}

func sha256Bytes(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

// loadStateFile 从 path 读取并严格校验状态文件。
//
// 文件不存在返回 (nil, nil)，表示全新存储，绝不能把损坏文件误判为“空存储”。
// 校验顺序（每类失败可区分）：
//  1. 读取/JSON 外层结构失败（含截断）      → KindStorageCorrupt
//  2. 外层 magic 不匹配                       → KindStorageCorrupt
//  3. format > 当前支持                       → KindUnsupportedFormat
//  4. body 为空 / sha256 缺失或不匹配（截断） → KindStorageCorrupt
//  5. body 自身不是合法 JSON                  → KindStorageCorrupt
//  6. body 语义校验（magic/版本/材料/激活）   → KindStorageCorrupt
func loadStateFile(path string) (*stateBody, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, newError(KindInternal, 0, "read state file failed")
	}

	var file stateFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, corrupt(0, "state file is not valid json (truncated or damaged)")
	}
	if file.Magic != stateMagic {
		return nil, corrupt(0, "state file magic mismatch")
	}
	if file.Format == 0 {
		return nil, corrupt(0, "state file missing format version")
	}
	if file.Format > stateFormatMax {
		return nil, newError(KindUnsupportedFormat, 0,
			fmt.Sprintf("state format version %d is newer than supported %d", file.Format, stateFormatMax))
	}
	if len(file.Body) == 0 {
		return nil, corrupt(0, "state file body is empty")
	}
	if file.SHA256 == "" {
		return nil, corrupt(0, "state file checksum is missing")
	}
	want, err := hex.DecodeString(file.SHA256)
	if err != nil {
		return nil, corrupt(0, "state file checksum is not valid hex")
	}
	if got := sha256Bytes(file.Body); !hexBytesEqual(got, want) {
		return nil, corrupt(0, "state file checksum mismatch (truncated or damaged)")
	}

	var body stateBody
	if err := json.Unmarshal(file.Body, &body); err != nil {
		return nil, corrupt(0, "state body is not valid json")
	}
	if err := validateBody(&body); err != nil {
		return nil, err
	}
	return &body, nil
}

// validateBody 对恢复出来的状态做语义校验，拒绝任何自相矛盾的内容，
// 防止损坏数据被当成“没有版本”或错误激活版本继续使用。
func validateBody(b *stateBody) error {
	if b.Magic != stateMagic {
		return corrupt(0, "state body magic mismatch")
	}
	if b.Format == 0 || b.Format > stateFormatMax {
		return corrupt(0, "state body format invalid")
	}
	if b.Next == 0 {
		return corrupt(0, "state body next counter is zero")
	}
	seen := make(map[uint64]bool, len(b.Versions))
	activeCount := 0
	for _, v := range b.Versions {
		if v.Version == 0 {
			return corrupt(0, "stored version number is zero")
		}
		if v.Version >= b.Next {
			return corrupt(v.Version, "stored version is ahead of next counter")
		}
		if seen[v.Version] {
			return corrupt(v.Version, "duplicate stored version")
		}
		seen[v.Version] = true
		switch v.State {
		case StateActive:
			activeCount++
			if len(v.Material) != keySize {
				return corrupt(v.Version, "active version missing key material")
			}
		case StateDeactivated, StateDisabled:
			if len(v.Material) != keySize {
				return corrupt(v.Version, "non-retired version missing key material")
			}
		case StateRetired:
			if len(v.Material) != 0 {
				return corrupt(v.Version, "retired version must not carry key material")
			}
		default:
			return corrupt(v.Version, "unknown key state in state file")
		}
	}
	if activeCount > 1 {
		return corrupt(0, "multiple active versions in state file")
	}
	if b.Active != 0 {
		kv, ok := lookupStored(b.Versions, b.Active)
		if !ok {
			return corrupt(b.Active, "active version is missing from versions")
		}
		if kv.State != StateActive {
			return corrupt(b.Active, "active pointer does not point at an active version")
		}
		if activeCount != 1 {
			return corrupt(b.Active, "active pointer without active record")
		}
	} else if activeCount != 0 {
		return corrupt(0, "active record exists but active pointer is zero")
	}
	return nil
}

func lookupStored(vs []storedVersion, version uint64) (storedVersion, bool) {
	for _, v := range vs {
		if v.Version == version {
			return v, true
		}
	}
	return storedVersion{}, false
}

func hexBytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// atomicWriteState 以“同目录临时文件 → fsync → rename”的方式原子替换状态文件。
// rename 在同文件系统内是原子的，因此崩溃只会留下旧文件或新文件，不会有半截目标文件。
func atomicWriteState(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir == "" {
		dir = "."
	}
	tmp, err := os.CreateTemp(dir, ".kekstate-*")
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
		return newError(KindInternal, 0, "rename temp state file failed")
	}
	// 尽力 fsync 目录，让 rename 自身落盘；失败不影响“文件内容原子可见”。
	if df, err := os.Open(dir); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}
	return nil
}
