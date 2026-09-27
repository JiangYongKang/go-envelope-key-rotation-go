package envelope

import (
	"crypto/rand"
	"sync"
)

// keySize 主密钥与数据密钥均为 AES-256（32 字节）。
const keySize = 32

// KeyState 表示主密钥版本的生命周期状态。
type KeyState string

const (
	// StateActive 当前激活版本，可用于加密与解密。
	StateActive KeyState = "active"
	// StateDeactivated 轮换后自动转入的状态：不可加密新数据，但仍可解密历史数据。
	StateDeactivated KeyState = "deactivated"
	// StateDisabled 手动停用的版本：加解密均被拒绝（key_disabled），
	// 用于在迁移完成后、退役前显式关闭一个版本的读取能力。
	StateDisabled KeyState = "disabled"
	// StateRetired 已退役版本，密钥材料已销毁，不可加解密。
	StateRetired KeyState = "retired"
)

// KeyVersion 保存一个主密钥版本的材料与状态。
type KeyVersion struct {
	Version uint64
	State   KeyState
	key     []byte // AES-256 主密钥材料，退役时清零
}

// LocalKeyStore 以本地内存存储模拟受管密钥服务（KMS）。
// 所有方法并发安全。
type LocalKeyStore struct {
	mu       sync.RWMutex
	versions map[uint64]*KeyVersion
	active   uint64
	next     uint64
}

// NewLocalKeyStore 创建一个空的本地密钥存储。
func NewLocalKeyStore() *LocalKeyStore {
	return &LocalKeyStore{versions: make(map[uint64]*KeyVersion), next: 1}
}

// Generate 生成一个新的主密钥版本并置为激活版本，返回版本号。
// 旧的激活版本自动转为已停用，保证任意时刻至多一个激活版本。
func (s *LocalKeyStore) Generate() (uint64, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return 0, newError(KindInternal, 0, "generate key material failed")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.versions[s.active]; ok && old.State == StateActive {
		old.State = StateDeactivated
	}
	v := s.next
	s.next++
	s.versions[v] = &KeyVersion{Version: v, State: StateActive, key: key}
	s.active = v
	return v, nil
}

// ActiveVersion 返回当前激活版本号；不存在时返回 KindKeyNotFound 错误。
func (s *LocalKeyStore) ActiveVersion() (uint64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active == 0 {
		return 0, newError(KindKeyNotFound, 0, "no active key version")
	}
	return s.active, nil
}

// Deactivate 手动停用指定版本，使其加解密均被拒绝（key_disabled）。
// 激活版本不得直接停用（须先轮换）；轮换产生的 deactivated 版本
// 在确认无需再读取历史数据后可经此转为 disabled。
func (s *LocalKeyStore) Deactivate(version uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kv, ok := s.versions[version]
	if !ok {
		return newError(KindKeyNotFound, version, "key version does not exist")
	}
	switch kv.State {
	case StateActive:
		return newError(KindVersionInUse, version, "active version cannot be deactivated; rotate first")
	case StateRetired:
		return newError(KindKeyRetired, version, "key version already retired")
	case StateDisabled:
		return newError(KindKeyDisabled, version, "key version already disabled")
	}
	kv.State = StateDisabled
	return nil
}

// Retire 退役指定版本并销毁密钥材料；
// 仍处于激活状态的版本不得退役（由 Service 额外校验未迁移数据）。
func (s *LocalKeyStore) Retire(version uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kv, ok := s.versions[version]
	if !ok {
		return newError(KindKeyNotFound, version, "key version does not exist")
	}
	switch kv.State {
	case StateActive:
		return newError(KindVersionInUse, version, "active version cannot be retired")
	case StateRetired:
		return newError(KindKeyRetired, version, "key version already retired")
	}
	// 销毁密钥材料，之后任何解密请求都会得到 KindKeyRetired。
	for i := range kv.key {
		kv.key[i] = 0
	}
	kv.key = nil
	kv.State = StateRetired
	return nil
}

// State 返回指定版本的状态。
func (s *LocalKeyStore) State(version uint64) (KeyState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	kv, ok := s.versions[version]
	if !ok {
		return "", newError(KindKeyNotFound, version, "key version does not exist")
	}
	return kv.State, nil
}

// encryptKey 返回当前激活版本的密钥材料副本。
func (s *LocalKeyStore) encryptKey() (uint64, []byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	kv, ok := s.versions[s.active]
	if s.active == 0 || !ok || kv.State != StateActive {
		return 0, nil, newError(KindKeyNotFound, 0, "no active key version")
	}
	return kv.Version, append([]byte(nil), kv.key...), nil
}

// decryptKey 返回可用于解密的指定版本密钥材料（激活或已停用）。
// 已退役或不存在分别返回 KindKeyRetired / KindKeyNotFound。
func (s *LocalKeyStore) decryptKey(version uint64) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	kv, ok := s.versions[version]
	if !ok {
		return nil, newError(KindKeyNotFound, version, "key version does not exist")
	}
	switch kv.State {
	case StateRetired:
		return nil, newError(KindKeyRetired, version, "key version retired, material destroyed")
	case StateDisabled:
		return nil, newError(KindKeyDisabled, version, "key version disabled")
	}
	return append([]byte(nil), kv.key...), nil
}
