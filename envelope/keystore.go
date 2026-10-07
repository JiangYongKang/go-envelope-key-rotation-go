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

// LocalKeyStore 以本地内存存储模拟受管密钥服务（KMS），
// 并可选地把全部密钥版本状态持久化到本地状态文件。
// 所有方法并发安全。
type LocalKeyStore struct {
	mu       sync.RWMutex
	versions map[uint64]*KeyVersion
	active   uint64
	next     uint64
	// path 非空时为持久化模式：每次状态变更都在同一把写锁内原子落盘，
	// 落盘失败则回滚内存，保证内存结论与磁盘结论一致；
	// 为空时为纯内存模式（与最初版本行为一致）。
	path string
}

// memSnapshot 是一次状态变更前的完整内存快照，用于落盘失败时整体回滚。
// 密钥材料做深拷贝，避免与线上 map 共享底层数组。
type memSnapshot struct {
	versions map[uint64]keySnap
	active   uint64
	next     uint64
}

type keySnap struct {
	state KeyState
	key   []byte
}

// NewLocalKeyStore 创建一个空的纯内存密钥存储（不落盘）。
func NewLocalKeyStore() *LocalKeyStore {
	return &LocalKeyStore{versions: make(map[uint64]*KeyVersion), next: 1}
}

// OpenLocalKeyStore 打开（或新建）一个带本地状态文件的持久化密钥存储。
//
// 文件不存在时视为全新存储；文件存在但被截断/损坏返回 KindStorageCorrupt，
// 格式版本比当前程序更新返回 KindUnsupportedFormat，这两类情况都不会被
// 静默当成空存储继续运行。
func OpenLocalKeyStore(path string) (*LocalKeyStore, error) {
	s := &LocalKeyStore{versions: make(map[uint64]*KeyVersion), next: 1, path: path}
	body, err := loadStateFile(path)
	if err != nil {
		return nil, err
	}
	if body != nil {
		s.applyBody(body)
	}
	return s, nil
}

// applyBody 用已通过校验的状态负载重建内存索引。
func (s *LocalKeyStore) applyBody(b *stateBody) {
	s.versions = make(map[uint64]*KeyVersion, len(b.Versions))
	for _, v := range b.Versions {
		s.versions[v.Version] = &KeyVersion{
			Version: v.Version,
			State:   v.State,
			key:     append([]byte(nil), v.Material...),
		}
	}
	s.active = b.Active
	s.next = b.Next
}

// snapshot 深拷贝当前内存状态（含密钥字节）。
func (s *LocalKeyStore) snapshot() memSnapshot {
	sn := memSnapshot{
		versions: make(map[uint64]keySnap, len(s.versions)),
		active:   s.active,
		next:     s.next,
	}
	for v, kv := range s.versions {
		sn.versions[v] = keySnap{state: kv.State, key: append([]byte(nil), kv.key...)}
	}
	return sn
}

// restore 用快照整体替换内存状态，仅在落盘失败的回滚路径中调用。
func (s *LocalKeyStore) restore(sn memSnapshot) {
	s.versions = make(map[uint64]*KeyVersion, len(sn.versions))
	for v, ks := range sn.versions {
		s.versions[v] = &KeyVersion{Version: v, State: ks.state, key: append([]byte(nil), ks.key...)}
	}
	s.active = sn.active
	s.next = sn.next
}

// snapshotStored 按版本号顺序生成磁盘表示；已退役版本不带材料。
func (s *LocalKeyStore) snapshotStored() []storedVersion {
	out := make([]storedVersion, 0, len(s.versions))
	for v := uint64(1); v < s.next; v++ {
		kv, ok := s.versions[v]
		if !ok {
			continue
		}
		st := storedVersion{Version: v, State: kv.State}
		if kv.State != StateRetired {
			st.Material = append([]byte(nil), kv.key...)
		}
		out = append(out, st)
	}
	return out
}

// commit 在写锁内应用变更并原子落盘；落盘失败则回滚到变更前快照。
// 因此“内存里的结论”和“已经落盘的结论”要么同时是新状态，要么同时是旧状态。
func (s *LocalKeyStore) commit(mutate func()) error {
	before := s.snapshot()
	mutate()
	raw, err := marshalStateFile(s.snapshotStored(), s.active, s.next)
	if err != nil {
		s.restore(before)
		return err
	}
	if s.path != "" {
		if err := atomicWriteState(s.path, raw); err != nil {
			s.restore(before)
			return err
		}
	}
	return nil
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
	old, oldOK := s.versions[s.active]
	v := s.next
	if err := s.commit(func() {
		if oldOK && old.State == StateActive {
			old.State = StateDeactivated
		}
		s.next = v + 1
		s.versions[v] = &KeyVersion{Version: v, State: StateActive, key: key}
		s.active = v
	}); err != nil {
		return 0, err
	}
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
	return s.commit(func() {
		kv.State = StateDisabled
	})
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
	return s.commit(func() {
		// 销毁密钥材料，之后任何解密请求都会得到 KindKeyRetired。
		for i := range kv.key {
			kv.key[i] = 0
		}
		kv.key = nil
		kv.State = StateRetired
	})
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
