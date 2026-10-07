package envelope

import "sync"

// Service 组合密钥存储与信封加密，提供对外统一入口。
// 所有方法并发安全，轮换、退役、落盘与在线迁移期间的读写行为一致。
type Service struct {
	store *LocalKeyStore

	// refs 记录每个密钥版本当前持有的密文数量（本进程内），
	// 用于阻止仍有未迁移数据的版本被退役。
	// mu 同时用于串行化“引用计数变更”与“退役检查”，
	// 保证退役决策、写入记账、迁移转移之间没有竞态。
	mu   sync.Mutex
	refs map[uint64]int

	// migrations 记录每个版本上尚未完成的迁移会话。
	// 存在进行中迁移的版本不得停用；迁移全部完成后引用清零，方可退役。
	migrations map[uint64]*Migration
}

// NewService 基于给定密钥存储创建服务（可为纯内存或已打开的持久化存储）。
func NewService(store *LocalKeyStore) *Service {
	return &Service{store: store, refs: make(map[uint64]int), migrations: make(map[uint64]*Migration)}
}

// OpenService 打开（或新建）一个带本地状态文件的持久化服务。
// 状态文件不存在时新建；损坏（KindStorageCorrupt）或格式更新
// （KindUnsupportedFormat）时明确返回错误，不会静默以空存储启动。
//
// 注意：密文引用计数是调用方数据层的事实，只存在于进程内存；
// 重启后需要调用方在加密前自行 Forget/重新建立记账，
// 迁移会话本身同样不跨进程持久化。
func OpenService(path string) (*Service, error) {
	store, err := OpenLocalKeyStore(path)
	if err != nil {
		return nil, err
	}
	return NewService(store), nil
}

// Encrypt 使用当前激活版本加密明文，返回序列化后的信封。
// 若加密完成后版本恰好被并发退役，则放弃本次结果并用新激活版本重试，
// 保证返回的密文必然可被解密，不产生静默失败。
func (s *Service) Encrypt(plaintext []byte) ([]byte, error) {
	for {
		version, kek, err := s.store.encryptKey()
		if err != nil {
			return nil, err
		}
		env, err := encrypt(version, kek, plaintext)
		if err != nil {
			return nil, err
		}
		raw, err := encode(env)
		if err != nil {
			return nil, err
		}

		s.mu.Lock()
		st, serr := s.store.State(version)
		if serr == nil && st != StateRetired {
			s.refs[version]++
			s.mu.Unlock()
			return raw, nil
		}
		s.mu.Unlock()
		// 版本在加密期间被退役，重试。
	}
}

// Decrypt 解密信封；失败时返回可区分类别的错误且不返回部分明文。
func (s *Service) Decrypt(raw []byte) ([]byte, error) {
	env, err := decode(raw)
	if err != nil {
		return nil, err
	}
	kek, err := s.store.decryptKey(env.Version)
	if err != nil {
		return nil, err
	}
	return decrypt(env.Version, kek, env)
}

// Rotate 生成并激活新的主密钥版本，旧版本自动转为已停用。
// 轮换在密钥存储的写锁内完成并原子落盘；轮换期间的新写入立即使用新版本，
// 历史数据仍可解密，迁移中的条目也会在重试时落到最新激活版本。
func (s *Service) Rotate() (uint64, error) {
	return s.store.Generate()
}

// Retire 退役指定版本；激活中或仍有未迁移数据的版本会被拒绝。
// 检查与退役在同一临界区内完成，并发写入与并发迁移都不会绕过检查。
func (s *Service) Retire(version uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refs[version] > 0 {
		return newError(KindVersionInUse, version, "version still holds unmigrated ciphertexts")
	}
	return s.store.Retire(version)
}

// Deactivate 停用指定版本。存在进行中迁移会话的版本不得停用，
// 以免迁移中途失去源密钥而把已迁/未迁数据混在一起。
func (s *Service) Deactivate(version uint64) error {
	s.mu.Lock()
	if m, ok := s.migrations[version]; ok && m != nil {
		s.mu.Unlock()
		return newError(KindMigrationState, version, "migration in progress; finish or close it first")
	}
	s.mu.Unlock()
	return s.store.Deactivate(version)
}

// Forget 通知服务某版本的密文已迁移或删除，减少引用计数。
func (s *Service) Forget(version uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decRef(version)
}

// decRef 在持有 s.mu 的前提下递减引用计数。
func (s *Service) decRef(version uint64) {
	if s.refs[version] > 0 {
		s.refs[version]--
	}
	if s.refs[version] == 0 {
		delete(s.refs, version)
	}
}

// Refs 返回指定版本当前持有的密文引用数。
func (s *Service) Refs(version uint64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refs[version]
}

// reencrypt 把一条信封解密后用当前激活版本重新加密，
// 并在同一临界区内完成“源引用 -1、目标引用 +1”，
// 使任一时刻 refs 的总和守恒，迁过的与没迁的不会混记。
func (s *Service) reencrypt(raw []byte) (MigratedRecord, error) {
	env, err := decode(raw)
	if err != nil {
		return MigratedRecord{}, err
	}
	source := env.Version

	kek, err := s.store.decryptKey(source)
	if err != nil {
		return MigratedRecord{}, err
	}
	plaintext, err := decrypt(source, kek, env)
	if err != nil {
		return MigratedRecord{}, err
	}

	target, tkek, err := s.store.encryptKey()
	if err != nil {
		return MigratedRecord{}, err
	}
	newEnv, err := encrypt(target, tkek, plaintext)
	if err != nil {
		return MigratedRecord{}, err
	}
	newRaw, err := encode(newEnv)
	if err != nil {
		return MigratedRecord{}, err
	}
	// 落账与退役检查共用一把锁：引用转移不可被半程观察到。
	s.mu.Lock()
	if _, serr := s.store.decryptKey(source); serr != nil {
		s.mu.Unlock()
		return MigratedRecord{}, serr
	}
	if st, serr := s.store.State(target); serr != nil || st == StateRetired {
		s.mu.Unlock()
		if serr != nil {
			return MigratedRecord{}, serr
		}
		return MigratedRecord{}, newError(KindKeyRetired, target, "target version retired during migration")
	}
	s.decRef(source)
	s.refs[target]++
	s.mu.Unlock()

	return MigratedRecord{
		Old:       raw,
		New:       newRaw,
		Source:    source,
		Target:    target,
		Plaintext: plaintext,
	}, nil
}
