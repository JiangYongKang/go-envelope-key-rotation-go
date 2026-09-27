package envelope

import "sync"

// Service 组合密钥存储与信封加密，提供对外统一入口。
// 所有方法并发安全，轮换与退役期间的读写行为一致。
type Service struct {
	store *LocalKeyStore

	// refs 记录每个密钥版本当前持有的密文数量（本进程内），
	// 用于阻止仍有未迁移数据的版本被退役。
	// mu 同时用于串行化“引用计数变更”与“退役检查”，
	// 保证退役决策与写入记账之间没有竞态。
	mu   sync.Mutex
	refs map[uint64]int
}

// NewService 基于给定密钥存储创建服务。
func NewService(store *LocalKeyStore) *Service {
	return &Service{store: store, refs: make(map[uint64]int)}
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
// 轮换期间的新写入立即使用新版本，历史数据仍可解密。
func (s *Service) Rotate() (uint64, error) {
	return s.store.Generate()
}

// Retire 退役指定版本；激活中或仍有未迁移数据的版本会被拒绝。
// 检查与退役在同一临界区内完成，并发写入不会绕过检查。
func (s *Service) Retire(version uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refs[version] > 0 {
		return newError(KindVersionInUse, version, "version still holds unmigrated ciphertexts")
	}
	return s.store.Retire(version)
}

// Forget 通知服务某版本的密文已迁移或删除，减少引用计数。
func (s *Service) Forget(version uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
