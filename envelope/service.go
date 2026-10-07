package envelope

import "sync"

// Service 组合密钥存储与信封加密，提供对外统一入口。
//
// 引用计数（未迁移密文数）与迁移作业记录都保存在底层 LocalKeyStore 中：
// 纯内存模式下随进程存活，持久化模式下每次变更原子落盘，重启后原样恢复。
// 所有方法并发安全，轮换、停用、退役、迁移期间的读写行为一致。
type Service struct {
	store *LocalKeyStore

	// migrateMu 串行化迁移作业的“记账提交”，与存储写锁配合保证
	// 记账不重复、不丢失；迁移本身的加解密在锁外进行，不阻塞新写入。
	migrateMu sync.Mutex
}

// NewService 基于给定密钥存储创建服务。
func NewService(store *LocalKeyStore) *Service {
	return &Service{store: store}
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

		// 状态检查与引用记账在存储的同一写锁临界区内，
		// 与轮换/停用/退役/落盘严格互斥：内存结论与磁盘记账对得上。
		st, err := s.store.stateAndAddRef(version)
		if err != nil {
			return nil, err
		}
		if st == StateRetired {
			// 版本在加密期间被退役，重试。
			continue
		}
		return raw, nil
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

// Retire 退役指定版本；激活中、仍有未迁移数据或存在未完成迁移作业的
// 版本会被拒绝。检查与退役在存储同一写锁临界区内完成，
// 并发写入与迁移都无法绕过检查。
func (s *Service) Retire(version uint64) error {
	return s.store.retireChecked(version)
}

// Forget 通知服务某版本的一条密文已在迁移之外的途径删除，减少引用计数。
func (s *Service) Forget(version uint64) {
	_ = s.store.dropRef(version)
}

// Refs 返回指定版本当前持有的密文引用数。
func (s *Service) Refs(version uint64) int {
	return s.store.refsOf(version)
}
