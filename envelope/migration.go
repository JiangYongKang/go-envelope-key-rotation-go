package envelope

import (
	"crypto/sha256"
	"strconv"
)

// cloneMigration 深拷贝一个迁移作业，避免外部/磁盘快照间共享切片。
func cloneMigration(m *persistedMigration) *persistedMigration {
	if m == nil {
		return nil
	}
	cp := &persistedMigration{Source: m.Source, Target: m.Target,
		Items: make([]persistedMigrationItem, len(m.Items))}
	for i, it := range m.Items {
		cp.Items[i] = persistedMigrationItem{
			ID:          it.ID,
			Fingerprint: append([]byte(nil), it.Fingerprint...),
			Landed:      it.Landed,
			Done:        it.Done,
		}
	}
	return cp
}

// migrationDone 报告作业的全部条目是否都已迁完。
func migrationDone(m *persistedMigration) bool {
	if m == nil || len(m.Items) == 0 {
		return false
	}
	for _, it := range m.Items {
		if !it.Done {
			return false
		}
	}
	return true
}

// MigrationProgress 是某个源版本迁移作业的可查询进度。
type MigrationProgress struct {
	Source   uint64 // 被迁移的旧版本
	Target   uint64 // 作业开始时的激活版本
	Total    int    // 条目总数
	Done     int    // 已迁完条目数
	Pending  int    // 尚未迁完条目数
	Finished bool   // 是否全部迁完（Finished 后该版本才允许退役）
}

// MigrationItem 是待迁移的一批信封中的一个条目。
// ID 必须在同一源版本的迁移作业内稳定且唯一（通常取数据记录主键），
// Raw 是该记录当前存储的序列化信封字节。
type MigrationItem struct {
	ID  string
	Raw []byte
}

// MigrationResult 是单个条目迁移的结果。
type MigrationResult struct {
	ID     string
	Source uint64 // 迁移前信封所在版本
	Target uint64 // 本次实际落到的激活版本
	Output []byte // 重新封装后的信封字节（明文与原信封一致）
}

// BeginMigration 登记一个针对 source 版本的迁移作业。
//
// items 是该版本下“要迁移的那一批信封”，ID 必须稳定唯一（取记录主键），
// Raw 为当前信封字节。作业一旦登记即持久化：进程崩溃/重启后可用完全相同
// 的条目集合重新调用本方法恢复（幂等），条目集合不一致会得到
// KindMigrationConflict，避免重复计数或把迁过/没迁的混在一起。
func (s *Service) BeginMigration(source uint64, items []MigrationItem) (*MigrationProgress, error) {
	if len(items) == 0 {
		return nil, newError(KindMigrationConflict, source, "migration requires at least one item")
	}
	registered := make([]persistedMigrationItem, len(items))
	seen := make(map[string]bool, len(items))
	for i, it := range items {
		if it.ID == "" {
			return nil, newError(KindMigrationConflict, source, "migration item id is empty")
		}
		if seen[it.ID] {
			return nil, newError(KindMigrationConflict, source, "duplicate migration item id "+it.ID)
		}
		seen[it.ID] = true
		// 先确认 Raw 确实是 source 版本的合法信封，登记阶段就挡住错配数据。
		env, err := decode(it.Raw)
		if err != nil {
			return nil, err
		}
		if env.Version != source {
			return nil, newError(KindMigrationConflict, source,
				"item "+it.ID+" is envelope version "+strconv.FormatUint(env.Version, 10)+
					", not "+strconv.FormatUint(source, 10))
		}
		fp := sha256.Sum256(it.Raw)
		registered[i] = persistedMigrationItem{ID: it.ID, Fingerprint: fp[:]}
	}
	job, err := s.store.beginMigration(source, registered)
	if err != nil {
		return nil, err
	}
	return progressOf(job), nil
}

// MigrationProgressOf 查询某源版本的迁移进度；作业不存在返回
// KindMigrationNotFound。只有 Finished 为 true 后该版本才允许退役。
func (s *Service) MigrationProgressOf(source uint64) (*MigrationProgress, error) {
	job, err := s.store.migrationJob(source)
	if err != nil {
		return nil, err
	}
	return progressOf(job), nil
}

// MigrateOne 迁移单个条目：用源版本解密旧信封，再以当前激活版本重新封装。
//
// 迁移期间新写入照常走当前激活版本、不会被卡住：密钥材料在锁内取出后，
// 加解密在锁外完成。提交记账是幂等的——同一 ID 失败重试时，若它此前已
// 确认迁完，则按已登记的落地版本重新封装且不重复调整引用计数。
func (s *Service) MigrateOne(source uint64, item MigrationItem) (*MigrationResult, error) {
	if item.ID == "" {
		return nil, newError(KindMigrationConflict, source, "migration item id is empty")
	}
	// 记账提交串行化，与轮换/退役的存储写锁互斥。
	s.migrateMu.Lock()
	defer s.migrateMu.Unlock()

	fp := sha256.Sum256(item.Raw)

	for {
		job, err := s.store.migrationJob(source)
		if err != nil {
			return nil, err
		}
		if done := findJobItem(job, item.ID); done != nil && done.Done {
			// 重试已完成条目：按原落地版本重新封装，记账不变、不重复计数。
			out, err := s.rewrap(source, item.Raw, done.Landed)
			if err != nil {
				return nil, err
			}
			return &MigrationResult{ID: item.ID, Source: source,
				Target: done.Landed, Output: out}, nil
		}

		// 锁内取材料并校验作业条目，锁外做加解密。
		srcKey, target, targetKey, err := s.store.prepareMigrationCrypto(source, item.ID, fp[:])
		if err != nil {
			return nil, err
		}
		env, err := decode(item.Raw)
		if err != nil {
			return nil, err
		}
		if env.Version != source {
			return nil, newError(KindMigrationConflict, source,
				"item "+item.ID+" does not belong to source version")
		}
		pt, err := decrypt(source, srcKey, env)
		if err != nil {
			return nil, err
		}
		newEnv, err := encrypt(target, targetKey, pt)
		if err != nil {
			return nil, err
		}
		out, err := encode(newEnv)
		if err != nil {
			return nil, err
		}

		// 锁内原子转移引用并标记完成；若落地版本在加解密期间被退役，
		// 提交返回可重试错误，用新的激活版本重来。
		committed, err := s.store.commitMigrationItem(source, item.ID, fp[:], target)
		if err != nil {
			if KindOf(err) == KindVersionInUse {
				continue
			}
			return nil, err
		}
		_ = committed
		return &MigrationResult{ID: item.ID, Source: source, Target: target, Output: out}, nil
	}
}

// rewrap 用 source 版本解密旧信封，再以指定版本（重试时为原落地版本）
// 重新封装；不改变任何记账。
func (s *Service) rewrap(source uint64, raw []byte, target uint64) ([]byte, error) {
	env, err := decode(raw)
	if err != nil {
		return nil, err
	}
	srcKey, err := s.store.decryptKey(source)
	if err != nil {
		return nil, err
	}
	pt, err := decrypt(source, srcKey, env)
	if err != nil {
		return nil, err
	}
	tgtKey, err := s.store.decryptKey(target)
	if err != nil {
		return nil, err
	}
	newEnv, err := encrypt(target, tgtKey, pt)
	if err != nil {
		return nil, err
	}
	return encode(newEnv)
}

func findJobItem(job *persistedMigration, id string) *persistedMigrationItem {
	for i := range job.Items {
		if job.Items[i].ID == id {
			return &job.Items[i]
		}
	}
	return nil
}

func progressOf(job *persistedMigration) *MigrationProgress {
	p := &MigrationProgress{
		Source: job.Source,
		Target: job.Target,
		Total:  len(job.Items),
	}
	for _, it := range job.Items {
		if it.Done {
			p.Done++
		}
	}
	p.Pending = p.Total - p.Done
	p.Finished = p.Pending == 0
	return p
}
