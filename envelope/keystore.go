package envelope

import (
	"crypto/rand"
	"crypto/sha256"
	"sort"
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

// LocalKeyStore 以本地存储模拟受管密钥服务（KMS）。
//
// 当通过 NewLocalKeyStore 创建（无路径）时为纯内存模式；
// 当通过 OpenKeyStore 绑定状态文件时，每次状态变更都在持锁临界区内
// 原子落盘，内存结论与磁盘内容严格一致，进程重启后可原样恢复。
// 所有方法并发安全。
type LocalKeyStore struct {
	mu sync.RWMutex

	// path 为空表示纯内存模式，变更不落盘。
	path string

	versions   map[uint64]*KeyVersion
	active     uint64
	next       uint64
	refs       map[uint64]int
	migrations map[uint64]*persistedMigration
}

// NewLocalKeyStore 创建一个空的纯内存本地密钥存储（不落盘）。
func NewLocalKeyStore() *LocalKeyStore {
	return newKeyStore("")
}

// OpenKeyStore 打开（或首次创建）绑定到 path 的持久化密钥存储。
// 文件不存在时创建空存储；文件存在但为空、被截断、校验和不符或使用
// 比当前更新的格式时，返回 KindStorageCorrupted / KindUnsupportedFormat，
// 绝不会把损坏文件默默当成空存储。
func OpenKeyStore(path string) (*LocalKeyStore, error) {
	st, err := loadStateFile(path)
	if err != nil {
		return nil, err
	}
	s := newKeyStore(path)
	if st != nil {
		s.restore(st)
	}
	return s, nil
}

func newKeyStore(path string) *LocalKeyStore {
	return &LocalKeyStore{
		path:       path,
		versions:   make(map[uint64]*KeyVersion),
		refs:       make(map[uint64]int),
		migrations: make(map[uint64]*persistedMigration),
		next:       1,
	}
}

// snapshot 在调用方持锁时生成可落盘的完整状态快照。
func (s *LocalKeyStore) snapshot() *persistedState {
	st := &persistedState{
		Format:     uint32(stateVersion),
		Active:     s.active,
		Next:       s.next,
		Versions:   make([]persistedKey, 0, len(s.versions)),
		Refs:       make(map[uint64]int, len(s.refs)),
		Migrations: make(map[uint64]*persistedMigration, len(s.migrations)),
	}
	ids := make([]uint64, 0, len(s.versions))
	for v := range s.versions {
		ids = append(ids, v)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, v := range ids {
		kv := s.versions[v]
		pk := persistedKey{Version: kv.Version, State: kv.State}
		if kv.State != StateRetired {
			pk.Key = append([]byte(nil), kv.key...)
		}
		st.Versions = append(st.Versions, pk)
	}
	for v, n := range s.refs {
		st.Refs[v] = n
	}
	for v, m := range s.migrations {
		st.Migrations[v] = cloneMigration(m)
	}
	return st
}

// restore 用磁盘快照重建内存状态（仅初始化时调用）。
func (s *LocalKeyStore) restore(st *persistedState) {
	s.versions = make(map[uint64]*KeyVersion, len(st.Versions))
	for _, pk := range st.Versions {
		kv := &KeyVersion{Version: pk.Version, State: pk.State}
		if pk.State != StateRetired {
			kv.key = append([]byte(nil), pk.Key...)
		}
		s.versions[pk.Version] = kv
	}
	s.active = st.Active
	s.next = st.Next
	if st.Next == 0 {
		s.next = 1
	}
	s.refs = make(map[uint64]int, len(st.Refs))
	for v, n := range st.Refs {
		s.refs[v] = n
	}
	s.migrations = make(map[uint64]*persistedMigration, len(st.Migrations))
	for v, m := range st.Migrations {
		s.migrations[v] = cloneMigration(m)
	}
}

// persistLocked 必须在持有写锁时调用。落盘失败时回滚到 prev，
// 保证失败后内存与磁盘仍是同一份（上一次完整）状态。
func (s *LocalKeyStore) commitLocked(prev *persistedState) error {
	if s.path == "" {
		return nil
	}
	if err := saveStateFile(s.path, s.snapshot()); err != nil {
		if prev != nil {
			s.restore(prev)
		}
		return err
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
	prev := s.snapshot()
	if old, ok := s.versions[s.active]; ok && old.State == StateActive {
		old.State = StateDeactivated
	}
	v := s.next
	s.next++
	s.versions[v] = &KeyVersion{Version: v, State: StateActive, key: key}
	s.active = v
	if err := s.commitLocked(prev); err != nil {
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
	prev := s.snapshot()
	kv.State = StateDisabled
	return s.commitLocked(prev)
}

// Retire 退役指定版本并销毁密钥材料；激活版本不允许退役。
// 是否仍有未迁移数据/在途迁移作业由更高层（Service）在同一存储锁内判定。
func (s *LocalKeyStore) Retire(version uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.retireLocked(version)
}

func (s *LocalKeyStore) retireLocked(version uint64) error {
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
	prev := s.snapshot()
	// 销毁密钥材料，之后任何解密请求都会得到 KindKeyRetired。
	for i := range kv.key {
		kv.key[i] = 0
	}
	kv.key = nil
	kv.State = StateRetired
	delete(s.refs, version)
	delete(s.migrations, version)
	return s.commitLocked(prev)
}

// retireChecked 是 Service.Retire 的存储侧实现：在同一写锁临界区内
// 校验“非激活 + 无未迁移引用 + 无未完成迁移作业”，然后销毁材料并落盘。
func (s *LocalKeyStore) retireChecked(version uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.versions[version]; !ok {
		return newError(KindKeyNotFound, version, "key version does not exist")
	}
	if s.versions[version].State == StateActive {
		return newError(KindVersionInUse, version, "active version cannot be retired")
	}
	if m := s.migrations[version]; m != nil && !migrationDone(m) {
		return newError(KindVersionInUse, version, "migration for this version is not finished")
	}
	if s.refs[version] > 0 {
		return newError(KindVersionInUse, version, "version still holds unmigrated ciphertexts")
	}
	return s.retireLocked(version)
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

// addRef 在写锁内为某版本记一笔未迁移密文引用并落盘。
func (s *LocalKeyStore) addRef(version uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.versions[version]; !ok {
		return newError(KindKeyNotFound, version, "key version does not exist")
	}
	prev := s.snapshot()
	s.refs[version]++
	return s.commitLocked(prev)
}

// stateAndRef 在同一临界区返回某版本的状态与当前引用数，
// 供加密后“版本未退役才记账”的判定使用，消除状态检查与记账间的竞态。
func (s *LocalKeyStore) stateAndAddRef(version uint64) (KeyState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kv, ok := s.versions[version]
	if !ok {
		return "", newError(KindKeyNotFound, version, "key version does not exist")
	}
	if kv.State == StateRetired {
		return kv.State, nil
	}
	prev := s.snapshot()
	s.refs[version]++
	if err := s.commitLocked(prev); err != nil {
		return "", err
	}
	return kv.State, nil
}

// dropRef 在写锁内减少某版本的引用计数（不会变负），并落盘。
func (s *LocalKeyStore) dropRef(version uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.snapshot()
	if s.refs[version] > 0 {
		s.refs[version]--
		if s.refs[version] == 0 {
			delete(s.refs, version)
		}
	}
	return s.commitLocked(prev)
}

// refsOf 返回某版本当前未迁移密文引用数。
func (s *LocalKeyStore) refsOf(version uint64) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.refs[version]
}

// beginMigration 在写锁内为某源版本登记（或复用）迁移作业。
//
// items 为本次登记的完整条目集合（ID 稳定且唯一）：
//   - 首次登记：必须源版本可解密、存在当前激活版本，作业落盘；
//   - 重试登记：条目集合必须与既有作业逐一致（ID 集合一致，
//     且同一 ID 的信封指纹一致），否则返回 KindMigrationConflict，
//     防止把迁过的和没迁的混在一起、也防止重复计数。
//
// 返回作业的持久化深拷贝。
func (s *LocalKeyStore) beginMigration(source uint64, items []persistedMigrationItem) (*persistedMigration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	srcKV, ok := s.versions[source]
	if !ok {
		return nil, newError(KindKeyNotFound, source, "key version does not exist")
	}
	if srcKV.State == StateRetired {
		return nil, newError(KindKeyRetired, source, "source version retired, cannot migrate")
	}
	if srcKV.State == StateDisabled {
		return nil, newError(KindKeyDisabled, source, "source version disabled, cannot migrate")
	}
	if s.active == 0 {
		return nil, newError(KindKeyNotFound, 0, "no active key version")
	}
	if len(items) == 0 {
		return nil, newError(KindMigrationConflict, source, "migration requires at least one item")
	}

	incoming := make(map[string]persistedMigrationItem, len(items))
	for _, it := range items {
		if it.ID == "" || len(it.Fingerprint) != sha256.Size {
			return nil, newError(KindMigrationConflict, source, "migration item is invalid")
		}
		if _, dup := incoming[it.ID]; dup {
			return nil, newError(KindMigrationConflict, source, "duplicate migration item id "+it.ID)
		}
		incoming[it.ID] = it
	}

	if existing := s.migrations[source]; existing != nil {
		if len(existing.Items) != len(incoming) {
			return nil, newError(KindMigrationConflict, source,
				"migration retry must present the same item set")
		}
		for _, old := range existing.Items {
			neu, ok := incoming[old.ID]
			if !ok || !equalBytes(old.Fingerprint, neu.Fingerprint) {
				return nil, newError(KindMigrationConflict, source,
					"migration retry item "+old.ID+" differs from the registered item")
			}
		}
		return cloneMigration(existing), nil
	}

	prev := s.snapshot()
	job := &persistedMigration{Source: source, Target: s.active, Items: items}
	s.migrations[source] = job
	if err := s.commitLocked(prev); err != nil {
		return nil, err
	}
	return cloneMigration(job), nil
}

// migrationJob 返回某源版本迁移作业的深拷贝；不存在返回
// KindMigrationNotFound。
func (s *LocalKeyStore) migrationJob(source uint64) (*persistedMigration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.migrations[source]
	if !ok {
		return nil, newError(KindMigrationNotFound, source, "no migration for version")
	}
	return cloneMigration(m), nil
}

// prepareMigrationCrypto 在同一读锁临界区内取出源版本密钥材料与当前
// 激活版本（迁移落地版本）密钥材料，并校验条目属于该作业且指纹一致。
// 加解密由调用方在锁外完成，因此迁移不阻塞并发写入与轮换。
func (s *LocalKeyStore) prepareMigrationCrypto(source uint64, id string, fp []byte) (srcKey []byte, target uint64, targetKey []byte, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	job, ok := s.migrations[source]
	if !ok {
		return nil, 0, nil, newError(KindMigrationNotFound, source, "no migration for version")
	}
	it := findPersistedItem(job, id)
	if it == nil {
		return nil, 0, nil, newError(KindMigrationConflict, source, "item "+id+" is not part of the migration")
	}
	if it.Done {
		return nil, 0, nil, newError(KindInternal, source, "item already committed")
	}
	if !equalBytes(it.Fingerprint, fp) {
		return nil, 0, nil, newError(KindMigrationConflict, source, "item "+id+" fingerprint differs from registration")
	}
	srcKV, ok := s.versions[source]
	if !ok {
		return nil, 0, nil, newError(KindKeyNotFound, source, "key version does not exist")
	}
	if srcKV.State == StateRetired {
		return nil, 0, nil, newError(KindKeyRetired, source, "source version retired")
	}
	if srcKV.State == StateDisabled {
		return nil, 0, nil, newError(KindKeyDisabled, source, "source version disabled")
	}
	tgtKV, ok := s.versions[s.active]
	if !ok || tgtKV.State != StateActive {
		return nil, 0, nil, newError(KindKeyNotFound, 0, "no active key version")
	}
	return append([]byte(nil), srcKV.key...), s.active, append([]byte(nil), tgtKV.key...), nil
}

func findPersistedItem(job *persistedMigration, id string) *persistedMigrationItem {
	for i := range job.Items {
		if job.Items[i].ID == id {
			return &job.Items[i]
		}
	}
	return nil
}

// commitMigrationItem 在写锁内确认一个条目已迁移：
// 仅当该条目尚未完成时，把一笔引用从源版本转到落地版本并记账落盘；
// 已完成的条目重复提交是幂等空操作（不重复计数、不丢数据）。
// 若落地版本在加解密期间已被轮换（不再是激活版本）或退役，
// 返回 KindVersionInUse 供调用方用新的激活版本重试。
// 返回（是否本次首次记账, 落地版本）。
func (s *LocalKeyStore) commitMigrationItem(source uint64, id string, fp []byte, landed uint64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	job, ok := s.migrations[source]
	if !ok {
		return false, newError(KindMigrationNotFound, source, "no migration for version")
	}
	idx := -1
	for i := range job.Items {
		if job.Items[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false, newError(KindMigrationConflict, source, "item "+id+" is not part of the migration")
	}
	it := &job.Items[idx]
	if !equalBytes(it.Fingerprint, fp) {
		return false, newError(KindMigrationConflict, source, "item "+id+" fingerprint differs from registration")
	}
	if it.Done {
		// 重试：该条目此前已记账，幂等返回，不重复计数。
		return false, nil
	}
	tgtKV, ok := s.versions[landed]
	if !ok {
		return false, newError(KindKeyNotFound, landed, "landed key version does not exist")
	}
	if tgtKV.State == StateRetired || landed != s.active {
		// 加解密期间发生了轮换或退役，用新激活版本重试整条迁移。
		return false, newError(KindVersionInUse, landed, "landed version changed during migration; retry")
	}
	prev := s.snapshot()
	it.Done = true
	it.Landed = landed
	// 引用从旧版本转到新版本：旧版本 -1，落地版本 +1，总数不变。
	if s.refs[source] > 0 {
		s.refs[source]--
		if s.refs[source] == 0 {
			delete(s.refs, source)
		}
	}
	s.refs[landed]++
	if err := s.commitLocked(prev); err != nil {
		return false, err
	}
	return true, nil
}
