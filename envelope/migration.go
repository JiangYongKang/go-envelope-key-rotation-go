package envelope

import (
	"bytes"
	"sync"
)

// MigrationItem 是待迁移的一条信封。
//
// ID 由调用方提供、在同一次迁移内必须唯一且非空，用于重试时去重：
// 已成功迁移的条目不会被重复处理，也就不会重复计数。
type MigrationItem struct {
	ID       string
	Envelope []byte
}

// MigratedRecord 是一条成功迁移的结果。
type MigratedRecord struct {
	ID        string // 对应 MigrationItem.ID
	Old       []byte // 迁移前的信封（源版本）
	New       []byte // 重新落到当前激活版本的信封
	Source    uint64
	Target    uint64
	Plaintext []byte // 解密得到的明文，供调用方做二次核对
}

// itemStatusType 是单个迁移条目的状态。
type itemStatusType string

const (
	itemPending   itemStatusType = "pending"   // 尚未处理
	itemDelivered itemStatusType = "delivered" // sink 已成功，但引用转移尚未确认
	itemFailed    itemStatusType = "failed"    // 最近一次尝试失败，可重试
	itemDone      itemStatusType = "done"      // 已交付且引用已转移
)

// MigrationProgress 描述迁移会话的整体进度。
type MigrationProgress struct {
	Source   uint64
	Total    int
	Done     int
	Failed   int
	Pending  int  // 含尚未交付与交付后等待转移确认的条目
	Complete bool // 全部条目都已成功迁移；此时源版本引用应为零，可以退役
}

// itemState 记录单条目迁移状态。
type itemState struct {
	item      MigrationItem
	status    itemStatusType
	delivered bool // sink 是否已成功接收结果
	record    MigratedRecord
	lastErr   *Error
}

// Migration 是针对单个源密钥版本的在线迁移会话。
// 并发安全；Run 可重复调用以重试此前失败的条目。
type Migration struct {
	svc    *Service
	source uint64

	mu       sync.Mutex
	runMu    sync.Mutex // 串行化并发的 Run 调用，避免同一条目被两个 Run 同时处理
	order    []string
	items    map[string]*itemState
	closed   bool
	finished bool // 全部 done 后已从服务登记表摘除
}

// BeginMigration 在服务上为指定源版本创建迁移会话。
//
// 源版本必须存在且处于 deactivated（轮换后、停用/退役前）；
// 条目不能为空、ID 不能重复、每条信封必须确实属于源版本；
// 同一源版本同一时间只允许一个未完成的迁移会话。
//
// 迁移不阻塞新写入：迁移期间 Encrypt 始终使用当前激活版本，
// 迁移本身也可以与 Rotate 并发，重试时会自动落到最新激活版本。
func (s *Service) BeginMigration(source uint64, items []MigrationItem) (*Migration, error) {
	if len(items) == 0 {
		return nil, newError(KindMigrationState, source, "migration has no items")
	}

	st, err := s.store.State(source)
	if err != nil {
		return nil, err
	}
	switch st {
	case StateActive:
		return nil, newError(KindVersionInUse, source, "cannot migrate the active version; rotate first")
	case StateRetired:
		return nil, newError(KindKeyRetired, source, "cannot migrate a retired version")
	case StateDisabled:
		return nil, newError(KindKeyDisabled, source, "cannot migrate a disabled version")
	}

	// 先在锁外完成条目静态校验，避免持锁做 JSON 解析。
	parsed := make(map[string]*itemState, len(items))
	order := make([]string, 0, len(items))
	for _, it := range items {
		if it.ID == "" {
			return nil, newError(KindMigrationState, source, "migration item has empty id")
		}
		if _, dup := parsed[it.ID]; dup {
			return nil, newError(KindMigrationState, source, "duplicate migration item id: "+it.ID)
		}
		env, derr := decode(it.Envelope)
		if derr != nil {
			return nil, derr
		}
		if env.Version != source {
			return nil, newError(KindMigrationState, source,
				"item "+it.ID+" belongs to version "+itoa(env.Version)+", not source "+itoa(source))
		}
		parsed[it.ID] = &itemState{item: it, status: itemPending}
		order = append(order, it.ID)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing := s.migrations[source]; existing != nil {
		return nil, newError(KindMigrationState, source, "a migration for this version is already in progress")
	}
	m := &Migration{
		svc:    s,
		source: source,
		order:  order,
		items:  parsed,
	}
	s.migrations[source] = m
	return m, nil
}

// Run 处理尚未完成的条目（首次处理 pending，重试处理 failed，
// 以及交付成功但引用转移未确认的条目）。
//
// 每条的提交流程：
//  1. 用源版本解密、用当前激活版本重新加密，并复验新旧明文一致；
//  2. 调用 sink 交付新信封（失败则条目留在 failed，稍后重试，无副作用）；
//  3. 在服务同一把锁内把引用从源版本转移到目标版本（成功才记 done）。
//
// 已 done 的条目永远跳过，因此重试不会重复计数、不会重复转移引用。
// 返回一个聚合错误：只要还有条目未完成即非空，错误类别取首个失败条目的类别。
func (m *Migration) Run(sink func(MigratedRecord) error) error {
	// 串行化并发 Run：同一条目任何时刻只被一个执行流处理，
	// 配合条目 ID 去重，保证 sink 不被重复调用、引用不被重复转移。
	m.runMu.Lock()
	defer m.runMu.Unlock()

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return newError(KindMigrationState, m.source, "migration session is closed")
	}
	ids := append([]string(nil), m.order...)
	m.mu.Unlock()

	var firstErr *Error
	for _, id := range ids {
		m.mu.Lock()
		st := m.items[id]
		m.mu.Unlock()
		if st.status == itemDone {
			continue
		}
		if err := m.processOne(st, sink); err != nil {
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	m.mu.Lock()
	complete := true
	for _, st := range m.items {
		if st.status != itemDone {
			complete = false
			break
		}
	}
	if complete && !m.finished {
		m.finished = true
		if m.svc.migrations[m.source] == m {
			delete(m.svc.migrations, m.source)
		}
	}
	m.mu.Unlock()
	if firstErr != nil {
		return firstErr
	}
	return nil
}

// processOne 完成单个条目的“加密转换 → 交付 → 引用转移”，全程幂等。
func (m *Migration) processOne(st *itemState, sink func(MigratedRecord) error) *Error {
	// 已交付过的结果重试时不再重复调用 sink，只重试引用转移，避免重复交付。
	if !st.delivered {
		rec, err := m.svc.rewrap(st.item.Envelope)
		if err != nil {
			m.fail(st, err)
			return asEnvelopeError(err)
		}
		rec.ID = st.item.ID
		if sink != nil {
			if err := sink(rec); err != nil {
				m.fail(st, newError(KindInternal, rec.Source, "migration sink rejected record "+rec.ID))
				return asEnvelopeError(err)
			}
		}
		m.mu.Lock()
		st.delivered = true
		st.record = rec
		st.status = itemDelivered
		st.lastErr = nil
		m.mu.Unlock()
	}

	// 引用转移是真正的提交点：源 -1、目标 +1 在同一临界区内完成。
	m.mu.Lock()
	rec := st.record
	m.mu.Unlock()
	if err := m.svc.transferRefs(rec.Source, rec.Target); err != nil {
		m.fail(st, err)
		return asEnvelopeError(err)
	}
	m.mu.Lock()
	st.status = itemDone
	st.lastErr = nil
	m.mu.Unlock()
	return nil
}

// fail 记录条目失败状态，保留 delivered 事实以便重试时跳过重复交付。
func (m *Migration) fail(st *itemState, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st.status = itemFailed
	st.lastErr = asEnvelopeError(err)
}

// Progress 返回当前迁移进度。
func (m *Migration) Progress() MigrationProgress {
	m.mu.Lock()
	defer m.mu.Unlock()
	p := MigrationProgress{Source: m.source, Total: len(m.items)}
	for _, st := range m.items {
		switch st.status {
		case itemDone:
			p.Done++
		case itemFailed:
			p.Failed++
			p.Pending++
		default:
			p.Pending++
		}
	}
	p.Complete = p.Done == p.Total
	return p
}

// Failed 返回尚未迁移成功的条目 ID 及其最近一次失败的错误类别。
func (m *Migration) Failed() map[string]ErrorKind {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]ErrorKind)
	for id, st := range m.items {
		if st.status != itemDone && st.lastErr != nil {
			out[id] = st.lastErr.Kind
		}
	}
	return out
}

// Close 主动放弃一个未完成的迁移会话并从服务登记表摘除，
// 使该版本可以重新发起迁移或被停用；已经 done 的条目引用转移保持有效。
func (m *Migration) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	if m.svc.migrations[m.source] == m {
		delete(m.svc.migrations, m.source)
	}
}

// rewrap 解密旧信封并用当前激活版本重新加密，复验迁移前后明文完全一致。
// 本函数只做密码学转换，不触碰引用计数。
func (s *Service) rewrap(raw []byte) (MigratedRecord, error) {
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

	// 复验：新信封必须能解开且与原明文逐字节一致。
	verify, err := s.Decrypt(newRaw)
	if err != nil {
		return MigratedRecord{}, err
	}
	if !bytes.Equal(verify, plaintext) {
		return MigratedRecord{}, newError(KindInternal, target, "migration plaintext verification mismatch")
	}

	return MigratedRecord{
		Old:       append([]byte(nil), raw...),
		New:       newRaw,
		Source:    source,
		Target:    target,
		Plaintext: append([]byte(nil), plaintext...),
	}, nil
}

// transferRefs 在同一临界区把一条引用从源版本转移到目标版本，
// 并在转移前重新确认两个版本仍可用，防止与停用/退役竞态。
func (s *Service) transferRefs(source, target uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := s.store.decryptKey(source); err != nil {
		return err
	}
	if st, err := s.store.State(target); err != nil {
		return err
	} else if st == StateRetired {
		return newError(KindKeyRetired, target, "target version retired during migration")
	}
	s.decRef(source)
	s.refs[target]++
	return nil
}

func asEnvelopeError(err error) *Error {
	if e, ok := err.(*Error); ok {
		return e
	}
	return newError(KindInternal, 0, "unexpected migration error")
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
