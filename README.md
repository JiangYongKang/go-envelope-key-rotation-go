# go-envelope-key-rotation-go

信封加密（Envelope Encryption）与主密钥生命周期管理。以本地内存密钥存储
（`LocalKeyStore`）模拟受管密钥服务（KMS），保证密钥轮换、历史数据解密与
并发读写在各入口下行为一致且失败原因可区分。密钥版本状态可原子落盘、跨重启
原样恢复，并提供把旧版本信封在线迁移到当前激活版本的迁移会话。

## 密钥生命周期

每个主密钥版本处于且仅处于以下三种状态之一：

```
            Generate/Rotate                Retire
  (不存在) ───────────► active ──────────► (拒绝: version_in_use)
                           │ Rotate（生成新版本时自动转换）
                           ▼
                     deactivated ──Deactivate──► disabled
                     （仅可解密）                 （加解密均拒绝）
                           │                        │
                           └──────Retire────────────┘
                                  ▼
                              retired（密钥材料已销毁）
```

| 状态 | 加密新数据 | 解密历史数据 | 可退役 |
|---|---|---|---|
| `active` | ✅ | ✅ | ❌（`version_in_use`） |
| `deactivated` | ❌ | ✅ | ✅（须无未迁移数据） |
| `disabled` | ❌ | ❌（`key_disabled`） | ✅ |
| `retired` | ❌ | ❌（`key_retired`） | —（已退役） |

规则：

- **轮换**（`Service.Rotate`）：生成新版本并置为激活，旧激活版本自动转为
  `deactivated`。任意时刻至多一个激活版本。轮换后新写入立即使用新版本，
  旧版本保留期间历史数据仍可解密。
- **停用**（`LocalKeyStore.Deactivate`）：将 `deactivated` 版本显式关闭，
  此后其加解密请求均被拒绝并返回 `key_disabled`，用于迁移完成后、退役前
  的过渡。激活版本不得直接停用，须先轮换。
- **退役**（`Service.Retire`）：销毁密钥材料。激活版本或仍持有未迁移密文
  （引用计数 > 0）的版本会被拒绝并返回 `version_in_use`；调用方在数据迁移
  或删除后通过 `Service.Forget` 递减引用。三类失败可区分：已停用版本返回
  `key_disabled`，已退役版本返回 `key_retired`，不存在版本返回
  `key_not_found`。

## 信封格式

每条密文是一个 JSON 信封（格式标识 `env1`）：

| 字段 | 含义 |
|---|---|
| `magic` | 固定 `"env1"`，标识信封格式版本 |
| `version` | 包裹 DEK 所用的主密钥版本 |
| `keycheck` | 主密钥承诺值 `HMAC-SHA256(kek, "env1/keycheck")` 截断 16 字节 |
| `wrapped` | 主密钥以 AES-256-GCM 包裹的数据加密密钥（DEK） |
| `wrapnonce` / `datanonce` | 包裹 DEK / 加密数据各自的随机 nonce（12 字节） |
| `data` | 以 DEK 通过 AES-256-GCM 加密的密文（含认证标签） |

加密时随机生成一次性 DEK 加密数据，再用当前激活主密钥包裹 DEK；`magic` 与
`version` 作为 GCM 附加认证数据（AAD）绑定，元数据篡改同样导致校验失败。

## 错误类别与版本兼容

所有对外错误为 `*envelope.Error`，用 `envelope.KindOf(err)` 判定类别，
底层错误细节不透出接口：

| 类别 | 触发场景 |
|---|---|
| `key_not_found` | 密钥版本不存在 / 无激活版本 |
| `key_disabled` | 版本已停用，不可用于该操作 |
| `key_retired` | 版本已退役，密钥材料已销毁 |
| `version_in_use` | 激活中或仍有未迁移数据，不得停用/退役 |
| `ciphertext_tampered` | 密文或被包裹 DEK 的 GCM 完整性校验失败 |
| `malformed_metadata` | 信封 JSON 或字段格式非法 |
| `key_mismatch` | 信封承诺值与解密所用密钥不匹配 |
| `storage_corrupt` | 状态文件被截断、校验和不符或语义损坏 |
| `unsupported_format` | 状态文件格式版本比当前程序支持的更新 |
| `migration_state` | 迁移前置条件不满足（源版本状态非法 / 条目 ID 重复 / 会话冲突等） |
| `internal` | 内部错误（含落盘写失败，此时内存已回滚） |

解密顺序：先校验元数据格式（`malformed_metadata`）→ 查密钥版本
（`key_not_found` / `key_retired`）→ 校验密钥承诺（`key_mismatch`）→
GCM 完整性校验（`ciphertext_tampered`）。任何失败路径都不返回部分明文。

兼容规则：同一 `magic`（`env1`）内，任意历史版本写入的信封在其密钥版本
未被退役前均可解密；退役后该版本数据视为已迁移完毕，解密被明确拒绝。

## 持久化

默认构造（`NewService(NewLocalKeyStore())`）仍是纯内存模式。需要跨重启保留时，
改用 `envelope.OpenService(path)`（或 `envelope.OpenLocalKeyStore(path)`）：

```go
svc, err := envelope.OpenService("/var/lib/app/kek-state.json")
```

进程重启后再次以同一路径打开，即可恢复：全部密钥材料、每个版本的状态
（active / deactivated / disabled / retired）、当前激活版本与版本号计数器。
退役版本不写材料，因此重启后它依然是退役状态（`key_retired`），绝不会被
当成可用版本或“版本不存在”。

### 原子性与内存/磁盘一致性

- 每次轮换、停用、退役都在密钥存储的同一把写锁内完成
  “变更 → 序列化 → 临时文件 `fsync` → `rename` 原子替换”。
- `rename` 在同一文件系统内是原子的：写到一半崩溃 / 被杀，重启后只能看到
  **上一次完整状态**或**本次完整状态**，不存在半截目标文件；临时文件位于
  同目录，替换后还会尽力 `fsync` 所在目录。
- 落盘失败时内存状态整体回滚到变更前（深拷贝快照），因此“内存里的结论”和
  “已经落盘的结论”始终是同一个状态，不会出现“内存已轮换、磁盘没轮换”的
  分叉。并发轮换 / 停用 / 退役同理：磁盘可见状态与内存决策一一对应。

### 存储格式与兼容范围

文件是一层带校验和的 JSON 信封，格式版本为 1：

| 字段 | 含义 |
|---|---|
| `magic` | 固定 `"KEKSTORE"`，识别状态文件身份 |
| `format` | 状态格式版本号（当前为 `1`） |
| `body` | 状态负载的原始 JSON，校验和针对这段字节计算 |
| `sha256` | `body` 的 SHA-256（十六进制），检测截断 / 损坏 |

`body` 内含版本计数器 `next`、激活版本指针 `active`，以及每个版本的
`version / state / material`（退役版本无 `material`）。

加载时严格校验，失败类别彼此可区分，且**绝不**把坏文件静默当成空存储：

| 情况 | 结果 |
|---|---|
| 文件不存在 | 按全新存储启动 |
| 能识别的旧格式（当前即 format=1） | 正常加载（承诺：可识别的旧格式可读） |
| `format` 比本程序支持的更新 | `unsupported_format`，明确拒绝并保留文件 |
| JSON 截断 / 乱码 / 空文件 | `storage_corrupt` |
| 外层 `magic` 不符 | `storage_corrupt` |
| `sha256` 缺失、非法或不符（含被截断） | `storage_corrupt` |
| 语义自相矛盾（退役版本带材料、激活指针缺失、多个 active 等） | `storage_corrupt` |

> 引用计数（每个版本当前持有多少密文）反映的是调用方数据层的事实，不写入
> 状态文件；迁移会话同样是进程内对象，不跨重启持久化。重启后由调用方在数据
> 层重新建立记账（新写入会再次计数，或通过 `Forget` 调整）。密钥材料与
> 生命周期状态本身则完整持久化。

## 在线迁移

旧版本的数据可以在线重新落到当前激活版本，迁移期间无需停写：

```go
items := []envelope.MigrationItem{
    {ID: "row-1", Envelope: oldEnvelope1},
    // ...某源版本下的一整批信封；ID 由调用方提供、会话内唯一
}
m, err := svc.BeginMigration(sourceVersion, items)
// Run 可与 Encrypt/Rotate 并发；可重复调用以重试失败条目
err = m.Run(func(r envelope.MigratedRecord) error {
    return myStore.Replace(r.ID, r.New) // 用新信封替换旧信封
})
prog := m.Progress() // {Source Total Done Failed Pending Complete}
```

- **前置条件**：源版本必须已轮换（处于 `deactivated`）。激活版本
  （`version_in_use`）、已停用（`key_disabled`）、已退役（`key_retired`）
  版本不可迁移；条目不能为空、ID 不能重复，每条信封必须确实属于源版本，
  否则返回 `migration_state`；同一源版本同时只允许一个迁移会话。
- **不阻塞新写入**：迁移期间 `Encrypt` 始终使用当前激活版本；迁移也可以与
  `Rotate` 并发，重试时自动落到当时最新的激活版本。
- **明文一致**：每条记录先解密、再用激活版本重新加密，并复验新旧信封解出的
  明文逐字节一致才交付；`MigratedRecord` 同时给出旧/新信封与明文。
- **进度可查**：`Progress()` 返回 total/done/failed/pending/complete；
  `Failed()` 给出仍失败条目 ID 及其最近错误类别。
- **失败可重试、不重不丢**：成功条目以条目 ID 去重，重复 `Run` 不会重复调用
  sink、不会重复转移引用。单条流程是“重新加密 → sink 落库 → 在同一把锁内
  把引用源版本 -1、目标版本 +1”，引用转移是提交点；sink 失败则该条停在
  failed 稍后重试，已交付结果重试时不会重复交付。
- **退役闸门**：只有源版本全部迁完（引用归零）才允许 `Retire`，未迁完一律
  `version_in_use`；迁移会话进行中不允许 `Deactivate` 源版本
  （`migration_state`），避免迁移中途失去源密钥、把已迁与未迁数据混在一起。
  主动放弃会话用 `Migration.Close()`（已完成条目的引用转移保持有效）。

## 并发保证

- 密钥存储与服务的所有方法并发安全（`sync.RWMutex` / `sync.Mutex`）。
- 退役的“引用检查 + 销毁材料”在同一临界区完成，并发写入无法绕过检查。
- 加密完成后若版本恰被并发退役，本次写入自动用新激活版本重试，
  保证返回的密文必然可解密：无数据损坏、无半写、无静默失败。

## 验证方法

```sh
go build ./...        # 编译
go vet ./...          # 静态检查
go test ./... -race -v  # 测试（含竞态检测），日志打印密钥版本与错误类别
```

测试覆盖：

- `TestRotateDecryptsOldData`：轮换前数据在旧版本保留时可解密，新写入使用新版本。
- `TestDecryptUnavailableVersions`：已退役 / 不存在版本的解密被可区分地拒绝。
- `TestTamperAndMismatch`：篡改密文、篡改包裹密钥、格式错误元数据、密钥不匹配
  分别映射为对应错误类别，且失败路径不返回部分明文。
- `TestRetireBoundaries`：激活版本不得停用/退役、有引用不得退役、重复退役与
  不存在版本的边界。
- `TestConcurrentRotateReadWrite` / `TestConcurrentRetire`：轮换与退役期间的
  并发读写（`-race` 下验证），无损坏、无半写、无静默失败。

持久化与迁移新增覆盖（日志统一带 `scenario=`、涉及版本与错误类别）：

- `TestPersistRestartRecoversVersions`：重启后密钥材料 / 状态 / 激活版本 /
  版本计数器原样恢复，重启前各版本写的历史密文仍可解密。
- `TestPersistRetiredDisabledBoundariesSurviveRestart`：退役版本重启后仍为
  `key_retired`、停用版本保持 `key_disabled`，边界结论不回潮。
- `TestPersistAtomicWriteLeavesNoTempFiles` / `TestPersistConcurrentLifecycleAndReopen`：
  原子写无临时文件残留；并发轮换写入后重开文件，磁盘与内存状态一致。
- `TestRejectUnknownNewerFormat`：更新的未知格式以 `unsupported_format` 拒绝。
- `TestRejectCorruptAndTruncated` / `TestRejectSemanticallyCorruptBody`：
  截断、空文件、乱码、magic 不符、校验和不符以及语义损坏均为
  `storage_corrupt`，且坏文件保留、不会被当成空存储或“版本不存在”。
- `TestLoadKnownOlderFormat` / `TestOpenMissingFileStartsFresh`：可识别旧格式
  正常加载、缺文件按全新存储启动。
- `TestPersistWriteFailureRollsBackMemory`：落盘失败时内存回滚，内存/磁盘不分叉。
- `TestMigrationRewrapsAndGatesRetirement`：迁移前后明文逐字节一致、引用转移、
  未迁完阻塞退役、全部迁完可退役。
- `TestMigrationIdempotentRetry` / `TestMigrationRetryAfterFailure`：成功条目
  去重，失败重试不重复计数、不重复交付、不丢数据。
- `TestMigrationValidation`：激活/停用/退役版本不可发起迁移、重复 ID 与错误
  源信封拒绝、同版本重复会话拒绝、迁移中禁止停用、`Close` 后可重新发起。
- `TestMigrationAcrossRestart`：迁移完成并退役、重启后新版本数据可读、
  旧版本保持退役边界。
- `TestConcurrentMigrationRotateWrite`：迁移与轮换、持续新写入同时进行，
  新写入不被卡住、交付不重复、最终全部完成且源版本可退役（`-race` 验证）。

本地快速验证持久化 + 迁移行为可参考测试中的用法：用 `t.TempDir()` 下的路径
`OpenService` → `Rotate` / `Encrypt` → 再次 `OpenService` 模拟重启；
迁移则 `Rotate` 后用旧信封列表 `BeginMigration` 并 `Run` 一个把
`r.New` 写回存储的 sink。
