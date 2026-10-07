# go-envelope-key-rotation-go

信封加密（Envelope Encryption）与主密钥生命周期管理。以本地密钥存储
（`LocalKeyStore`）模拟受管密钥服务（KMS），保证密钥轮换、历史数据解密与
并发读写在各入口下行为一致且失败原因可区分。

密钥版本既可以只活在进程内存里（`NewLocalKeyStore`），也可以落到本地状态
文件跨重启保留（`OpenKeyStore`）；旧版本密文支持在线迁移到当前激活版本，
迁移进度可查询、可重试，并且是退役流程的前置条件。

## 快速开始

```go
// 纯内存模式（不落盘，进程退出即失）
store := envelope.NewLocalKeyStore()

// 持久化模式：状态文件不存在则新建，存在则原样恢复
store, err := envelope.OpenKeyStore("/var/lib/app/keystore.state")
if err != nil {
    // 损坏 -> envelope.KindStorageCorrupted
    // 更新的未知格式 -> envelope.KindUnsupportedFormat
    log.Fatal(err)
}
svc := envelope.NewService(store)
v, _ := svc.Rotate()                 // 生成并激活首个主密钥版本
ct, _ := svc.Encrypt([]byte("data")) // 用当前激活版本封装
pt, _ := svc.Decrypt(ct)             // 用信封记录的版本解封
```


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
- **退役**（`Service.Retire`）：销毁密钥材料。激活版本、仍持有未迁移密文
  （引用计数 > 0）或存在未完成迁移作业的版本会被拒绝并返回
  `version_in_use`；旧版本数据应先经“在线迁移”全部迁到当前激活版本（作业
  完成即把引用转移走），再行退役。三类解密失败可区分：已停用版本返回
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
| `storage_corrupted` | 状态文件为空、截断、校验和不符、JSON 非法或语义不自洽 |
| `unsupported_format` | 状态文件使用了比当前更新 / 无法识别的格式版本 |
| `migration_conflict` | 迁移重试的条目集合与登记不一致（ID/指纹/数量） |
| `migration_not_found` | 查询或提交的迁移作业不存在 |
| `internal` | 内部错误 |

解密顺序：先校验元数据格式（`malformed_metadata`）→ 查密钥版本
（`key_not_found` / `key_retired`）→ 校验密钥承诺（`key_mismatch`）→
GCM 完整性校验（`ciphertext_tampered`）。任何失败路径都不返回部分明文。

兼容规则：同一 `magic`（`env1`）内，任意历史版本写入的信封在其密钥版本
未被退役前均可解密；退役后该版本数据视为已迁移完毕，解密被明确拒绝。

## 持久化（跨重启保留）

通过 `OpenKeyStore(path)` 打开的存储会把**全部状态**原子落到本地文件，
进程重启后原样恢复：

- 每个版本的密钥材料（退役版本的材料不落盘）与生命周期状态；
- 当前激活版本指针与下一个版本计数器（版本号单调、不复用）；
- 每个版本“尚未迁移密文”的引用计数；
- 正在进行的迁移作业及其逐条进度。

每次轮换、停用、退役、写入记账、迁移提交都在存储的同一把写锁内完成
“改内存 → 原子落盘”，因此并发操作下内存结论与磁盘内容严格一致。落盘失败
会回滚内存到上一份快照并对外返回错误，绝不出现“内存改了、磁盘还是旧的”。

### 状态文件格式

文件是带外封装的二进制容器，容器头携带**自己的格式版本**，载荷为 JSON，
末尾附 SHA-256 校验和：

```
magic    "EKSF"                       4 字节
version  容器格式版本（当前为 1）      1 字节
length   payload 长度（大端）          4 字节
payload  length 字节 JSON（persistedState）
sum      SHA-256(以上全部字节)         32 字节
```

JSON 载荷内另有 `format` 字段与容器版本相互印证（容器版本决定怎么切字节，
载荷版本决定怎么解释 JSON）。

**兼容范围：**

| 打开时遇到的情况 | 行为 |
|---|---|
| 文件不存在 | 视为全新空存储，首次变更时创建 |
| 容器版本 == 当前（1），校验通过 | 正常加载 |
| 容器版本更新（如 2） | 拒绝，返回 `unsupported_format`，错误信息带版本号 |
| 文件存在但为空 | 拒绝，返回 `storage_corrupted`（**不**当成空存储） |
| magic 不符 / 头部或载荷截断 / 长度不符 | `storage_corrupted` |
| 校验和不符（载荷或尾部被改） | `storage_corrupted` |
| JSON 无法解析 | `storage_corrupted` |
| 语义不自洽（退役版本仍带材料、激活指针悬空、未知状态、密钥长度错误、refs/迁移指向不存在版本） | `storage_corrupted` |

> 校验和用于检测截断与意外损坏，并区分“空文件 / 版本不存在 / 存储损坏”。
> 它不提供抗恶意篡改能力，本地状态文件应配合文件系统权限保护；把 KEK 外包
> 到真实 KMS/HSM 的静态加密不在本地存储的威胁模型内。

### 原子写

写入采用 `写同目录临时文件 → fsync → rename 替换 → fsync 目录`。进程在
写到一半时崩溃或被杀，重启后目标文件只可能是**上一次完整状态**或
**本次完整状态**，不会读到半截；损坏的半截文件会被明确拒绝而不是被当成空
存储。正常流程不残留 `.tmp` 临时文件。

## 旧版本密文在线迁移

`Service` 提供以某个源版本为单位的在线迁移能力，迁移期间新写入照常使用
当前激活版本、不会被卡住：

```go
items := []envelope.MigrationItem{
    {ID: "row-1", Raw: row1Envelope}, // ID 取数据记录主键，须稳定唯一
    {ID: "row-2", Raw: row2Envelope},
}
prog, _ := svc.BeginMigration(oldVersion, items) // 登记作业（持久化）
for _, it := range items {
    res, _ := svc.MigrateOne(oldVersion, it) // 旧版解密 → 当前激活版重封
    saveToDB(it.ID, res.Output)              // 调用方把新信封写回自己的库
}
prog, _ = svc.MigrationProgressOf(oldVersion) // 查询进度
// prog.Finished == true 后才允许退役 oldVersion
_ = svc.Retire(oldVersion)
```

行为保证：

- **明文一致**：每条迁移先以源版本解密、再以当前激活版本重新封装；信封的
  AAD/承诺/完整性机制不变，调用方落库前可自行比对解密结果。
- **引用原子转移**：条目提交时在同一写锁内把一笔引用从源版本转到落地版本
  （源 -1 / 目标 +1，总数守恒）并落盘。
- **并发轮换不丢**：若一条迁移在加解密期间其落地版本恰好被轮换/退役，
  提交得到 `version_in_use`，服务自动用新的激活版本重试，已产出的旧结果
  作废，绝不把密文记到不可用版本上。
- **进度可查询**：`MigrationProgressOf` 返回 `Total/Done/Pending/Finished`。
- **失败重试安全**：作业按 `ID + 原信封 SHA-256 指纹` 记账。重试
  `BeginMigration` 必须提交**完全相同**的条目集合（ID 集合与每个 ID 的指纹
  都一致），否则返回 `migration_conflict`，防止把迁过的和没迁的混在一起或
  重复计数；对已完成条目再次 `MigrateOne` 是幂等空操作，不重复计数。
- **跨重启续迁**：作业与逐条进度随状态文件落盘，重启后用相同集合重新
  `BeginMigration` 即可从断点继续。

### 迁移对退役流程的影响

`Service.Retire(v)` 在存储同一写锁临界区内依次校验，任一不满足都返回
`version_in_use`：

1. `v` 不是当前激活版本（须先轮换）；
2. 针对 `v` 的迁移作业不存在未完成条目（从未登记迁移、但确无引用的版本
   不受此限）；
3. `v` 的未迁移引用计数为 0。

即：**某个版本的数据全部迁完，它才允许被退役。** 退役会销毁密钥材料、清空
该版本引用与迁移作业记录并落盘；重启后仍是退役态，旧密文稳定得到
`key_retired`。

## 并发保证

- 密钥存储与服务的所有方法并发安全（`sync.RWMutex` / `sync.Mutex`）。
- 退役的“引用检查 + 销毁材料”在同一临界区完成，并发写入无法绕过检查；
  持久化模式下该临界区同时完成原子落盘，内存结论与磁盘严格一致。
- 加密完成后若版本恰被并发退役，本次写入自动用新激活版本重试，
  保证返回的密文必然可解密：无数据损坏、无半写、无静默失败。
- 迁移的加解密在迁移记账锁之外完成，不阻塞并发写入；记账提交串行化，
  且与轮换/退役在存储写锁上互斥，引用转移不重复、不丢失。

## 验证方法

```sh
go build ./...           # 编译
go vet ./...             # 静态检查
go test ./... -race -v   # 全部用例（含竞态检测）
go test ./... -race -count=10  # 压测并发用例的稳定性
```

本地手动验证跨重启 / 迁移 / 损坏拒绝，可参考测试中的小套路：

1. 用 `t.TempDir()` 下的路径 `OpenKeyStore`，`Rotate` + `Encrypt` 若干条，
   再 `Rotate`/`Deactivate`，然后用**同一文件路径**重新 `OpenKeyStore`，
   验证激活版本、各版本状态、引用计数与历史密文解密结果。
2. `BeginMigration` → 若干 `MigrateOne` → 查询 `MigrationProgressOf`，
   中途重新 `OpenKeyStore` 模拟重启，验证进度与引用转移从断点恢复。
3. 直接读入状态文件，截断 / 翻转载荷或校验和字节 / 把版本字节改成更大值
   后写回，再 `OpenKeyStore`，分别得到 `storage_corrupted` 与
   `unsupported_format`。

测试日志统一用 `op=… version=vN kind=…` 打印操作、涉及的密钥版本与失败
类别，失败归属（哪个场景、哪个版本、哪一类）可直接从 `-v` 输出看出。

测试覆盖：

- `TestRotateDecryptsOldData`：轮换前数据在旧版本保留时可解密，新写入使用新版本。
- `TestDecryptUnavailableVersions`：已退役 / 不存在版本的解密被可区分地拒绝。
- `TestTamperAndMismatch`：篡改密文、篡改包裹密钥、格式错误元数据、密钥不匹配
  分别映射为对应错误类别，且失败路径不返回部分明文。
- `TestRetireBoundaries`：激活版本不得停用/退役、有引用不得退役、重复退役与
  不存在版本的边界。
- `TestConcurrentRotateReadWrite` / `TestConcurrentRetire`：轮换与退役期间的
  并发读写（`-race` 下验证），无损坏、无半写、无静默失败。
- `TestPersistenceRestartRecoversKeys`：重启后密钥材料/状态/激活版本/引用原样
  恢复，未退役版本历史数据可解密，停用与退役的边界结论与重启前一致。
- `TestPersistenceRejectsCorruption` / `TestPersistenceSemanticCorruption`：
  空文件、截断、未知 magic、更新格式版本、载荷/校验和损坏、语义不自洽被
  可区分地拒绝（`storage_corrupted` / `unsupported_format`），不会当成空存储。
- `TestAtomicWriteNoHalfState`：高频轮换/写入后无临时文件残留，完整快照可加载，
  半截文件被拒绝。
- `TestMigrationRewrapAndRetire`：迁移前后明文一致、引用随迁移转移、进度可查，
  只有全部迁完才允许退役。
- `TestMigrationIdempotentRetry`：中途失败后重试，已迁条目不重复计数、未迁
  条目继续可迁、数据不丢。
- `TestMigrationConflictGuards`：指纹不符 / 集合大小变化 / 查询不存在作业
  分别得到可区分错误。
- `TestMigrationSurvivesRestart`：迁移迁一半重启后进度与引用记账原样恢复，
  续迁不重复计数并可正常退役。
- `TestMigrationConcurrentWithRotateAndWrites`：迁移与并发轮换、并发写入同时
  进行，全部条目成功、明文一致、引用守恒、新写入不被卡住（`-race`）。
