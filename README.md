# 信封加密与主密钥生命周期管理（本地受管密钥服务模拟）

本工程用**本地持久化密钥存储**模拟受管密钥服务（Managed KMS），在其之上实现
信封加密，并提供主密钥版本的生成、激活、轮换、停用、退役与历史数据迁移。
目标是让「轮换、历史数据解密、并发读写、退役边界」在所有入口下得到一致且
可解释的结论：**每一种失败都有稳定、可区分的错误类别，任何失败路径都不返回
部分明文，也不把底层 crypto 错误透出到对外接口。**

## 目录结构

```
internal/apperr    对外错误类型（稳定的 Category 枚举），内部错误只记录不外泄
internal/kms       受管密钥服务：版本生命周期、数据密钥包装、原子持久化
internal/envelope  信封格式与 Seal/Open（AES-256-GCM 双层 AEAD）
internal/vault     命名密文记录存储 + 旧版本数据迁移（并发安全）
cmd/demo           走完一个版本完整生命周期的可运行示例
```

## 快速开始

```bash
# 跑全部测试（含 -race 并发检测）
go test ./... -race -count=1

# 观察完整生命周期与每一步的错误类别
go run ./cmd/demo
```

## 密钥版本生命周期

一个主密钥版本（`kms.Version`）只能沿下列状态迁移：

```
                 GenerateVersion
   (不存在) ───────────────────────▶ prepared
                                       │ ActivateVersion
                                       ▼
            Rotate/ActivateVersion  ┌────────┐  Rotate
                ┌──────────────────▶│ active │─────────┐
                │                   └────────┘         │ 旧 active
                │ ActivateVersion(retained)            ▼
                │                                  ┌──────────┐
                │                  Deactivate      │ retained │
                │               ┌─────────────────▶│ 历史可解密 │
                │               ▲                   └──────────┘
                │               │ Reenable             │ Deactivate
                │               │                      ▼
                │               │               ┌──────────────┐
                │               └───────────────│ deactivated  │
                │                               │ 拒绝一切加解密 │
                │                               └──────────────┘
                │                                      │ Retire（仅当无待迁移数据）
                │                                      ▼
                └──────────────────────────────▶ ┌─────────┐
                                                 │ retired │ 密钥材料已销毁，不可逆
                                                 └─────────┘
```

各状态的能力：

| 状态          | 加密（写） | 解密（读历史数据） | 说明                       |
| ------------- | :--------: | :----------------: | -------------------------- |
| `prepared`    |     ✗      |         ✗          | 已生成、未激活             |
| `active`      |     ✓      |         ✓          | 全局唯一，新写入只能用它   |
| `retained`    |     ✗      |         ✓          | 轮换后的旧版本，供历史解密 |
| `deactivated` |     ✗      |         ✗          | 行政停用；可 `Reenable` 恢复为 retained 以完成迁移 |
| `retired`     |     ✗      |         ✗          | 密钥材料已擦除，永久不可解 |

关键规则：

- **新写入必须用当前激活版本。** `Rotate` 原子地「生成新版本 + 激活」，旧
  active 变为 `retained`；任意时刻至多一个 active 版本。
- **旧版本保留期间历史数据必须可解。** active 与 retained 都允许解密。
- **仍需用于读写或迁移未完成的版本不得退役。** `Retire` 仅接受
  `deactivated` 且 `MigrationPending=false` 的版本：
  - 退役 active → `conflict`（应先轮换）；
  - 退役 retained（仍在读）→ `migration_pending`；
  - 退役 deactivated 但仍有记录引用 → `migration_pending`；
  - 迁移全部完成（`MigrateAll` 会清除待迁移标记）后才允许退役。
- 停用后若发现还要做迁移，可调用 `Reenable` 回到 retained（**不改变当前
  active 加密版本**），迁移完成再停用、退役。

## 信封格式

线格式（整数均为大端），格式版本 `1`，魔数 `ENV1`：

| 偏移    | 长度 | 字段                                   |
| ------- | ---: | -------------------------------------- |
| 0       |    4 | 魔数 `ENV1`（同时是格式标识）          |
| 4       |    1 | 信封格式版本，当前 `1`                 |
| 5       |    8 | 包装该数据密钥的主密钥**版本 ID**      |
| 13      |    4 | 已包装数据密钥长度 N                   |
| 17      |    N | 已包装数据密钥 = nonce ‖ AES-256-GCM(32B 数据密钥) |
| 17+N    |   12 | 内层 nonce                             |
| 29+N    |  ... | 内层密文 = AES-256-GCM(明文)           |

信封加密为**双层 AES-256-GCM**：

1. 每条消息生成随机 32 字节数据密钥（DEK），用主密钥版本做外层 GCM 包装；
2. 明文用 DEK 做内层 GCM 加密。

**完整性绑定（AAD）：**

- 外层 GCM 以固定 17 字节头部作为 AAD 认证——头部里的版本号、长度、魔数被
  绑定到「由该主密钥版本包装」这一事实；
- 内层 GCM 以「头部 + 已包装数据密钥」作为 AAD——密文与「它配套的那个数据
  密钥、以及版本号」绑定。

因此下列篡改都会被拒绝，且**错误类别可区分**：

| 攻击 / 异常                                                | 错误类别                |
| ---------------------------------------------------------- | ----------------------- |
| 不是 ENV1、格式版本不符、截断、声明长度越界               | `malformed_metadata`    |
| 翻转密文字节 / 内层 nonce                                  | `tampered_ciphertext`   |
| 把 B 信封（v2 包装的 DEK）拼进 A 信封（头部写 v1）         | `key_mismatch`          |
| 仅把头部版本号改写成 v2，但 DEK 实际由 v1 包装            | `key_mismatch`          |
| 版本不存在                                                 | `version_not_found`     |
| 版本为 deactivated（或 prepared）                          | `version_inactive`      |
| 版本已 retired（材料已销毁）                               | `version_retired`       |
| 退役时仍有数据依赖 / 迁移未完成                            | `migration_pending`     |
| 非法状态流转（如直接退役 active）                          | `conflict`              |
| 其它未预期内部故障                                         | `internal`              |

`Open` 在任何失败时都返回 `nil` 明文（GCM 认证失败不会产出部分明文，代码也不
返回它）。对外只暴露 `apperr.Error`，底层如 `cipher: message authentication
failed` 之类信息仅保留在内部 cause 中供日志使用，不会出现在对外消息里。

## 版本兼容规则

- 信封头部携带**主密钥版本 ID 与信封格式版本**，二者独立：
  - 主密钥版本 ID 决定用哪个主密钥解包 DEK，支持「任意多个历史 retained
    版本并存解密，仅 active 版本加密」；
  - 信封格式版本（当前 1）决定字节布局；`Open` 只接受它能解析的格式版本，
    不识别的格式返回 `malformed_metadata`，绝不做猜测式解析。
- 前向读取：新版本写入用新 active 版本；旧密文只要其版本仍处于
  active/retained 就一直可解。
- 退役是**显式、不可逆**的兼容边界：一旦 `retired`，该版本数据在任何入口都
  不可解（`version_retired`），因此退役前必须先 `MigrateAll` 把数据重写到
  当前 active 版本。
- 密钥存储自身也有 `format_version`；加载未知版本或损坏文件返回
  `malformed_metadata`。

## 并发正确性

- KMS 所有状态操作在互斥锁内完成；`Persist` 采用「写同目录临时文件 → fsync →
  rename」原子替换，读者只能看到上一份或下一份完整存储，不会读到半写文件。
- vault 的记录用 `RWMutex` 保护，密码学运算在锁外进行，结果以单次 map 赋值
  安装：读者要么看到旧 blob、要么看到新 blob，不存在半成品记录。
- 迁移采用 **compare-and-install**：若记录在「读出旧密文 → 重加密 → 装回」
  期间被并发 `Put` 改写，则放弃本次安装并重试，杜绝用过期重加密覆盖新写入；
  超过重试上限返回 `conflict`，且不保留任何部分写入。
- `Seal` 在「选 active 版本 → 包装 DEK」的极小窗口内若撞上轮换（收到
  `version_inactive`）会自动用新 active 重试，因此一次成功的 Seal 必定由当时
  的 active 版本密封，调用方不会看到该竞态。

## 验证方法

```bash
# 1) 全部单测，带竞态检测；测试日志会打印涉及的密钥版本与错误类别
go test ./... -race -count=1 -v

# 2) 压稳并发用例（轮换期并发读写 / 并发 Put 与迁移）
go test ./internal/vault/ ./internal/kms/ -race -count=20

# 3) 端到端生命周期演示
go run ./cmd/demo
```

测试覆盖点（日志中均带版本号与错误类别）：

- `kms`：轮换后历史 DEK 可解、retained 禁止加密；不存在/停用/退役版本解密被
  拒且类别可区分；跨版本解包为 `key_mismatch` 且不泄漏底层错误；**轮换期间
  并发包装**事后全部可解；存储往返与损坏文件拒绝。
- `envelope`：轮换前数据轮换后仍可解；魔数/格式/截断类 `malformed_metadata`；
  翻密文/翻 nonce 为 `tampered_ciphertext`；DEK 拼接与版本号改写为
  `key_mismatch`；停用/退役读取拒绝；失败路径明文为 nil 且无内部错误泄漏。
- `vault`：**轮换期间 8 写 8 读并发**无损坏、无半写，最终值与最后一次写入
  一致；先迁移再停用退役的边界（中途停用读拒绝、退役被 `migration_pending`
  拒绝、`Reenable` 后完成迁移、二次迁移为空操作）；并发 `Put` 与
  `MigrateRecord` 不丢更新。
