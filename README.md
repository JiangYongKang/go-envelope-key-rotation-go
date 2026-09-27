# go-envelope-key-rotation-go

信封加密（Envelope Encryption）与主密钥生命周期管理。以本地内存密钥存储
（`LocalKeyStore`）模拟受管密钥服务（KMS），保证密钥轮换、历史数据解密与
并发读写在各入口下行为一致且失败原因可区分。

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
| `internal` | 内部错误 |

解密顺序：先校验元数据格式（`malformed_metadata`）→ 查密钥版本
（`key_not_found` / `key_retired`）→ 校验密钥承诺（`key_mismatch`）→
GCM 完整性校验（`ciphertext_tampered`）。任何失败路径都不返回部分明文。

兼容规则：同一 `magic`（`env1`）内，任意历史版本写入的信封在其密钥版本
未被退役前均可解密；退役后该版本数据视为已迁移完毕，解密被明确拒绝。

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
