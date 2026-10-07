// Package envelope 提供信封加密与主密钥生命周期管理。
package envelope

import "errors"

// ErrorKind 区分对外暴露的错误类别，调用方应通过 KindOf 判定，
// 底层错误细节不会透出到接口之外。
type ErrorKind string

const (
	// KindKeyNotFound 请求的密钥版本不存在。
	KindKeyNotFound ErrorKind = "key_not_found"
	// KindKeyDisabled 请求的密钥版本已停用，不可用于加解密。
	KindKeyDisabled ErrorKind = "key_disabled"
	// KindKeyRetired 请求的密钥版本已退役，密钥材料已销毁。
	KindKeyRetired ErrorKind = "key_retired"
	// KindVersionInUse 版本仍被使用（激活中或仍有未迁移数据），不得退役。
	KindVersionInUse ErrorKind = "version_in_use"
	// KindCiphertextTampered 密文或被包裹的 DEK 完整性校验失败。
	KindCiphertextTampered ErrorKind = "ciphertext_tampered"
	// KindMalformedMetadata 信封元数据格式错误。
	KindMalformedMetadata ErrorKind = "malformed_metadata"
	// KindKeyMismatch 信封引用的密钥版本与解密所用密钥不匹配。
	KindKeyMismatch ErrorKind = "key_mismatch"
	// KindStorageCorrupt 本地持久化状态文件被截断、校验和不符或内容语义损坏。
	KindStorageCorrupt ErrorKind = "storage_corrupt"
	// KindUnsupportedFormat 状态文件格式版本比当前程序支持的更新，拒绝加载。
	KindUnsupportedFormat ErrorKind = "unsupported_format"
	// KindMigrationState 迁移会话状态非法：源版本不可迁移、条目 ID 重复、
	// 已有进行中的同版本迁移等。
	KindMigrationState ErrorKind = "migration_state"
	// KindInternal 内部错误，细节不对外暴露。
	KindInternal ErrorKind = "internal"
)

// Error 是对外暴露的统一错误类型。
type Error struct {
	Kind    ErrorKind
	Version uint64 // 涉及的密钥版本，未知时为 0
	msg     string
}

func (e *Error) Error() string { return string(e.Kind) + ": " + e.msg }

// KindOf 从 error 中提取错误类别；非本包错误归为 KindInternal。
func KindOf(err error) ErrorKind {
	var ee *Error
	if errors.As(err, &ee) {
		return ee.Kind
	}
	return KindInternal
}

func newError(kind ErrorKind, version uint64, msg string) *Error {
	return &Error{Kind: kind, Version: version, msg: msg}
}
