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
	// KindStorageCorrupted 本地状态文件被截断、校验和不符或内容无法解析。
	KindStorageCorrupted ErrorKind = "storage_corrupted"
	// KindUnsupportedFormat 状态文件使用了比当前更新或无法识别的格式版本。
	KindUnsupportedFormat ErrorKind = "unsupported_format"
	// KindMigrationConflict 迁移作业的条目与既有作业不一致（重复/多余/重复 ID）。
	KindMigrationConflict ErrorKind = "migration_conflict"
	// KindMigrationNotFound 请求的迁移作业不存在。
	KindMigrationNotFound ErrorKind = "migration_not_found"
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
