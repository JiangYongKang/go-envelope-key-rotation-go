package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
)

// 信封格式（JSON 序列化）：
//
//	magic    : 固定标识 "env1"，用于识别信封格式版本
//	version  : 用于包裹 DEK 的主密钥版本
//	keycheck : 主密钥承诺值 HMAC-SHA256(kek, "env1/keycheck") 截断，
//	           用于在解包前区分“密钥不匹配”与“密文被篡改”
//	wrapped  : 主密钥以 AES-GCM 包裹（加密）的数据加密密钥 DEK
//	wrapnonce: 包裹 DEK 时使用的随机 nonce
//	datanonce: 加密数据时使用的随机 nonce
//	data     : 以 DEK 通过 AES-GCM 加密的密文（含认证标签）
const (
	envelopeMagic = "env1"
	nonceSize     = 12
	keyCheckSize  = 16
)

// Envelope 是一条密文记录及其元数据。
type Envelope struct {
	Magic     string `json:"magic"`
	Version   uint64 `json:"version"`
	KeyCheck  []byte `json:"keycheck"`
	Wrapped   []byte `json:"wrapped"`
	WrapNonce []byte `json:"wrapnonce"`
	DataNonce []byte `json:"datanonce"`
	Data      []byte `json:"data"`
}

// aad 将格式标识与密钥版本绑定为 GCM 附加认证数据，
// 使元数据篡改同样导致完整性校验失败。
func aad(version uint64) []byte {
	b := make([]byte, 0, len(envelopeMagic)+8)
	b = append(b, envelopeMagic...)
	return binary.BigEndian.AppendUint64(b, version)
}

// keyCommitment 计算主密钥承诺值。
func keyCommitment(kek []byte) []byte {
	mac := hmac.New(sha256.New, kek)
	mac.Write([]byte("env1/keycheck"))
	return mac.Sum(nil)[:keyCheckSize]
}

// encode 将信封序列化为字节流。
func encode(e *Envelope) ([]byte, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return nil, newError(KindInternal, e.Version, "encode envelope failed")
	}
	return raw, nil
}

// decode 解析并校验信封元数据格式，格式错误返回 KindMalformedMetadata。
func decode(raw []byte) (*Envelope, error) {
	var e Envelope
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, newError(KindMalformedMetadata, 0, "envelope is not valid json")
	}
	bad := func(msg string) (*Envelope, error) {
		return nil, newError(KindMalformedMetadata, e.Version, msg)
	}
	if e.Magic != envelopeMagic {
		return bad("unknown envelope magic")
	}
	if e.Version == 0 {
		return bad("missing key version")
	}
	if len(e.KeyCheck) != keyCheckSize {
		return bad("invalid keycheck length")
	}
	if len(e.WrapNonce) != nonceSize || len(e.DataNonce) != nonceSize {
		return bad("invalid nonce length")
	}
	if len(e.Wrapped) == 0 || len(e.Data) == 0 {
		return bad("missing wrapped key or ciphertext")
	}
	return &e, nil
}

// newGCM 基于密钥材料构造 AES-GCM，密钥长度错误映射为内部错误。
func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, newError(KindInternal, 0, "invalid key material")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, newError(KindInternal, 0, "gcm init failed")
	}
	return gcm, nil
}

// encrypt 使用指定版本的主密钥加密明文，生成信封。
func encrypt(version uint64, kek, plaintext []byte) (*Envelope, error) {
	dek := make([]byte, keySize)
	wrapNonce := make([]byte, nonceSize)
	dataNonce := make([]byte, nonceSize)
	if _, err := rand.Read(dek); err != nil {
		return nil, newError(KindInternal, version, "dek generation failed")
	}
	if _, err := rand.Read(wrapNonce); err != nil {
		return nil, newError(KindInternal, version, "nonce generation failed")
	}
	if _, err := rand.Read(dataNonce); err != nil {
		return nil, newError(KindInternal, version, "nonce generation failed")
	}

	kekGCM, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	dekGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}

	return &Envelope{
		Magic:     envelopeMagic,
		Version:   version,
		KeyCheck:  keyCommitment(kek),
		Wrapped:   kekGCM.Seal(nil, wrapNonce, dek, aad(version)),
		WrapNonce: wrapNonce,
		DataNonce: dataNonce,
		Data:      dekGCM.Seal(nil, dataNonce, plaintext, aad(version)),
	}, nil
}

// decrypt 使用指定版本的主密钥解密信封；
// 任何失败路径都不会返回部分明文。
func decrypt(version uint64, kek []byte, e *Envelope) ([]byte, error) {
	// 先校验密钥承诺：密钥不匹配与密文篡改由此区分。
	if !hmac.Equal(keyCommitment(kek), e.KeyCheck) {
		return nil, newError(KindKeyMismatch, version, "key does not match envelope commitment")
	}

	kekGCM, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	dek, err := kekGCM.Open(nil, e.WrapNonce, e.Wrapped, aad(e.Version))
	if err != nil {
		return nil, newError(KindCiphertextTampered, version, "wrapped dek integrity check failed")
	}
	defer func() {
		for i := range dek {
			dek[i] = 0
		}
	}()

	dekGCM, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	plaintext, err := dekGCM.Open(nil, e.DataNonce, e.Data, aad(e.Version))
	if err != nil {
		return nil, newError(KindCiphertextTampered, version, "ciphertext integrity check failed")
	}
	return plaintext, nil
}
