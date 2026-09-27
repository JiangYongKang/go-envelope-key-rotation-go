package envelope

import (
	"bytes"
	"fmt"
	"sync"
	"testing"
)

// logKind 统一打印涉及的密钥版本与错误类别。
func logKind(t *testing.T, op string, version uint64, err error) {
	t.Helper()
	if err == nil {
		t.Logf("op=%s version=%d result=ok", op, version)
		return
	}
	t.Logf("op=%s version=%d kind=%s err=%v", op, version, KindOf(err), err)
}

func newServiceWithKey(t *testing.T) (*Service, uint64) {
	t.Helper()
	s := NewService(NewLocalKeyStore())
	v, err := s.Rotate()
	if err != nil {
		t.Fatalf("initial rotate: %v", err)
	}
	return s, v
}

// TestRotateDecryptsOldData 验证轮换前写入的数据在旧版本保留时仍可解密，
// 且新写入使用新激活版本。
func TestRotateDecryptsOldData(t *testing.T) {
	s, v1 := newServiceWithKey(t)

	oldCT, err := s.Encrypt([]byte("before-rotation"))
	if err != nil {
		t.Fatalf("encrypt with v%d: %v", v1, err)
	}

	v2, err := s.Rotate()
	logKind(t, "rotate", v2, err)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if v2 == v1 {
		t.Fatalf("expected new version, got %d again", v2)
	}

	newCT, err := s.Encrypt([]byte("after-rotation"))
	if err != nil {
		t.Fatalf("encrypt with v%d: %v", v2, err)
	}
	env, err := decode(newCT)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Version != v2 {
		t.Fatalf("new write used version %d, want %d", env.Version, v2)
	}
	t.Logf("op=encrypt version=%d result=ok (post-rotation write)", env.Version)

	pt, err := s.Decrypt(oldCT)
	logKind(t, "decrypt-old", v1, err)
	if err != nil || string(pt) != "before-rotation" {
		t.Fatalf("decrypt pre-rotation data: pt=%q err=%v", pt, err)
	}
	pt, err = s.Decrypt(newCT)
	logKind(t, "decrypt-new", v2, err)
	if err != nil || string(pt) != "after-rotation" {
		t.Fatalf("decrypt post-rotation data: pt=%q err=%v", pt, err)
	}
}

// TestDecryptUnavailableVersions 验证已退役与不存在版本的解密请求被可区分地拒绝。
func TestDecryptUnavailableVersions(t *testing.T) {
	s, v1 := newServiceWithKey(t)
	ct, err := s.Encrypt([]byte("doomed"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	if _, err := s.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	s.Forget(v1)
	if err := s.Retire(v1); err != nil {
		t.Fatalf("retire v%d: %v", v1, err)
	}

	if _, err := s.Decrypt(ct); KindOf(err) != KindKeyRetired {
		t.Fatalf("retired version: got kind %s, want %s", KindOf(err), KindKeyRetired)
	}
	logKind(t, "decrypt-retired", v1, s.lastErr(ct))

	// 已停用（disabled）版本：轮换后手动停用，解密须被拒绝且类别可区分。
	s2, w1 := newServiceWithKey(t)
	ct2, err := s2.Encrypt([]byte("about to be disabled"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := s2.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// 停用前（deactivated）仍可解密。
	if _, err := s2.Decrypt(ct2); err != nil {
		t.Fatalf("decrypt deactivated v%d: %v", w1, err)
	}
	if err := s2.store.Deactivate(w1); err != nil {
		t.Fatalf("deactivate v%d: %v", w1, err)
	}
	_, err = s2.Decrypt(ct2)
	logKind(t, "decrypt-disabled", w1, err)
	if KindOf(err) != KindKeyDisabled {
		t.Fatalf("disabled version: got kind %s, want %s", KindOf(err), KindKeyDisabled)
	}

	// 不存在的版本：篡改信封中的版本号。
	env, _ := decode(ct)
	env.Version = 9999
	raw, _ := encode(env)
	if _, err := s.Decrypt(raw); KindOf(err) != KindKeyNotFound {
		t.Fatalf("unknown version: got kind %s, want %s", KindOf(err), KindKeyNotFound)
	}
	logKind(t, "decrypt-unknown", 9999, s.lastErr(raw))
}

// lastErr 返回解密错误（用于日志），测试辅助。
func (s *Service) lastErr(raw []byte) error {
	_, err := s.Decrypt(raw)
	return err
}

// TestTamperAndMismatch 验证篡改密文、格式错误元数据与密钥不匹配映射为可区分错误，
// 且失败路径不返回部分明文。
func TestTamperAndMismatch(t *testing.T) {
	s, v1 := newServiceWithKey(t)
	ct, err := s.Encrypt([]byte("integrity matters"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	env, _ := decode(ct)

	// 1. 篡改密文。
	tampered := *env
	tampered.Data = append([]byte(nil), env.Data...)
	tampered.Data[0] ^= 0xff
	raw, _ := encode(&tampered)
	pt, err := s.Decrypt(raw)
	logKind(t, "decrypt-tampered-data", v1, err)
	if KindOf(err) != KindCiphertextTampered || pt != nil {
		t.Fatalf("tampered data: kind=%s pt=%v", KindOf(err), pt)
	}

	// 2. 篡改被包裹的 DEK。
	tampered = *env
	tampered.Wrapped = append([]byte(nil), env.Wrapped...)
	tampered.Wrapped[0] ^= 0xff
	raw, _ = encode(&tampered)
	pt, err = s.Decrypt(raw)
	logKind(t, "decrypt-tampered-wrapped", v1, err)
	if KindOf(err) != KindCiphertextTampered || pt != nil {
		t.Fatalf("tampered wrapped: kind=%s pt=%v", KindOf(err), pt)
	}

	// 3. 格式错误的元数据。
	pt, err = s.Decrypt([]byte("{not-json"))
	logKind(t, "decrypt-malformed", 0, err)
	if KindOf(err) != KindMalformedMetadata || pt != nil {
		t.Fatalf("malformed: kind=%s pt=%v", KindOf(err), pt)
	}
	envBad := *env
	envBad.Magic = "env9"
	raw, _ = encode(&envBad)
	if _, err = s.Decrypt(raw); KindOf(err) != KindMalformedMetadata {
		t.Fatalf("bad magic: kind=%s", KindOf(err))
	}
	logKind(t, "decrypt-bad-magic", v1, err)

	// 4. 密钥不匹配：用 v1 的密钥材料伪造 v2 版本的信封。
	v2, err := s.Rotate()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	kekV1, err := s.store.decryptKey(v1)
	if err != nil {
		t.Fatalf("get v1 key: %v", err)
	}
	forged, err := encrypt(v2, kekV1, []byte("forged"))
	if err != nil {
		t.Fatalf("forge: %v", err)
	}
	raw, _ = encode(forged)
	pt, err = s.Decrypt(raw)
	logKind(t, "decrypt-key-mismatch", v2, err)
	if KindOf(err) != KindKeyMismatch || pt != nil {
		t.Fatalf("key mismatch: kind=%s pt=%v", KindOf(err), pt)
	}
}

// TestRetireBoundaries 验证停用与退役的边界条件。
func TestRetireBoundaries(t *testing.T) {
	s, v1 := newServiceWithKey(t)
	if _, err := s.Encrypt([]byte("pinned")); err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// 激活版本不得退役。
	err := s.Retire(v1)
	logKind(t, "retire-active", v1, err)
	if KindOf(err) != KindVersionInUse {
		t.Fatalf("retire active: kind=%s", KindOf(err))
	}
	// 激活版本不得直接停用。
	err = s.store.Deactivate(v1)
	logKind(t, "deactivate-active", v1, err)
	if KindOf(err) != KindVersionInUse {
		t.Fatalf("deactivate active: kind=%s", KindOf(err))
	}

	v2, err := s.Rotate()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// 仍有未迁移数据，不得退役。
	err = s.Retire(v1)
	logKind(t, "retire-with-refs", v1, err)
	if KindOf(err) != KindVersionInUse {
		t.Fatalf("retire with refs: kind=%s", KindOf(err))
	}

	// 迁移完成后可退役。
	s.Forget(v1)
	if err := s.Retire(v1); err != nil {
		t.Fatalf("retire after forget: %v", err)
	}
	logKind(t, "retire", v1, nil)
	if st, _ := s.store.State(v1); st != StateRetired {
		t.Fatalf("state=%s, want retired", st)
	}

	// 重复退役与退役不存在的版本。
	err = s.Retire(v1)
	logKind(t, "retire-again", v1, err)
	if KindOf(err) != KindKeyRetired {
		t.Fatalf("re-retire: kind=%s", KindOf(err))
	}
	err = s.Retire(4242)
	logKind(t, "retire-missing", 4242, err)
	if KindOf(err) != KindKeyNotFound {
		t.Fatalf("retire missing: kind=%s", KindOf(err))
	}

	// 已停用版本仍可解密（退役前）。
	s2, w1 := newServiceWithKey(t)
	ct, _ := s2.Encrypt([]byte("still readable"))
	if _, err := s2.Rotate(); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if st, _ := s2.store.State(w1); st != StateDeactivated {
		t.Fatalf("old version state=%s, want deactivated", st)
	}
	pt, err := s2.Decrypt(ct)
	logKind(t, "decrypt-deactivated", w1, err)
	if err != nil || string(pt) != "still readable" {
		t.Fatalf("decrypt deactivated: pt=%q err=%v", pt, err)
	}
	_ = v2
}

// TestConcurrentRotateReadWrite 在轮换期间并发读写：
// 所有成功写入的密文必须可解密且内容一致，不得出现半写或静默失败。
func TestConcurrentRotateReadWrite(t *testing.T) {
	s, _ := newServiceWithKey(t)

	const writers = 8
	const perWriter = 50

	var producers sync.WaitGroup
	errCh := make(chan error, writers*perWriter*2)
	ctCh := make(chan []byte, writers*perWriter)

	// 写方。
	for w := 0; w < writers; w++ {
		producers.Add(1)
		go func(w int) {
			defer producers.Done()
			for i := 0; i < perWriter; i++ {
				msg := []byte(fmt.Sprintf("w%d-%d", w, i))
				ct, err := s.Encrypt(msg)
				if err != nil {
					errCh <- fmt.Errorf("encrypt: %w", err)
					return
				}
				ctCh <- ct
			}
		}(w)
	}
	// 轮换方：写入期间连续轮换多次。
	producers.Add(1)
	go func() {
		defer producers.Done()
		for i := 0; i < 5; i++ {
			v, err := s.Rotate()
			t.Logf("op=rotate version=%d err=%v", v, err)
			if err != nil {
				errCh <- fmt.Errorf("rotate: %w", err)
				return
			}
		}
	}()
	// 写方与轮换方全部结束后关闭通道，通知读方退出。
	go func() {
		producers.Wait()
		close(ctCh)
	}()

	// 读方：边写边解密，验证内容与版本一致性。
	var readerWG sync.WaitGroup
	for r := 0; r < 2; r++ {
		readerWG.Add(1)
		go func() {
			defer readerWG.Done()
			for ct := range ctCh {
				env, err := decode(ct)
				if err != nil {
					errCh <- fmt.Errorf("decode: %w", err)
					continue
				}
				pt, err := s.Decrypt(ct)
				if err != nil {
					errCh <- fmt.Errorf("decrypt version=%d kind=%s: %w", env.Version, KindOf(err), err)
					continue
				}
				if !bytes.HasPrefix(pt, []byte("w")) {
					errCh <- fmt.Errorf("corrupt plaintext %q (version=%d)", pt, env.Version)
				}
			}
		}()
	}
	readerWG.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// TestConcurrentRetire 在并发读写期间尝试退役：
// 仍有引用的版本必须被拒绝（KindVersionInUse），
// 且所有成功写入的密文都可解密，无静默失败。
func TestConcurrentRetire(t *testing.T) {
	s, v1 := newServiceWithKey(t)

	const writers = 4
	const perWriter = 30

	var producers sync.WaitGroup
	errCh := make(chan error, writers*perWriter*2)
	ctCh := make(chan []byte, writers*perWriter)

	for w := 0; w < writers; w++ {
		producers.Add(1)
		go func(w int) {
			defer producers.Done()
			for i := 0; i < perWriter; i++ {
				ct, err := s.Encrypt([]byte(fmt.Sprintf("r%d-%d", w, i)))
				if err != nil {
					errCh <- fmt.Errorf("encrypt: %w", err)
					return
				}
				ctCh <- ct
			}
		}(w)
	}
	// 退役方：持续尝试退役各版本，预期在引用清零前均被拒绝。
	producers.Add(1)
	go func() {
		defer producers.Done()
		for i := 0; i < 20; i++ {
			for v := uint64(1); v <= v1; v++ {
				err := s.Retire(v)
				if err != nil && KindOf(err) != KindVersionInUse {
					errCh <- fmt.Errorf("retire v%d unexpected kind=%s: %w", v, KindOf(err), err)
				}
			}
		}
	}()
	go func() {
		producers.Wait()
		close(ctCh)
	}()

	var readerWG sync.WaitGroup
	readerWG.Add(1)
	go func() {
		defer readerWG.Done()
		for ct := range ctCh {
			env, err := decode(ct)
			if err != nil {
				errCh <- fmt.Errorf("decode: %w", err)
				continue
			}
			if _, err := s.Decrypt(ct); err != nil {
				errCh <- fmt.Errorf("decrypt version=%d kind=%s: %w", env.Version, KindOf(err), err)
			}
		}
	}()
	readerWG.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	// 轮换到新版本后写入一条数据，其引用清零后退役应成功，
	// 此后解密该版本数据须得到 KindKeyRetired。
	v2, err := s.Rotate()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	ct, err := s.Encrypt([]byte("last one"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	env, _ := decode(ct)
	if env.Version != v2 {
		t.Fatalf("envelope version=%d, want %d", env.Version, v2)
	}
	// 再轮换一次使 v2 停用，引用清零后即可退役。
	if _, err := s.Rotate(); err != nil {
		t.Fatalf("second rotate: %v", err)
	}
	s.Forget(env.Version)
	if err := s.Retire(env.Version); err != nil {
		t.Fatalf("retire v%d after drain: %v", env.Version, err)
	}
	_, err = s.Decrypt(ct)
	logKind(t, "decrypt-after-retire", env.Version, err)
	if KindOf(err) != KindKeyRetired {
		t.Fatalf("decrypt after retire: kind=%s, want %s", KindOf(err), KindKeyRetired)
	}
}
