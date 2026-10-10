package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// 密码哈希：PBKDF2-HMAC-SHA256（纯标准库实现，零外部依赖）。
//
// 选型说明：x/crypto/argon2 不可用时退而用 PBKDF2（CPU 密集型、每用户独立盐，
// 配高迭代次数 ≥20万，足以抵御离线暴力）。格式自描述，便于未来平滑迁移 Argon2id：
//
//	$pbkdf2-sha256$i=<iterations>$<b64salt>$<b64hash>
//
// 服务端仅存此哈希，恒零明文密码；与 E2EE 身份密钥解耦（Plan A：密码只做鉴权，
// 不托管私钥，故改密不动端侧密钥）。
const (
	pbkdf2Iterations = 200_000
	pbkdf2KeyLen     = 32
	pbkdf2SaltLen    = 16
	pbkdf2Prefix     = "$pbkdf2-sha256$"
)

// HashPassword：对明文密码派生加盐哈希，返回自描述存储串。
func HashPassword(password string) (string, error) {
	salt := make([]byte, pbkdf2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("生成盐失败: %w", err)
	}
	hash := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyLen)
	return fmt.Sprintf("%si=%d$%s$%s", pbkdf2Prefix, pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

// VerifyPassword：恒定时间比对存储哈希与待验密码。
func VerifyPassword(storedHash, password string) bool {
	parts := strings.Split(storedHash, "$")
	// ["", "pbkdf2-sha256", "i=200000", salt, hash]
	if len(parts) != 5 || parts[1] != "pbkdf2-sha256" {
		return false
	}
	var iter int
	if _, err := fmt.Sscanf(parts[2], "i=%d", &iter); err != nil || iter <= 0 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) == 0 {
		return false
	}
	expect, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(expect) == 0 {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, iter, len(expect))
	return hmac.Equal(got, expect)
}

// pbkdf2SHA256：RFC 8018 PBKDF2 的 HMAC-SHA256 实现（密码恒作 HMAC key，消息逐轮变化）。
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	hLen := sha256.Size
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	for i := 1; i <= blocks; i++ {
		m := hmac.New(sha256.New, password)
		m.Write(salt)
		m.Write([]byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)})
		u := m.Sum(nil)
		t := append([]byte(nil), u...)
		for j := 2; j <= iter; j++ {
			m.Reset()
			m.Write(u)
			u = m.Sum(nil)
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
