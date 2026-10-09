package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// VerifyPoW：Hashcash 校验 —— SHA-256(challenge + solution) 的十六进制串前导 '0' 个数不少于难度。
//
// 定位（fact 草案 §7.1-2）：PoW 只挡最低级扫描器，真防线是「注册孤岛无害化 + 单 IP 限流 + OPK 瘦身」；
// 难度默认 4（≈2^16 次尝试，手机端 <50ms）。难度>8 会明显拖慢低端机，配置层已硬限。
func VerifyPoW(challenge, solution string, difficulty int) bool {
	if difficulty <= 0 {
		return true
	}
	sum := sha256.Sum256([]byte(challenge + solution))
	hexSum := hex.EncodeToString(sum[:])
	return strings.HasPrefix(hexSum, strings.Repeat("0", difficulty))
}
