package auth

import (
	"bytes"
	"crypto/ed25519"
)

// VerifyPoP：所有权证明验签 —— 客户端用身份私钥对 nonce 签名，服务端用库内公钥验证。
//
// 签名消息体：nonce 原样字节串（设计稿 §1.4：Sign(Nonce) with IK）。双端必须同口径，
// 任何「顺手加时间戳/加路径」都会让对端验签失败。
func VerifyPoP(identityPub, sig []byte, nonce string) bool {
	if len(identityPub) != ed25519.PublicKeySize {
		return false
	}
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(identityPub), []byte(nonce), sig)
}

// EqualID：常量时间比较 user_id，避免时序侧信道。
func EqualID(a, b string) bool {
	return bytes.Equal([]byte(a), []byte(b))
}
