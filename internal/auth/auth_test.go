package auth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"shiguang-relay/internal/auth"
)

func TestVerifyPoP(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	nonce := "deadbeef-nonce"
	sig := ed25519.Sign(priv, []byte(nonce))

	if !auth.VerifyPoP(pub, sig, nonce) {
		t.Fatal("合法签名应通过")
	}
	if auth.VerifyPoP(pub, sig, nonce+"x") {
		t.Fatal("消息被篡改不应通过")
	}
	if auth.VerifyPoP(pub[:10], sig, nonce) {
		t.Fatal("公钥长度非法应拒绝")
	}
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if auth.VerifyPoP(otherPub, sig, nonce) {
		t.Fatal("换公钥不应通过")
	}
	if auth.VerifyPoP(pub, sig[:10], nonce) {
		t.Fatal("签名长度非法应拒绝")
	}
}

func TestVerifyPoW(t *testing.T) {
	const difficulty = 3
	var solution string
	for i := 0; ; i++ {
		solution = string(rune('a'+i%26)) + time.Now().Format("150405.000000000") + string(rune('0'+i%10))
		if auth.VerifyPoW("challenge-1", solution, difficulty) {
			break
		}
		if i > 2_000_000 {
			t.Skip("难度 3 采样失败（不应发生）")
		}
	}
	if !auth.VerifyPoW("challenge-1", solution, difficulty) {
		t.Fatal("已求解的 PoW 应通过")
	}
	if auth.VerifyPoW("challenge-2", solution, difficulty) {
		t.Fatal("换题面不应通过")
	}
	if !auth.VerifyPoW("challenge-1", "whatever", 0) {
		t.Fatal("难度 0 = 关闭校验")
	}
}

func TestIssuerRoundTrip(t *testing.T) {
	iss := auth.NewIssuer([]byte("test-secret-test-secret-test-secret"), time.Hour, 24*time.Hour)
	pair, err := iss.Issue(context.Background(), "user-1")
	if err != nil {
		t.Fatal(err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("双 Token 均应签发")
	}
	sub, err := iss.Verify(pair.AccessToken, "access")
	if err != nil || sub != "user-1" {
		t.Fatalf("access 校验失败: %v sub=%q", err, sub)
	}
	if _, err := iss.Verify(pair.AccessToken, "refresh"); err == nil {
		t.Fatal("access 不得当 refresh 用")
	}
	if _, err := iss.Verify(pair.RefreshToken, "access"); err == nil {
		t.Fatal("refresh 不得当 access 用")
	}
	other := auth.NewIssuer([]byte("another-secret-another-secret-xxxx"), time.Hour, 24*time.Hour)
	if _, err := other.Verify(pair.AccessToken, "access"); err == nil {
		t.Fatal("换密钥签发的 token 必须失效")
	}
	if _, err := iss.Verify("garbage.token.value", "access"); err == nil {
		t.Fatal("畸形 token 必须拒绝")
	}
}
