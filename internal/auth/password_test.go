package auth_test

import (
	"testing"

	"shiguang-relay/internal/auth"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := auth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !auth.VerifyPassword(hash, "correct horse battery staple") {
		t.Fatal("正确密码应通过校验")
	}
	if auth.VerifyPassword(hash, "wrong password") {
		t.Fatal("错误密码不应通过")
	}
	if auth.VerifyPassword(hash+"x", "correct horse battery staple") {
		t.Fatal("哈希被篡改不应通过")
	}
	if auth.VerifyPassword("not-a-valid-format", "correct horse battery staple") {
		t.Fatal("非法格式哈希不应通过")
	}

	// 每次哈希盐不同：同密码两哈希不同，但均可验过
	hash2, _ := auth.HashPassword("correct horse battery staple")
	if hash == hash2 {
		t.Fatal("同密码两次哈希应不同（随机盐）")
	}
	if !auth.VerifyPassword(hash2, "correct horse battery staple") {
		t.Fatal("第二个哈希应可验过")
	}

	// 空密码也应可哈希可验（业务层另设最小长度约束）
	empty, _ := auth.HashPassword("")
	if !auth.VerifyPassword(empty, "") {
		t.Fatal("空密码哈希应可验过")
	}
	if auth.VerifyPassword(empty, " ") {
		t.Fatal("空密码哈希不应验过其他输入")
	}
}
