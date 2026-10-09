package auth

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

// FriendshipTicket：好友名片凭证的验签口径（协同设计 §1.6 / proto FriendshipTicket）。
//
// 防篡改签名覆盖范围 = 下列规范化字符串（双端必须一字不差，否则跨端验签必失败）：
//   shiguang.relay.v1/friendship-ticket|<issuer_user_id>|<subject_user_id>|<nonce>|<expires_at>
// subject_user_id 可空（任意扫码者），此时该段为空串。
type FriendshipTicket struct {
	IssuerUserID  string // B：Ticket 签发人（被加者）
	SubjectUserID string // A：被指定可扫码者，可空
	Nonce         string
	ExpiresAt     int64
	Signature     []byte
	EncKeyPub     []byte // B 的 X25519 加密公钥（ECIES 自报家门用，服务端不解析）
}

func TicketMessage(t FriendshipTicket) string {
	return fmt.Sprintf("shiguang.relay.v1/friendship-ticket|%s|%s|%s|%d",
		t.IssuerUserID, t.SubjectUserID, t.Nonce, t.ExpiresAt)
}

// VerifyFriendshipTicket：用签发人身份公钥验签 + 校验未过期。
// 返回（签名有效，是否过期）——分开返回以便接口层给出不同错误码（TICKET_SIGNATURE_INVALID / TICKET_EXPIRED）。
func VerifyFriendshipTicket(issuerPub ed25519.PublicKey, t FriendshipTicket) (sigOK, expired bool) {
	if len(issuerPub) != ed25519.PublicKeySize || len(t.Signature) != ed25519.SignatureSize {
		return false, false
	}
	if !ed25519.Verify(issuerPub, []byte(TicketMessage(t)), t.Signature) {
		return false, false
	}
	return true, time.Now().Unix() > t.ExpiresAt
}
