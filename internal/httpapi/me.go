package httpapi

import (
	"encoding/base64"
	"net/http"

	"shiguang-relay/internal/apierr"
	"shiguang-relay/internal/auth"
)

// 自账户端点（Plan A）：
//   - GET /v1/users/me：读回自身份——换机恢复链路的最后一环
//     （recovery_vault 此前只写不读，新设备登录后无处取金库，E2EE 密钥恢复链路断裂）；
//   - PATCH /v1/users/me：更新 encrypted_profile / push_token（均为端侧语义字段，服务端纯盲）。
//
// 铁律延续：服务端不解密任何密文；错误通道零明文（§10.4）。

// 字段大小护栏（防单行膨胀；真硬限仍是 256KB 请求体上限）：
const (
	maxProfileCiphertextBytes = 64 * 1024  // encrypted_profile 密文上限
	maxVaultCiphertextBytes   = 128 * 1024 // recovery_vault 金库密文上限（内含主钥封送包裹，放宽于 profile）
	maxPushTokenLen           = 4096       // FCM/APNs token 实际均 <4KB
)

type updateSelfReq struct {
	EncryptedProfile *string `json:"encrypted_profile,omitempty"` // base64；缺省不动，present 即替换
	RecoveryVault    *string `json:"recovery_vault,omitempty"`    // base64；缺省不动，present 即替换（可清空）
	PushToken        *string `json:"push_token,omitempty"`        // 缺省不动；present 空串即清空
}

func (d Deps) handleGetMe(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	self, found, err := d.Users.SelfIdentity(r.Context(), caller)
	if err != nil {
		apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to load self identity", nil)
		return
	}
	if !found {
		// Bearer 合法但用户已不在（如 DB 被人工清理）——按未鉴权处理，不泄露细节
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "unknown caller", nil)
		return
	}
	resp := map[string]any{
		"user_id":    self.UserID,
		"username":   self.Username,
		"created_at": self.CreatedAt.Unix(),
	}
	if len(self.EncryptedProfile) > 0 {
		resp["encrypted_profile"] = b64(self.EncryptedProfile)
	}
	if len(self.RecoveryVault) > 0 {
		resp["recovery_vault"] = b64(self.RecoveryVault)
	}
	apierr.WriteJSON(w, http.StatusOK, resp)
}

func (d Deps) handleUpdateMe(w http.ResponseWriter, r *http.Request) {
	caller := auth.UserIDFromContext(r.Context())
	if caller == "" {
		apierr.Write(w, http.StatusUnauthorized, apierr.Unauthorized, "missing bearer access token", nil)
		return
	}
	var req updateSelfReq
	if !decode(w, r, &req) {
		return
	}
	if req.EncryptedProfile == nil && req.RecoveryVault == nil && req.PushToken == nil {
		apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "nothing to update", nil)
		return
	}

	if req.EncryptedProfile != nil {
		profile, err := base64.StdEncoding.DecodeString(*req.EncryptedProfile)
		if err != nil {
			apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "encrypted_profile must be base64", nil)
			return
		}
		if len(profile) > maxProfileCiphertextBytes {
			apierr.Write(w, http.StatusRequestEntityTooLarge, apierr.PayloadOversize,
				"encrypted_profile too large", map[string]any{"max_bytes": maxProfileCiphertextBytes})
			return
		}
		if err := d.Users.UpdateEncryptedProfile(r.Context(), caller, profile); err != nil {
			apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to update profile", nil)
			return
		}
	}

	if req.PushToken != nil {
		if len(*req.PushToken) > maxPushTokenLen {
			apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "push_token too long", nil)
			return
		}
		if err := d.Users.UpdatePushToken(r.Context(), caller, *req.PushToken); err != nil {
			apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to update push token", nil)
			return
		}
	}

	if req.RecoveryVault != nil {
		vault, err := base64.StdEncoding.DecodeString(*req.RecoveryVault)
		if err != nil {
			apierr.Write(w, http.StatusBadRequest, apierr.InvalidRequest, "recovery_vault must be base64", nil)
			return
		}
		if len(vault) > maxVaultCiphertextBytes {
			apierr.Write(w, http.StatusRequestEntityTooLarge, apierr.PayloadOversize,
				"recovery_vault too large", map[string]any{"max_bytes": maxVaultCiphertextBytes})
			return
		}
		// 端侧责任红线：金库包裹钥必须独立于登录密码（改密不解密金库，无需因改密重包裹）
		if err := d.Users.UpdateRecoveryVault(r.Context(), caller, vault); err != nil {
			apierr.Write(w, http.StatusInternalServerError, apierr.Internal, "failed to update recovery vault", nil)
			return
		}
	}

	apierr.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}
