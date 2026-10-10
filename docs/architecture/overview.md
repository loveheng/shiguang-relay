---
status: active
updated: 2026-10-11
---

# 架构导览（一句话级）

> 详细契约见 [api/user-accounts.md](../api/user-accounts.md)；本页只做方向性导览，与主 README 互为入口。

时光中继是**盲状态机 E2EE 中继**：服务端只转发密文与托管公钥（Ed25519 身份钥 + X25519 预密钥 + OPK 池构成 X3DH 素材），永远接触不到明文业务数据。

身份模型（Plan A）：`username + password` 构成用户唯一面对的账号体系（密码仅鉴权，PBKDF2 哈希落库）；E2EE 密钥由端侧生成并持有，对用户完全透明——注册时自动上传公钥材料，换设备用端侧 `recovery_vault` 恢复，服务端纯盲。

数据通道：REST（`/v1/*`）承载注册/登录/好友/密钥托管/信封/中继收发；WSS（`/ws`）承载长连接与推送，AUTH 用 JSON 帧。
