---
dev-loop: devlog
format: v1
epic: misc
total-merged: 0
last-merge: none
---

（散修/小改动按行追加；≥5 条自动归并进 memory.md）
- 2026-10-25 sim_activity 8 项缺陷评估收口（v0.1.10-contract）：#2/#3/#4最小/#6/#7/#8 修复+测试，#5 quorum 改判 OBSERVATION（§4.1 留痕），#1 base_revision 挂账待拍板（context/todos.md 两案）；REOPEN 仅 CONFIRMED 放行补齐（REOPEN_INVALID_STATE）；PG 集成全绿，sim DEFECT 0/OBSERVATION 5（两条 401 注册探针为既有现象）；主仓设计稿 §7 台账第 9 条留痕。注意：本轮曾与另一并行窗口同写本仓，经用户裁决由本窗口接管收尾。
- 2026-10-25 base_revision 选案 A 实装（用户拍板）：每非事实动作自增 + opt-in 校验 + 事实豁免；sim 探针转正、专项 PG 测试落地；主仓 §5.4/§7/schema 注释三处同步，README 契约账 ⑥ 销账。
