---
memo: done
format: v2
---

# 完成列表

## misc

- [done] (proj: shiguang-relay) 2026-10-25 base_revision 选案 A 实装（v0.1.10-contract ⑥，2026-10-25 用户拍板）：定型 bundle 级结构版本——每非事实动作自增 1（失败不推进）、`expected_revision` opt-in 校验（客户端仅整体重构/结构变更类携带）、事实三动作豁免维持；靶向实体级冲突判定归端侧 FSM。bundles.go 已自增，sim 探针转正 + 专项 TestBaseRevisionBundleLevelOptIn，主仓 §5.4 表述与 §7 台账 ⑥ 同步，schema.sql 注释对齐。
