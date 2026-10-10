---
name: shiguang-relay-docs
description: 时光中继（shiguang-relay）docs 域表与 lint 落点：api/architecture/deploy 三域划分、lint 脚本、本仓例外。新增/移动/废弃工程文档时先读本 skill。
---

# shiguang-relay-docs（项目 docs 数据）

> 规范机制（frontmatter / 切片命名 / Mermaid / 墓碑 / lint）一律指针到 docs-spec §1–§7，本 skill 只填项目数据。

## 域目录表

| 域目录 | 用途 | 已有文档 |
|---|---|---|
| `docs/api/` | 对外接口契约（客户端对接文档） | `docs/api/user-accounts.md` |
| `docs/architecture/` | 架构决策与总体设计 | `docs/architecture/overview.md`、`docs/architecture/accounts-e2ee-state.md` |
| `docs/deploy/` | 部署运维手册（暂无文档，按需建目录；配置在仓库 `deploy/`） | — |

## lint 脚本

- 全局机械校验：`toolbox run docs-lint`（frontmatter 四字段 + 根目录平铺 + updated 软自查）。
- 本仓无专属 lint 脚本。

## 本仓例外

- 无（存量与 docs-spec 无冲突）。
