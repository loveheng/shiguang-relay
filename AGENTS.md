# AGENTS.md

## 会话初始化（新窗口开场执行一次）

- 开场含「继续/开工/初始化」或首次指令时：先跑 `toolbox run-hooks bootstrap --quiet`（非 0 仅附一行 ⚠，不阻塞；无 toolbox 跳过）→ 跑 `toolbox run panel`（无 toolbox 则读 context/CURRENT → 绑定 epic 的 memory.md 断点）→ 输出会话绑定卡（域/类型/挂载/任务全景/状态）→ 按断点开工或等指令；多任务切换 `::board`（绑定纪律与恢复规约：~/.agents/skills/dev-loop/SKILL.md §3，存在时以其为准）
- CURRENT 缺失/none → 列 context/epics/ 候选请用户选，严禁自选开工；无 context/ → 提示走 dev-init 接入；命令速查 ~/.agents/COMMANDS.md
