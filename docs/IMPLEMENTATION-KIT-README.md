# WireFix Codex 实施包

这是结合 [REA](https://github.com/morluto/rea) 与 [Handwired](https://github.com/chenglou/handwired) 的逆向行为建模、候选恢复和验证工具开发规格。

## 使用方法

将整个目录放入 Codex 可访问的工作区。把 `CODEX_START.md` 的全文交给 Codex，或让它先阅读该文件再按文档执行。不要只把首页发给它；语义、接口和验收文件共同构成实现要求。

## 文件说明

| 文件 | 内容 |
| --- | --- |
| `IMPLEMENTATION_PLAN.md` | 完整产品范围、架构、REA/Handwired 集成、验证和阶段计划 |
| `CODEX_START.md` | 可直接提交的首条实施任务 |
| `TASKS.md` | 36 个带依赖与完成条件的任务 |
| `docs/SEMANTICS.md` | BV/FP32、输入域、反例和证据的规范 |
| `docs/INTERFACES.md` | 组件、Oracle、数据集、实验联合类型、CLI/MCP 数据流 |
| `docs/ACCEPTANCE.md` | 核心、数值、REA、产品与公平评测 gate |
| `docs/SOURCES.md` | 一手来源及实施时需要核实的事项 |
| `contracts/` | 规范 JSON Schema，语义 validator 仍须实现 |
| `examples/` | 格式正确的初始模型、请求和数据样例 |
| `fixtures/` | 自有测试函数和期望材料，供 Codex 建设真实验收链 |
| `upstream-lock.template.json` | 尚未固定的依赖模板，M0 需用真实结果替换 |
| `MANIFEST.json` | 本实施包文件的完整性摘要 |
| `tools/check_handoff.py` | 标准库实现的实施包检查器；不替代标准 Schema validator 或产品引擎 |
| `docs/HANDOFF_VALIDATION.md` | 本次交付实际核对范围及未运行项目 |

本包没有冒充已实现的引擎或已运行的上游集成。示例中的期望结果用于构建测试；产品支持和验收成绩必须由 Codex 实际实施、运行后填写。

## 首版重点

REA 提供采集与证据；WireFix 增加可执行模型、Oracle、候选搜索与验证；Handwired 参与连续参数拟合；Z3 负责受支持位向量模型的限定范围检查。模型证明与原程序样本证据在报告中并列显示。
