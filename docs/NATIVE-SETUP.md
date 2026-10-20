# Ghidra / JDK 本机部署记录

2026-10-19 已在 Windows x64 安装并验证：

| 软件 | 安装目录 |
| --- | --- |
| Ghidra 12.1.4 | `E:\wirefit\.tools\native\ghidra_12.1.4_PUBLIC` |
| Eclipse Temurin JDK 21.0.12.1+1 | `E:\wirefit\.tools\native\jdk-21.0.12.1+1` |

来源为 [NSA 官方发行版](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build) 和 [Adoptium 官方 JDK 发行版](https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.12.1%2B1)。两个归档均核对了官方 SHA-256；地址、实际文件摘要和字节数保存在 [deployment.json](../artifacts/native/deployment.json)。安装归档保留于 `.tools/native/archives/`。

## 启动与环境

从项目目录启动图形界面：

```powershell
cd E:\wirefit
.\ghidra.cmd
```

本次未自动打开 GUI；实际验证使用 REA 驱动的 Ghidra 原生分析过程。

已持久设置当前用户的 `JAVA_HOME`、`GHIDRA_INSTALL_DIR`，并加入 JDK 的 `bin` 到用户 Path。原环境记录在 `.local/native-installation.json`。对于已经打开的终端，运行：

```powershell
.\native-env.ps1
java -version
javac -version
```

项目本地 REA 启动配置为 `.local/rea-native.json`，显式传入 JDK 和 Ghidra 路径。MCP stdio 的默认环境转发不会自动包含所有变量，因此 Wirefit 采集时应使用该配置。

## 实际执行过的验证

使用本机 MSVC C11、`/Od /Ob0 /fp:strict` 编译原有 `fixtures/behavior_fixtures.c` 和 `fixture_probe.c`，通过导出表保留函数名。构建输出及源文件摘要均保留。二进制位于 `artifacts/native/fixture-build/wirefit-fixture.exe`。

以下 Wirefit 命令已真实执行并成功：

```powershell
.\wirefit.cmd case create --dir .\cases\native-install-20261019

.\wirefit.cmd evidence acquire --case .\cases\native-install-20261019 --config .\.local\rea-native.json --target .\artifacts\native\fixture-build\wirefit-fixture.exe --provider ghidra --procedure fixture_bv8_mba_original

.\wirefit.cmd model lift --case .\cases\native-install-20261019 --evidence evidence_4d21e07524074034a09b52228f6b5891 --output '0x14000103a#98'
```

案例已经存在；复验时使用新的案例目录。证据 ID、地址和模型 ID 属于本次编译，重新编译或换目标后应读取新结果，不能沿用。

结果：真实 REA 6.7.0 / Ghidra 12.1.4；非空反编译文本；8 个 high-p-code 操作、7 条 def-use 边；无截断和已知遗漏；portable evidence 认证通过；局部表达式提升和来源映射保存成功；临时分析会话正常关闭。

- [安装与验证收据](../artifacts/native/deployment.json)
- [原始 portable evidence](../artifacts/native/native-evidence.json)
- [实际反编译文本](../artifacts/native/function-pseudocode.c)
- 案例：`cases/native-install-20261019`，其中保留完整原始 MCP 回复、请求、模型和来源映射。

## 验证范围

安装问题已解决，Windows Ghidra 原生分析可用。安装成功不等于完整函数语义已经恢复。

本例中 Ghidra 将原 C 的 `uint8_t` 返回推断为 `int`。选定的局部 p-code 值是 32 位：输入 250、10 时为 260；真正 C 目标的 8 位返回是 4。因此本次模型保留 `execution_guard: unknown` 和 `observation_point: local_value`，不升级为原函数完整等价或可直接进行目标保真验证。

原 [完整验收记录](ACCEPTANCE-RESULTS.md)、`upstream-lock.json`、历史 REA 捕获和 Demo C 收据按原执行时间保留。`doctor` 输出中的 `last_recorded_native_gate: BLOCKED` 是此前完整验收门禁状态，由 `historical_native_gate.scope: full_acceptance` 明确标记；不会随安装收据改写。完整 ABI/guard、CFG/phi、原目标回放闭环仍需各自验证。Windows Ghidra 通道的成功也不代表 Linux 专属 pwntools 通道已经安装或测试。

## Doctor 的当前检查与历史证据

运行 `npm.cmd run doctor` 可查看三个独立层次：

- `rea.current_native_tools` 从当前 `.local/rea-native.json` 读取路径，检查 Java、javac、Ghidra headless 启动脚本、Node 和 REA 脚本是否为实际存在的普通文件。`available` 仅表示文件存在；`verification: regular_file_presence_only`、`executed: false` 表明本次没有启动或验证这些程序的版本、内容和运行状态。配置缺失或损坏分别显示 `not_configured`、`invalid_configuration`；任一文件缺失显示 `incomplete`。
- `rea.recorded_native_analysis` 对部署收据做结构校验，并重新核对其 `source_files`、portable evidence 及原案例 raw acquisition 的字节数和 SHA-256。还核对 Ghidra provider、证据 ID、目标摘要、未截断的 value-flow 计数，以及已完成、已持久化、已关闭的采集记录之间的对应关系。`validated` 表示这些保留文件符合收据，验证范围固定为 `local_expression_analysis`。`verified_at` 是当时执行的时间；`current_execution_verified: false` 表示本次没有重跑原生分析。该检查不替代完整 portable evidence 导入契约或模型验证。
- `rea.historical_native_gate` 保留以前的完整验收门禁结果，`current_proof: false` 表示它不是当前安装或原生分析的证据。

为兼容已有调用方，`native_ghidra`、`last_recorded_native_gate`、`native_reason` 继续存在。只有当前工具文件齐全、当前 JDK/Ghidra 路径和主机平台架构与收据一致、保留证据校验通过时，`native_ghidra` 才显示 `RECORDED_LOCAL_ANALYSIS`；其余情况为 `NOT_VERIFIED`。调用方应读取上述独立对象，避免将这个兼容字段当成当前执行成功或完整函数等价的结论。即使旧证据有效，删除当前 Java 或改用另一份 JDK 也不会升级当前状态。

检查只读取本地文件，不执行 Java、Ghidra、REA 或目标程序。收据上限 256 KiB，配置上限 64 KiB；证据引用最多 32 个，每个最多 16 MiB、总计最多 64 MiB，路径须位于项目内且不能经由符号链接或 junction。收据缺失、格式错误、超限、引用文件缺失或摘要改变，都会保留 `NOT_VERIFIED`。工具路径可位于项目外，但只能提供文件存在性信息。大型安装归档不会在每次 doctor 时重新读取，故 `archives_rechecked: false`；官方归档摘要仍作为历史安装记录保留，不表示当下重新验过安装内容。

重查本次证据与安装摘要（使用项目 Node）：

```powershell
& .\.tools\runtime\node_modules\node-win-x64\bin\node.exe .\artifacts\native\record-installation.mjs
```
