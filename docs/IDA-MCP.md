# IDA MCP 与 WireFit

本机 IDA Professional 9.3 已通过独立 MCP 接入 WireFit。运行 `E:\wirefit\wirefit-web.cmd` 后，在 <http://127.0.0.1:4318/#ida> 使用 **IDA 分析** 页面。

## 已安装与实测

| 组件 | 本机版本与位置 |
| --- | --- |
| IDA | `E:\IDA Professional 9.3`，原生版本 9.3.251224 |
| Python | CPython 3.14.2；使用安装的基础解释器和隔离模块目录 |
| MCP | `ida-pro-mcp==2.0.0`，源码固定为 `c133c3853faa111a9b00ee615c013b720d0c4acd` |
| 依赖 | `idapro==0.0.11`、`tomli-w==1.2.0`，安装在 `.tools/ida-mcp/venv/` |
| WireFit 配置 | `.local/ida-mcp.json`，固定后端命令、参数、环境、版本与实测收据 |

社区 MCP 来源为 [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp/tree/c133c3853faa111a9b00ee615c013b720d0c4acd)。本机版本采用兼容实现；当前官方 Hex-Rays MCP 的版本要求是 IDA 9.4+。

源代码自有的 x64、32 位 x86 样例都已通过真实 IDA 反汇编和 Hex-Rays 反编译，另实测了 CFG、引用、字节和类型查询。仅凭插件文件名不能判断 x86 支持是否存在。安装没有更改 IDA 程序或许可配置。

工作台显示“已实测可用”需要同时核对实测记录、Python 可执行文件、启动配置、包装器和登记的运行文件指纹。只有可执行文件存在时不会显示原生验证成功。能力查询读取收据，不启动 IDA。

## 浏览器使用

1. 进入 **IDA 分析**。可选自有 x64、自有 x86 或 vmde 网格核局部窗口样例，也可填写本机目标文件的绝对路径。
2. 选择函数分析、概览、函数/字符串/类型列表、字节读取，或编辑高级查询 JSON。地址使用 `0x` 开头的十六进制，保留全部 64 位。
3. 提交任务。界面明示写入案例；历史案例只读，新任务使用工作台实验区或已新建的可写案例。
4. 查看各项完成、部分结果或失败，浏览保留的伪代码、反汇编、真实 CFG 节点与原始哈希证据。任务完成与反编译成功分别呈现。
5. 可取消本服务会话的任务，或导出包含原始回复、源文件副本、来源说明和独立校验器的报告包。

轮询与案例/结果选择分开管理；后台任务更新不会使已选报告的下载失效。每个任务创建独立输入副本和 IDA 数据库，不连接或关闭用户手动打开的 IDA。动态调试、补丁和任意 Python 不属于这个浏览器接口。

## CLI

```powershell
cd E:\wirefit
.\wirefit.cmd ida status
.\wirefit.cmd case create --dir .\cases\ida-example
.\wirefit.cmd ida analyze --case .\cases\ida-example `
  --file .\artifacts\ida-mcp\runtime\vmde-window-00498000-source\vmde-window-00498000.exe `
  --query .\.local\ida-smoke-queries.json --timeout 60000
```

`--query` 是显式 UTF-8 JSON 文件，内容为查询数组，例如：

```json
[
  {"kind":"overview"},
  {"kind":"functions","offset":0,"limit":50},
  {"kind":"function","address":"0x498a50"},
  {"kind":"xrefs","address":"0x498a50"},
  {"kind":"bytes","address":"0x498a50","size":32}
]
```

支持 `overview`、`functions`、`strings`、`function`、`xrefs`、`bytes`、`types` 七种查询。每任务最多 16 项，列表每页最多 200 项、偏移最多 1,000,000，单次字节读取最多 4096 字节，总任务超时 1–600,000 毫秒。未知字段、任意工具名和代码请求均会拒绝。

CLI 前台等待任务及所属进程清理。报告保留 `status: partial` 等实际结果；不能仅凭进程退出码判断查询内容是否完整。通用导出命令支持 IDA：

```powershell
.\wirefit.cmd report export --case .\cases\ida-example --run <运行ID> --out .\exports\ida-example
# 进入导出目录后执行；仅核对文件，不启动 IDA 或输入程序
node verify.mjs
```

## MCP

WireFit MCP 新增 `wirefit_analyze_ida`，参数为 `{file,queries,timeout_ms?}`。通过现有 `wirefit_get_job` 轮询、`wirefit_cancel_job` 请求取消、`wirefit_get_report` 读取结果、`wirefit_export_report` 导出。大型结果可通过登记工件或导出读取，普通报告接口维持原有大小上限。`wirefit_capabilities` 包含实际 IDA 安装与验证状态。

另提供标准客户端配置 [.local/ida-mcp-client.json](../.local/ida-mcp-client.json)。该示例固定一个自有输入，启动时复制到新的会话目录；更换目标需修改本地 `--source` 配置。它没有自动写入全局 Codex 或其他客户端设置。完整运行器说明见 [tools/ida-mcp/README.md](../tools/ida-mcp/README.md)。

## 证据与语义边界

IDA 采集使用独立 provider。它复用 WireFit 的任务、案例、哈希工件和报告机制，不冒充 REA portable evidence 或 Ghidra p-code。当前并未实现任意 Hex-Rays microcode 到 WireFit 模型的自动语义提升。

每次任务记录原始输入哈希、隔离副本、数据库路径、imagebase、工具目录、原始 MCP 回复、逐项错误和清理结果。上游返回的地址必须与请求地址一致。超过 JavaScript 精确整数范围的数值不作为精确数值展示，原始数字文本保存在 stdio 工件中。

原始回复和归一化结果中的任意 `ArtifactRef` 外形对象不授予读取权限；预览与导出使用宿主登记的工件。受核对的样例来源说明、派生窗口 provenance 也作为宿主工件保留。

## vmde 当前实战结果

- 完整约 14 MiB 研究转储在两次 180 秒有界尝试中未完成加载/初始化；失败及所属进程终止记录保留。
- `0x498a50` 网格核窗口已通过真实静态反汇编、反编译、CFG、引用和字节查询。窗口保留原转储 `0x498000` 起的 4096 字节及虚拟地址；用于装载的 PE 头为合成。
- 窗口的完整转储哈希、偏移、RVA、字节哈希及派生 PE 哈希保存在相邻 `provenance.json`，并随对应报告归档。
- 跨窗口引用、完整导入/类型及整程序行为不完整。窗口成功不能替代完整转储成功；本轮没有执行 vmde 或新增原生函数调用。

已有 904 条原生网格核观测、31 例节点 CPU 回放和 26 次标签 CPU 调用保留原有作用域；IDA 伪代码不会把这些结论升级为完整程序等价。

## 验证与维护

```powershell
npm run build
npm run test:ida
npm run test:web
npm test
npm run test:e2e
```

实际原生和外部标准客户端探针在 `artifacts/ida-mcp/runtime/`；集成收据、浏览器截图在 `artifacts/ida-mcp/`。仅在本机 Windows/IDA 9.3 环境进行了原生验收，其他平台需要配置相应解释器、IDA 安装和隔离依赖后重新实测。

运行文件更新后，应重新执行真实探针并更新指纹。`configure.py` 只能根据真实且与当前包装器一致的探针报告生成本机配置和收据；不要把手工修改状态当成重新验证。

本次完整验收：59 个测试文件、852 项测试、6 项真实 Edge 浏览器流程均通过；公共 MCP 和 CLI 的七类查询均通过。收据见 [artifacts/ida-mcp/acceptance.json](../artifacts/ida-mcp/acceptance.json)，简要记录见 [验收说明](../artifacts/ida-mcp/README.md)。
