# Windows VMProtect 公开教育样本目录

本目录包含 **3 个受保护 PE 样本、3 个对应未保护 PE 和 3 份 C 源码**，全部来自同一个作者的研究仓库。仅下载和静态检查；没有运行样本、没有声称恢复其虚拟化逻辑。用户后续指定了实际目标，因此公开样本搜集到此结束。

## 来源与版本可信度

- 原作者：[Mitch Zakocs 的 VMProtect 3 研究文章](https://www.zakocs.com/blog/vmprotect3)，文章日期为 2021-07-28。
- 原作者仓库：[mzakocs/VirtualizationObfuscatorAnalysis，固定提交](https://github.com/mzakocs/VirtualizationObfuscatorAnalysis/tree/2fb7ad84a90a73c950c39eccbad81cc2f6c25c33)。README 将仓库中的二进制和分析数据库与作者研究文章关联。
- 固定提交：`2fb7ad84a90a73c950c39eccbad81cc2f6c25c33`。
- 作者文章明确说所分析的 `hello_world` 由 VMProtect **v3.5.0.1274** 保护。这是作者陈述，而且明确针对文章里的 `hello_world`。本次选择的 `adder`、`bitwise`、`multiadder` 位于同一仓库的 `VMProtect 3/` 目录；**没有找到它们逐文件的精确版本声明，亦未独立确认 VMProtect 版本**。不能把文章版本直接套到三份文件。
- 当前仓库树没有发现 LICENSE，GitHub API 未声明 SPDX 许可证。文件仅保留在本地研究输入目录，没有复制进 `vendor`、产品源代码或测试夹具；公开可读不等于拥有再分发许可。

## 本地路径与下载登记

本地前缀：

`E:\wirefit\.upstream\vmp-windows\2fb7ad84a90a73c950c39eccbad81cc2f6c25c33\VMProtect 3\`

| 样本 | 受保护文件 | 未保护文件 | 源码 |
| --- | --- | --- | --- |
| adder | `adder.vmp.exe` | `unprotected/adder.exe` | `unprotected/source/adder.c` |
| bitwise | `bitwise.vmp.exe` | `unprotected/bitwise.exe` | `unprotected/source/bitwise.c` |
| multiadder | `multiadder.vmp.exe` | `unprotected/multiadder.exe` | `unprotected/source/multiadder.c` |

[下载清单](../artifacts/research/vmp-windows-catalog/download-manifest.json) 记录每个文件的固定提交下载 URL、绝对路径、字节数、SHA-256，以及 PE 映像基址、入口与节表。[复核结果](../artifacts/research/vmp-windows-catalog/verification.json) 逐文件重读并校验大小和 SHA-256。

| 受保护文件 | 字节数 | SHA-256 |
| --- | ---: | --- |
| adder.vmp.exe | 1047040 | `0bf50b74eff6f7c7b761a33723080c249a46a0f2a63ae539d7b4432165b434fc` |
| bitwise.vmp.exe | 1056256 | `4ca551a780d5f60d646f9dc54c774893b5447d3d3042995b43066282f06a3fca` |
| multiadder.vmp.exe | 1049088 | `6100bc853386a34418d15a82ad0a4701defd59cfdd8a2acbb2986078f48da4a3` |

## 静态检查和分析入口

独立读取了 PE 头：6 个二进制都有 `MZ`/`PE` 签名、AMD64 Machine `0x8664`、PE32+ Magic `0x20b`，ImageBase 均为 `0x140000000`。每对原始 `.text` 相比，仅目标函数区域发生变化，其 `main` 中调用该位置的代码保持一致；保护版增加了约 1 MB 的节。目标入口的首条指令均由算术代码变为 `E9 rel32` 跳转。这些是格式和保护结构证据，不能代替虚拟机语义恢复或精确保护器版本识别。

以下地址均为首选映像基址下的静态 VA，运行时若发生重定位须加实际装载偏移。

| 样本 | 目标函数入口 | main 入口 | PE 入口 | 目标第一跳 |
| --- | --- | --- | --- | --- |
| adder | `0x140001000` | `0x140001020` | `0x1400012e0` | `0x14000508a` |
| bitwise | `0x140001000` | `0x140001050` | `0x140001310` | `0x1401040d1` |
| multiadder | `0x140001000` | `0x140001040` | `0x140001300` | `0x1400050f8` |

源码给出的目标分别是：

- `adder(int x, int y)`：返回 `x + y`。
- `arithmetic(int x, int y)`：先 XOR、再 AND、再 OR；按逐位代数，最后结果恒等于 `y`。
- `adder(int x, int y, int z)`：先 `y = z + y`，再 `x = x + y`，返回 `x`。

这些输入遵循 Windows x64 调用约定：`ECX`、`EDX`、第三参数 `R8D`，返回 `EAX`，均为 32 位 `int`。基线函数分别为 21、77、50 字节。加法源码有 C 有符号溢出语义限制，未来若做源码对照，应选无溢出输入域；分析机器码时须另行明确按 32 位位向量解释。

## 不能把它们算作已有实战成功

三份源码中的 `main` 都仅传固定常量：`20,40` 或 `20,40,60`，丢弃被测函数的返回值，最后返回零。没有命令行参数、标准输入或标准输出的可变输入 Oracle 界面。因此：

- 运行主程序得到退出码零，不能证明恢复了目标函数。
- 已知源码的代数结果，不是从受保护代码恢复出的结果。
- 当前没有 chosen-input / holdout 黑盒对照，也没有证明 protected/unprotected 的执行等价性。
- 本子任务只完成来源审阅、下载固定化和静态入口登记；未执行任何 PE，也未分析或执行用户随后指定的实际目标。

## 未纳入的候选

- [pgarba/UniTaint](https://github.com/pgarba/UniTaint/tree/880f14b52fc8196cce7f8daa3ac0abadeeb07d75)：作者 README 讨论 x64 VMProtect 纯函数攻击，但检查的仓库树只有 PoC 源码与说明，没有可下载的受保护 PE，故没有计入样本数。
- [void-stack/VMUnprotect](https://github.com/void-stack/VMUnprotect/tree/c20ba5d4baf6845c22481d996369b1992dd3f6cb)：作者定位为 .NET 方法跟踪/调用操作工具，检查的树中未发现所需的 native x64 受保护教育 PE；工具的功能声明没有作为本项目成功证据。
- 没有下载恶意软件合集、商业程序盗版或泄漏的 VMProtect 工具。
