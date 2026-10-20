# 交付包离线校验记录

本记录仅验证本实施包和自写夹具。它不是 WireFix 产品验收报告，也不证明外部工具已经接入。

- 开始：`2026-10-19T12:52:58.617988+00:00`
- 完成：`2026-10-19T12:52:59.724992+00:00`
- 环境：Python `3.12.14`；`Linux-6.18.55-x86_64-with-glibc2.39`
- 本轮结论：`PASS_BOUNDED_CHECKS`

## 重跑

```bash
python3 tools/check_handoff.py
# 显式更新本记录；重新打包前还需重建最终 MANIFEST：
python3 tools/check_handoff.py --write-report
```

默认不写文件；会对本包已明确绑定的自写 FP32 fixture 发起 32 次 fresh-process 调用。`--skip-oracle` 可跳过该调用，届时该项记录为 NOT_RUN。

## 本轮检查

| 检查 | 状态 |
| --- | --- |
| Schema JSON / local references / keyword inventory | PASS |
| Indexed positive examples and JSONL rows | PASS |
| Known-invalid in-memory mutations | PASS |
| Artifact and fixture target hash/length checks | PASS |
| Example model/request IDs and key cross-field checks | PASS |
| 32 expected rows and 16/8/8 leakage checks | PASS |
| BV8 exhaustive identity and wide-integer models | PASS |
| Self-authored integer reference-vector checks | PASS |
| Self-authored FP32 fixture fresh-process replay | PASS |
| Input files stable during QA | PASS |
| Standard JSON Schema 2020-12 validator compilation/conformance | NOT_RUN |
| REA/Ghidra product integration | NOT_RUN |
| Z3 product solver execution | NOT_RUN |
| Handwired build/evaluation/backprop product integration | NOT_RUN |
| WireFix CLI/MCP/product implementation | NOT_RUN |

## 方法与限制

- 使用 Python 标准库解析 JSON、拒绝重复键和非标准数值，并核对本地 `$ref`。
- 自定义结构检查器仅覆盖本包出现的有限关键词；未知关键词报错。它不是标准 JSON Schema 2020-12 validator，未运行 meta-schema/conformance 编译。
- `format` 只作注解；正则按本包的有限 ASCII 表达式检查，不宣称实现完整 ECMAScript 正则语义。
- 跨字段检查只针对所附样例的 ID、签名、拓扑、六种 BV 夹具算子、数值参数和域、映射、文件身份及数据划分；它不是产品完整语义 validator，也不是域包含关系求解器。
- 32 行历史数据仍是 expected_fixture。重跑自写 Python fixture 只增加本包夹具回放证据，不把这些文件重标为原目标观测。
- BV8 全枚举和整数向量一致性是自写材料的数学核对，没有运行 Z3、产品 TypeScript 执行器或外部二进制逆向链。
- 其余 C/浮点/状态夹具的独立检查若有记录，见 fixtures/validation；本脚本不把它们冒充本轮执行。
- 最终文件 MANIFEST 由打包步骤另行生成；默认重跑本脚本不会改写本记录或使清单过期。

## 详细记录

```json
{
  "scope": "handoff_package_qa_only",
  "started_at": "2026-10-19T12:52:58.617988+00:00",
  "finished_at": "2026-10-19T12:52:59.724992+00:00",
  "python_version": "3.12.14",
  "platform": "Linux-6.18.55-x86_64-with-glibc2.39",
  "overall": "PASS_BOUNDED_CHECKS",
  "checks": [
    {
      "check": "Schema JSON / local references / keyword inventory",
      "status": "PASS",
      "details": {
        "json_files": 11,
        "local_refs": 187,
        "checker": "package-specific subset; NOT standard 2020-12 validation",
        "keywords_seen": [
          "$defs",
          "$id",
          "$ref",
          "$schema",
          "additionalProperties",
          "anyOf",
          "const",
          "enum",
          "format",
          "items",
          "maxItems",
          "maxLength",
          "maxProperties",
          "maximum",
          "minItems",
          "minLength",
          "minProperties",
          "minimum",
          "oneOf",
          "pattern",
          "patternProperties",
          "properties",
          "required",
          "title",
          "type",
          "uniqueItems"
        ],
        "format_assertions": "NOT_RUN"
      }
    },
    {
      "check": "Indexed positive examples and JSONL rows",
      "status": "PASS",
      "details": {
        "indexed_files": 24,
        "json_files": 20,
        "jsonl_files": 4,
        "jsonl_rows": 64,
        "records_checked": 84
      }
    },
    {
      "check": "Known-invalid in-memory mutations",
      "status": "PASS",
      "details": {
        "rejected_mutations": 6,
        "scope": "smoke checks, not checker conformance tests"
      }
    },
    {
      "check": "Artifact and fixture target hash/length checks",
      "status": "PASS",
      "details": {
        "unique_artifact_refs": 4,
        "oracle_target_files": 1
      }
    },
    {
      "check": "Example model/request IDs and key cross-field checks",
      "status": "PASS",
      "details": {
        "models": 8,
        "datasets": 1,
        "oracles": 1,
        "requests": 7,
        "domain_check_scope": "the supplied identical-domain examples only"
      }
    },
    {
      "check": "32 expected rows and 16/8/8 leakage checks",
      "status": "PASS",
      "details": {
        "planned": 32,
        "split_sizes": {
          "train": 16,
          "validation": 8,
          "holdout": 8
        },
        "distinct_typed_inputs": 32,
        "source_records": "expected_fixture only; zero historical original-target observations"
      }
    },
    {
      "check": "BV8 exhaustive identity and wide-integer models",
      "status": "PASS",
      "details": {
        "bv8_input_pairs": 65536,
        "wrong_candidate_differences": 65536,
        "first_wrong_counterexample": {
          "a": "0x00",
          "b": "0x00",
          "reference": "0x00",
          "wrong": "0x01"
        },
        "bv64_boundary_inputs": 4,
        "wide_count_shift_inputs": 21,
        "scope": "self-authored Python fixture mathematics; no Z3 or TS product execution"
      }
    },
    {
      "check": "Self-authored integer reference-vector checks",
      "status": "PASS",
      "details": {
        "all_vector_rows_read": 166,
        "integer_vectors_checked": 76,
        "other_vector_computations": "outside this script's bounded scope"
      }
    },
    {
      "check": "Self-authored FP32 fixture fresh-process replay",
      "status": "PASS",
      "details": {
        "fresh_processes": 32,
        "bitwise_matches": 32,
        "fixture_sha256": "96541884fa61957890c0f086538907e889d03d94252a2a1a350c8c39d2cace35",
        "responses_sha256": "51ed867228ab73c64485dc6ff214807691a004daefde3df625efbc2659a63605",
        "python_executable": "/opt/codex/runtimes/codex-primary-runtime/dependencies/python/bin/python",
        "scope": "self-authored exact-integer/rational FP32 fixture; not WireFix Oracle integration"
      }
    },
    {
      "check": "Input files stable during QA",
      "status": "PASS",
      "details": {
        "watched_files": 41,
        "input_inventory_sha256": "f7f08714ecc09d59583741a4bd53b0f5989e760c8963c1f0c73ee097f1a55f6c"
      }
    },
    {
      "check": "Standard JSON Schema 2020-12 validator compilation/conformance",
      "status": "NOT_RUN",
      "details": "Outside this handoff QA; no success is claimed"
    },
    {
      "check": "REA/Ghidra product integration",
      "status": "NOT_RUN",
      "details": "Outside this handoff QA; no success is claimed"
    },
    {
      "check": "Z3 product solver execution",
      "status": "NOT_RUN",
      "details": "Outside this handoff QA; no success is claimed"
    },
    {
      "check": "Handwired build/evaluation/backprop product integration",
      "status": "NOT_RUN",
      "details": "Outside this handoff QA; no success is claimed"
    },
    {
      "check": "WireFix CLI/MCP/product implementation",
      "status": "NOT_RUN",
      "details": "Outside this handoff QA; no success is claimed"
    }
  ]
}
```
