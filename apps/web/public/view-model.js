function parseTypedValue(type, raw) {
  const text = String(raw).trim();
  if (text.length > 128) throw new Error("类型化数值输入过长");
  if (type?.kind === "bool") {
    if (!["true", "false"].includes(text)) throw new Error("布尔值必须为 true 或 false");
    return { kind: "bool", value: text === "true" };
  }
  if (type?.kind === "bv") {
    if (![8, 16, 32, 64].includes(type.width) || !/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(text)) throw new Error("BV 输入须为非负十进制整数或 0x 十六进制");
    const n = BigInt(text);
    if (n >= 1n << BigInt(type.width)) throw new Error(`数值超过 BV${type.width} 范围`);
    return { kind: "bv", width: type.width, bits: "0x" + n.toString(16).padStart(type.width / 4, "0") };
  }
  if (type?.kind === "fp32") {
    const bits = /^bits:([0-9a-f]{8})$/i.exec(text);
    if (bits) return { kind: "fp32", bits: "0x" + bits[1].toLowerCase() };
    if (!text || !Number.isFinite(Number(text))) throw new Error("FP32 输入须为有限数字或 bits:xxxxxxxx");
    const view = new DataView(new ArrayBuffer(4));
    view.setFloat32(0, Number(text), false);
    if (!Number.isFinite(view.getFloat32(0, false))) throw new Error("数值超出 FP32 有限范围");
    return { kind: "fp32", bits: "0x" + view.getUint32(0, false).toString(16).padStart(8, "0") };
  }
  throw new Error("不支持的输入类型");
}
function fp32Number(value) {
  if (!/^0x[0-9a-f]{8}$/i.test(value?.bits ?? "")) return NaN;
  const view = new DataView(new ArrayBuffer(4));
  view.setUint32(0, parseInt(value.bits, 16), false);
  return view.getFloat32(0, false);
}
function formatTypedValue(value) {
  if (value?.kind === "bool") return String(value.value);
  if (value?.kind === "bv") return `${value.bits} · BV${value.width}`;
  if (value?.kind === "fp32") {
    const n = fp32Number(value);
    return `${Object.is(n, -0) ? "-0" : String(n)} · ${value.bits}`;
  }
  return typeof value === "string" ? value : JSON.stringify(value);
}
const labels = { unverified: "未验证", not_verified: "未验证", "cpu-replay": "CPU 重放", "native-observed": "原生观测", recorded: "已记录", unvalidated: "未经目标验证", not_applicable: "不适用", sampled_match: "样本匹配", sampled_mismatch: "样本不匹配", matched: "匹配", mismatched: "不匹配", mismatch: "不匹配", unavailable: "不可用", fitted: "已拟合", proved: "作用域内已证明", not_run: "未执行", not_retained_in_comparison_report: "比较报告未保留候选输出", queued: "排队中", running: "运行中", cancelling: "正在取消", completed: "已完成", failed: "失败", cancelled: "已取消", interrupted: "已中断", pass: "通过", passed: "通过", fail: "不通过", ok: "已观测", unknown: "未知", unattempted: "未尝试", not_attempted: "未尝试", expected_fixture: "预期样例", reference_fixture: "参考样例", original_target: "原始目标", native_observation: "原生观测", cpu_replay: "CPU 重放", model_proof: "模型证明", partial: "局部结果", manual: "人工模型", oracle_fit: "拟合模型", rea_live: "实时导出", rea_portable: "可移植导出", observed: "实际观测", exact: "精确", equivalent: "作用域内等价", verified: "已验证" };
const statusLabel = (value) => labels[value] ?? String(value ?? "未知");
function statusTone(value) {
  const status = String(value ?? "").toLowerCase();
  if (["failed", "fail", "error", "target_error", "timeout", "crash", "mismatch", "mismatched", "sampled_mismatch", "refuted"].includes(status)) return "danger";
  if (["completed", "pass", "passed", "verified", "equivalent", "ok", "matched", "proved", "fitted"].includes(status)) return "success";
  if (["running", "queued", "cancelling", "native-observed", "cpu-replay"].includes(status)) return "info";
  return "muted";
}
function scopeLabel(scope) {
  if (!scope) return "作用域未声明";
  if (typeof scope === "string") return scope;
  const kinds = { expression: "表达式", exported_model: "导出模型", trace_slice: "轨迹片段", behavior_model: "行为模型" };
  return `${kinds[scope.kind] ?? scope.kind} · ${scope.source_completeness === "partial" ? "局部源信息" : scope.source_completeness === "complete" ? "完整源信息" : "源完整性未确认"}`;
}
function createGeneration() {
  let value = 0;
  return { next: () => ++value, isCurrent: (ticket) => ticket === value };
}
function filterRows(rows, status) {
  return !status || status === "all" ? rows : rows.filter((row) => String(row.status ?? row.result ?? "unknown") === status);
}
function curvePath(points, width = 650, height = 200) {
  const valid = points.filter((p) => Number.isFinite(p.x) && Number.isFinite(p.y));
  if (!valid.length) return "";
  const xs = valid.map((p) => p.x), ys = valid.map((p) => p.y), minX = Math.min(...xs), maxX = Math.max(...xs), minY = Math.min(...ys), maxY = Math.max(...ys);
  let active = false;
  return points.map((p) => {
    if (!Number.isFinite(p.x) || !Number.isFinite(p.y)) {
      active = false;
      return "";
    }
    const x = 24 + (p.x - minX) / (maxX - minX || 1) * (width - 48), y = height - 24 - (p.y - minY) / (maxY - minY || 1) * (height - 48);
    const s = `${active ? "L" : "M"}${x.toFixed(2)},${y.toFixed(2)}`;
    active = true;
    return s;
  }).join(" ");
}
const isTerminal = (status) => ["completed", "failed", "cancelled", "interrupted"].includes(status);
const pretty = (value) => JSON.stringify(value, null, 2) ?? "暂无数据";
const dateLabel = (value) => value ? new Date(value).toLocaleString("zh-CN", { hour12: false }) : "未记录";
function comparisonOutputs(row) {
  return { original: row.original_output ?? row.original_outputs ?? row.expected_outputs ?? row.original ?? row.expected ?? row.reference ?? row.left ?? row.native_outputs ?? null, candidate: row.candidate_output ?? row.candidate_outputs ?? row.actual_outputs ?? row.candidate ?? row.actual ?? row.right ?? row.model_outputs ?? null, candidateStatus: row.candidate_output_status ?? null };
}
function fitSeries(logs, key) {
  const groups = /* @__PURE__ */ new Map();
  for (const log of logs) {
    if (!Number.isFinite(log.iteration)) continue;
    const restart = Number.isInteger(log.restart) ? log.restart : 0;
    if (!groups.has(restart)) groups.set(restart, []);
    groups.get(restart).push({ x: log.iteration, y: Number.isFinite(log[key]) ? log[key] : null });
  }
  return [...groups].map(([restart, points]) => ({ restart, points }));
}
function fitAssessment(fit) {
  if (fit?.status === "failed") return { tone: "danger", label: "拟合未通过", message: "保存的拟合结果未通过固定策略；请检查各分割的不匹配、失败与未尝试计数。结果仅描述该数据集，不代表原始目标程序等价。" };
  const counts = [fit?.train_counts, fit?.validation_counts, fit?.holdout_counts].map(normalizeCounts);
  const matched = fit?.status === "fitted" && counts.every((c) => c.valid && c.planned > 0 && c.attempted === c.planned && c.completed === c.planned && c.matched === c.planned && c.mismatched === 0 && c.failed === 0 && c.out_of_domain === 0 && c.unattempted === 0);
  return matched ? { tone: "success", label: "三分割策略匹配", message: "保存的 train、validation 与冻结后的 holdout 计数均满足固定策略。结论仅描述该运行的数据集与声明输出，不代表原始目标程序等价。" } : { tone: "muted", label: "拟合结果待核对", message: "当前状态或分割计数不足以确认三分割策略均匹配。请检查保存结果与原始拟合证据。" };
}
async function currentResult(promise, isCurrent) {
  try {
    const value = await promise;
    return isCurrent() ? { current: true, value } : { current: false };
  } catch (error) {
    if (isCurrent()) throw error;
    return { current: false };
  }
}
const laboratoryCaseId = (selected, caseId, writableCaseId) => selected?.kind === "managed" ? caseId : writableCaseId;
function typedInputText(value) {
  if (value?.kind === "bool") return String(value.value);
  if (value?.kind === "bv") return value.bits;
  if (value?.kind === "fp32") {
    const number = fp32Number(value);
    if (Object.is(number, -0)) return "-0";
    return Number.isFinite(number) ? String(number) : `bits:${String(value.bits).replace(/^0x/, "")}`;
  }
  throw new Error("不支持的类型化值");
}
function normalizeCounts(value) {
  const keys = ["planned", "attempted", "completed", "matched", "mismatched", "failed", "out_of_domain"];
  if (!value || !keys.every((key) => Number.isSafeInteger(value[key]) && value[key] >= 0)) return { ...value, valid: false, unattempted: null };
  const valid = value.matched + value.mismatched === value.completed && value.completed + value.failed + value.out_of_domain === value.attempted && value.attempted <= value.planned;
  return { ...value, valid, unattempted: valid ? value.planned - value.attempted : null };
}
export {
  comparisonOutputs,
  createGeneration,
  currentResult,
  curvePath,
  dateLabel,
  filterRows,
  fitAssessment,
  fitSeries,
  formatTypedValue,
  fp32Number,
  isTerminal,
  laboratoryCaseId,
  normalizeCounts,
  parseTypedValue,
  pretty,
  scopeLabel,
  statusLabel,
  statusTone,
  typedInputText
};
