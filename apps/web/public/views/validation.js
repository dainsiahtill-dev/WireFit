import { el, heading, panel, badge, button, select, field, loading, errorBox, empty, kv, json, notice, pagination, table, evidenceLink } from "../components.js";
import { createGeneration, comparisonOutputs } from "../view-model.js";
async function renderValidation(ctx) {
  const research = await ctx.getResearch(), validations = research.validations ?? [];
  let selected = validations[0], offset = 0;
  const generation = createGeneration(), summary = el("div", {}), rows = el("div", {}), details = el("div", {}, empty("选择一条比较记录", "查看原始观测、候选输出与比较策略。"));
  const picker = select(validations.map((v) => ({ value: v.id, label: v.label })), { "aria-label": "验证数据集", onchange: (event) => {
    selected = validations.find((v) => v.id === event.target.value);
    offset = 0;
    load();
  } }), status = select([{ value: "", label: "全部状态" }, { value: "matched", label: "匹配 / matched" }, { value: "mismatched", label: "不匹配 / mismatched" }, { value: "failed", label: "失败 / failed" }, { value: "unattempted", label: "未尝试 / unattempted" }, { value: "unavailable", label: "不可用 / unavailable" }], { "aria-label": "比较结果筛选", onchange: () => {
    offset = 0;
    load();
  } });
  function showRow(row, index) {
    const outputs = comparisonOutputs(row);
    details.replaceChildren(el("h3", {}, String(row.sample_id ?? row.id ?? row.index ?? `记录 ${index + 1}`)), badge(row.status ?? "unknown"), kv([["记录来源", row.source_kind ?? row.record_kind ?? selected.kind], ["比较作用域", row.scope ?? selected.scope]]), el("h4", {}, "输入 / Inputs"), json(row.inputs ?? row.input ?? "该行未提供独立输入字段"), el("h4", {}, "原始 / 参考输出"), outputs.original !== null ? json(outputs.original) : notice("此记录未保留原始或参考输出。", "neutral"), el("h4", {}, "候选输出"), outputs.candidate !== null ? json(outputs.candidate) : notice(outputs.candidateStatus === "not_retained_in_comparison_report" ? "原始比较报告未保留候选输出；不以原始输出替代。" : "此记录未提供候选输出。", "neutral"), row.comparison ? el("div", {}, el("h4", {}, "比较准则与差异"), json(row.comparison)) : null, row.native_evidence ? el("div", {}, el("h4", {}, "原生观测依据"), json(row.native_evidence)) : null, row.checks ? el("div", {}, el("h4", {}, "检查项"), json(row.checks)) : null, row.evidence_id ? evidenceLink({ id: row.evidence_id, label: "查看此行原始证据" }, ctx) : null, el("details", { open: true }, el("summary", {}, "完整比较记录"), json(row)));
  }
  async function load() {
    if (!selected) {
      rows.replaceChildren(empty("没有验证记录"));
      return;
    }
    const ticket = generation.next();
    rows.replaceChildren(loading());
    details.replaceChildren(empty("选择一条比较记录", "详情只对应当前数据集中的选中行。"));
    summary.replaceChildren(el("div", { class: "validation-meta" }, badge(selected.status), el("span", { class: "tag mono" }, selected.kind)), notice(selected.scope, "neutral"), el("div", { class: "count-strip" }, Object.entries(selected.counts ?? {}).map(([key, value]) => el("div", {}, el("strong", { class: "mono" }, value.toLocaleString()), el("span", {}, key)))), ...(selected.limitations ?? []).map((text) => notice(text, "neutral")));
    try {
      const query = new URLSearchParams({ offset: String(offset), limit: "25" });
      if (status.value) query.set("status", status.value);
      const page = await ctx.api(`/api/research/validation/${encodeURIComponent(selected.id)}?${query}`);
      if (!ctx.isCurrent() || !generation.isCurrent(ticket)) return;
      rows.replaceChildren(table([{ label: "样本 / SAMPLE", render: (r, i) => button(String(r.sample_id ?? r.id ?? r.index ?? page.offset + i + 1), () => showRow(r, i), "text") }, { label: "结果", render: (r) => badge(r.status ?? "unknown") }, { label: "来源", render: (r) => String(r.source_kind ?? r.record_kind ?? selected.kind) }, { label: "摘要", render: (r) => String(r.reason ?? r.message ?? r.operation ?? r.method ?? r.profile ?? r.label ?? r.error?.message ?? (r.comparison?.matched === true ? "声明观察点匹配" : r.comparison?.matched === false ? "存在比较差异" : "查看原始比较字段")) }], page.items, { emptyTitle: "没有匹配的比较记录", emptyDetail: "请切换结果筛选。未知与未尝试不会被计入通过。" }), pagination(page, (next) => {
        offset = next;
        load();
      }));
    } catch (error) {
      if (error.name !== "AbortError" && ctx.isCurrent() && generation.isCurrent(ticket)) rows.replaceChildren(errorBox(error, load));
    }
  }
  await load();
  return el("div", { class: "view" }, heading("VALIDATION & COMPARISON", "验证与比较", "检验已声明的观察结果，保留每个成功、失败和未知结果的原始依据。"), ctx.selected.kind !== "research" ? notice("此页展示 vmde 研究档案的比较记录；当前工作区的实验结果见任务中心。", "neutral") : null, panel("验证范围", "Scope / 原生、重放与样例记录明确区分", el("div", {}, el("div", { class: "filter-bar" }, field("验证数据集", picker), field("比较结果", status)), summary)), el("div", { class: "validation-layout" }, panel("逐项比较", "Comparisons / 只展示实际记录", rows), panel("比较详情", "Original → Candidate", details)));
}
export {
  renderValidation
};
