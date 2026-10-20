import { el, svg, panel, badge, button, kv, table, notice, empty, loading, errorBox, json, showEvidence } from "../components.js";
import { fitSeries, fitAssessment, normalizeCounts, dateLabel } from "../view-model.js";
function fittingPanel(ctx, caseId, data, model, onCandidate) {
  const fits = data.runs.filter((run2) => run2.result?.fit?.candidate_model_id && run2.result.fit.status !== "not_run");
  const associated = fits.find((run2) => run2.result.fit.candidate_model_id === model.model_id);
  const run = associated ?? fits[0];
  const content = el("div", { class: "fitting-body" });
  const box = panel("拟合误差与保留集", "Fit evidence / 真实优化日志与独立分割结果", content);
  if (!run) {
    content.append(empty("尚无数值拟合结果", "在任务中心执行 Handwired 数值拟合后，这里会展示实际误差记录。"));
    return box;
  }
  const fit = run.result.fit;
  const assessment = fitAssessment(fit);
  content.append(notice(associated ? "此拟合结果与当前候选模型关联。" : "以下为最近一次拟合；当前所选模型并非该候选模型。", "neutral"), el("div", { class: "row" }, badge(fit.status), badge(assessment.tone === "success" ? "matched" : assessment.tone === "danger" ? "failed" : "unknown", assessment.label), el("span", { class: "tag mono" }, fit.backend ?? "未记录 backend")), kv([["运行 ID", run.id], ["候选模型", fit.candidate_model_id], ["时间", dateLabel(run.created_at)]]), !associated ? button("切换至此候选模型", () => onCandidate(fit.candidate_model_id), "secondary") : null, notice(assessment.message, assessment.tone === "success" ? "neutral" : assessment.tone), table([{ label: "分割", key: "split" }, { label: "计划", key: "planned" }, { label: "匹配", key: "matched" }, { label: "不匹配", key: "mismatched" }, { label: "失败", key: "failed" }, { label: "未尝试", render: (row) => row.valid ? row.unattempted : "计数不一致" }], [["train", fit.train_counts], ["validation", fit.validation_counts], ["holdout", fit.holdout_counts]].map(([split, counts]) => ({ split, ...normalizeCounts(counts) }))));
  const logs = el("div", {}, loading("读取真实拟合日志…"));
  content.append(logs);
  const artifact = fit.artifacts?.[0];
  if (!artifact) {
    logs.replaceChildren(empty("没有保存拟合日志", "结果记录未登记日志 artifact。"));
    return box;
  }
  (async () => {
    try {
      const evidence = await ctx.api(`/api/cases/${encodeURIComponent(caseId)}/artifacts/${artifact.sha256}`);
      if (!ctx.isCurrent()) return;
      if (evidence.truncated) {
        logs.replaceChildren(notice("拟合文件超出预览上限，未从截断数据推断误差。", "neutral"), button("查看日志证据", () => showEvidence(evidence, ctx), "text"));
        return;
      }
      const record = JSON.parse(evidence.text), rawLogs = record.fitted?.logs ?? [];
      logs.replaceChildren(rawLogs.length ? el("div", { class: "loss-charts" }, ...fitSeries(rawLogs, "train_mse").map((group) => lossChart(group.restart, rawLogs.filter((log) => (log.restart ?? 0) === group.restart)))) : empty("未保留迭代误差日志"), panel("冻结候选误差", "MSE / 来自原始 fitting artifact", table([{ label: "分割", key: "split" }, { label: "MSE", render: (r) => finiteLabel(r.mse) }, { label: "最大绝对误差", render: (r) => finiteLabel(r.max_absolute_error) }, { label: "匹配", key: "matched" }, { label: "不匹配", key: "mismatched" }], [{ split: "train", ...record.fitted?.train_metrics }, { split: "validation", ...record.fitted?.validation_metrics }])), button("查看原始拟合证据", () => showEvidence(evidence, ctx), "text"));
    } catch (error) {
      if (error.name !== "AbortError" && ctx.isCurrent()) logs.replaceChildren(errorBox(error));
    }
  })();
  return box;
}
function finiteLabel(value) {
  return Number.isFinite(value) ? Number(value).toPrecision(6) : "未记录";
}
function lossChart(restart, logs) {
  const values = logs.flatMap((row) => [row.train_mse, row.validation_mse]).filter(Number.isFinite);
  if (!values.length) return empty(`Restart ${restart} 无有限误差点`);
  const minX = Math.min(...logs.map((r) => r.iteration)), maxX = Math.max(...logs.map((r) => r.iteration)), minY = Math.min(...values), maxY = Math.max(...values);
  const chart = svg("svg", { viewBox: "0 0 650 180", class: "curve-chart", role: "img", "aria-label": `Restart ${restart} 训练与验证 MSE 误差曲线` });
  for (let y = 20; y <= 150; y += 32.5) chart.append(svg("line", { x1: 24, y1: y, x2: 626, y2: y, stroke: "#e4ebdc" }));
  for (const [key, color] of [["train_mse", "#287d6d"], ["validation_mse", "#c39655"]]) {
    let active = false;
    const path = logs.map((row) => {
      if (!Number.isFinite(row[key])) {
        active = false;
        return "";
      }
      const x = 24 + (row.iteration - minX) / (maxX - minX || 1) * 602, y = 150 - (row[key] - minY) / (maxY - minY || 1) * 130;
      const point = `${active ? "L" : "M"}${x},${y}`;
      active = true;
      return point;
    }).join(" ");
    chart.append(svg("path", { d: path, stroke: color, "stroke-width": 2, fill: "none" }));
  }
  return el("div", { class: "loss-chart" }, el("div", { class: "chart-summary" }, el("span", { class: "mono" }, `RESTART ${restart} · ${logs.length} 个原始日志点`), el("span", { class: "mono" }, `MSE ${finiteLabel(minY)} … ${finiteLabel(maxY)}`)), chart, el("div", { class: "loss-legend" }, el("span", { class: "train" }, "● train MSE"), el("span", { class: "validation" }, "● validation MSE"), el("span", { class: "mono" }, `iteration ${minX}–${maxX}`)));
}
export {
  fittingPanel
};
