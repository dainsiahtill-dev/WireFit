import { collectionNotice, el, heading, panel, badge, button, field, select, loading, errorBox, empty, kv, json, notice, bindAsync, table, time, showEvidence } from "../components.js";
import { pretty, isTerminal, dateLabel } from "../view-model.js";
async function renderTasks(ctx) {
  const caseId = ctx.managedCaseId;
  let data = await ctx.api(`/api/cases/${encodeURIComponent(caseId)}`), jobs = new Map(data.jobs.map((job) => [job.job_id, job])), selectedId = data.jobs[0]?.job_id;
  let pollTimer, polling = false;
  const jobList = el("div", {}), jobDetail = el("div", {}, empty("选择一个任务", "查看真实生命周期、结果与报告。")), runList = el("div", {}), exportStatus = el("div", { "aria-live": "polite" }), submitStatus = el("div", { "aria-live": "polite" });
  ctx.signal.addEventListener("abort", () => clearTimeout(pollTimer), { once: true });
  async function refreshData() {
    const next = await ctx.api(`/api/cases/${encodeURIComponent(caseId)}`);
    if (!ctx.isCurrent()) return;
    data = next;
    jobs = new Map(next.jobs.map((job) => [job.job_id, { ...jobs.get(job.job_id), ...job }]));
    if (!jobs.has(selectedId)) selectedId = next.jobs[0]?.job_id;
    renderJobs();
    renderRuns();
  }
  async function exportRun(runId, status = exportStatus) {
    status.replaceChildren(loading("正在生成证据闭包与报告…"));
    try {
      const result = await ctx.api(`/api/cases/${encodeURIComponent(caseId)}/exports`, { method: "POST", body: { runId } });
      if (!ctx.isCurrent()) return;
      status.replaceChildren(notice("报告包已写入本地。", "success"), kv([["导出目录", result.path], ["包 ID", result.id]]), el("div", { class: "download-files" }, result.files.map((file2) => el("a", { class: "download-link", href: `/api/exports/${encodeURIComponent(result.id)}/file?path=${encodeURIComponent(file2.name)}`, download: file2.name }, el("span", {}, file2.name), el("span", { class: "mono small" }, `${file2.size_bytes.toLocaleString()} bytes ↓`)))));
    } catch (error) {
      if (error.name !== "AbortError" && ctx.isCurrent()) status.replaceChildren(errorBox(error));
    }
  }
  function renderJobs() {
    const sorted = [...jobs.values()].sort((a, b) => b.created_at.localeCompare(a.created_at));
    jobList.replaceChildren(collectionNotice(data, "jobs", "任务"), sorted.length ? el("div", { class: "job-list" }, sorted.map((job) => button(el("span", { class: "job-content" }, el("span", { class: "job-heading" }, el("strong", {}, job.operation), badge(job.status)), el("small", { class: "mono" }, job.job_id), el("span", { class: "job-time" }, dateLabel(job.created_at), job.owned ? el("span", { class: "owned-label" }, "本会话") : null)), () => {
      selectedId = job.job_id;
      renderJobs();
    }, `job-row${job.job_id === selectedId ? " selected" : ""}`, { "data-job-id": job.job_id }))) : empty("还没有任务", "选择一个预设，或提交本机分析任务。"));
    showJob();
  }
  function showJob() {
    const job = jobs.get(selectedId);
    if (!job) return;
    const run = data.runs.find((run2) => run2.id === job.result_id);
    const cancelStatus = el("div", { "aria-live": "polite" }), cancel = button("取消任务", async (event) => {
      const cancelButton = event.currentTarget;
      cancelButton.disabled = true;
      cancelStatus.replaceChildren(loading("正在请求取消…"));
      try {
        const next = await ctx.api(`/api/cases/${encodeURIComponent(caseId)}/jobs/${encodeURIComponent(job.job_id)}/cancel`, { method: "POST", body: {} });
        if (!ctx.isCurrent()) return;
        jobs.set(job.job_id, { ...job, ...next });
        renderJobs();
        schedulePoll();
      } catch (error) {
        if (error.name !== "AbortError" && ctx.isCurrent()) {
          cancelStatus.replaceChildren(errorBox(error));
          cancelButton.disabled = false;
        }
      }
    }, "danger-outline", { disabled: !job.owned || isTerminal(job.status) || job.status === "cancelling", "data-testid": "cancel-job" });
    jobDetail.replaceChildren(el("div", { class: "job-detail-title" }, el("h3", {}, job.operation), badge(job.status)), kv([["任务 ID", job.job_id], ["提交时间", dateLabel(job.created_at)], ["开始时间", dateLabel(job.started_at)], ["结束时间", dateLabel(job.finished_at)], ["结果 ID", job.result_id ?? "尚无结果"], ["任务归属", job.owned ? "本服务会话提交" : "历史任务 / 当前服务无取消权"]]), el("div", { class: "row" }, cancel, job.result_id ? button("导出报告", () => exportRun(job.result_id), "primary", { "data-testid": "export-job" }) : null), cancelStatus, job.error ? el("div", { class: "error-box" }, el("strong", {}, job.error.code), el("p", {}, job.error.message)) : null, run ? el("div", {}, el("h4", {}, "实验结果 / Result"), resultSummary(run.result), el("details", { class: "raw-details" }, el("summary", {}, "完整结果 JSON"), json(run.result)), artifactButtons(run.result)) : isTerminal(job.status) ? notice("此任务没有可展示的运行结果。", "neutral") : notice("任务正在执行，状态由本地服务实时轮询。", "neutral"));
  }
  function artifactButtons(value) {
    const refs = /* @__PURE__ */ new Map();
    function visit(v, depth) {
      if (!v || typeof v !== "object" || depth > 12 || refs.size >= 40) return;
      if (typeof v.sha256 === "string" && /^[a-f0-9]{64}$/.test(v.sha256) && typeof v.relative_path === "string") refs.set(v.sha256, v);
      for (const child of Object.values(v)) visit(child, depth + 1);
    }
    visit(value, 0);
    return el("div", { class: "artifact-buttons" }, [...refs.values()].map((ref) => button(`查看证据 ${ref.relative_path}`, async () => {
      try {
        const evidence = await ctx.api(`/api/cases/${encodeURIComponent(caseId)}/artifacts/${ref.sha256}`);
        if (ctx.isCurrent()) showEvidence(evidence, ctx);
      } catch (error) {
        if (error.name !== "AbortError") exportStatus.replaceChildren(errorBox(error));
      }
    }, "text")));
  }
  function renderRuns() {
    runList.replaceChildren(collectionNotice(data, "runs", "运行"), table([{ label: "运行 ID", render: (r) => button(r.id, () => {
      jobDetail.replaceChildren(el("h3", {}, r.operation), badge(r.status), resultSummary(r.result), el("details", { class: "raw-details" }, el("summary", {}, "完整结果 JSON"), json(r.result)), artifactButtons(r.result), button("导出报告", () => exportRun(r.id), "primary"));
    }, "text") }, { label: "操作", key: "operation" }, { label: "结果", render: (r) => badge(r.status) }, { label: "报告", render: (r) => button("导出", () => exportRun(r.id), "ghost") }], data.runs, { emptyTitle: "尚无运行记录", emptyDetail: "任务产生持久化结果后，会出现在这里。" }));
  }
  function schedulePoll() {
    clearTimeout(pollTimer);
    if (!ctx.isCurrent() || ![...jobs.values()].some((job) => !isTerminal(job.status))) return;
    pollTimer = setTimeout(poll, 900);
  }
  async function poll() {
    if (polling || !ctx.isCurrent()) return;
    polling = true;
    try {
      const active = [...jobs.values()].filter((job) => !isTerminal(job.status));
      let terminalChanged = false;
      const settled = await Promise.allSettled(active.map(async (job) => ({ previous: job, next: await ctx.api(`/api/cases/${encodeURIComponent(caseId)}/jobs/${encodeURIComponent(job.job_id)}`) })));
      if (!ctx.isCurrent()) return;
      for (const result of settled) {
        if (result.status === "fulfilled") {
          const { previous, next } = result.value;
          jobs.set(next.job_id, { ...previous, ...next });
          terminalChanged ||= isTerminal(next.status);
        } else if (result.reason.name !== "AbortError") submitStatus.replaceChildren(errorBox(result.reason));
      }
      if (terminalChanged) await refreshData();
      else renderJobs();
    } catch (error) {
      if (error.name !== "AbortError" && ctx.isCurrent()) submitStatus.replaceChildren(errorBox(error));
    } finally {
      polling = false;
      schedulePoll();
    }
  }
  async function submitted(request) {
    const job = await ctx.api(`/api/cases/${encodeURIComponent(caseId)}/tasks`, { method: "POST", body: request });
    if (!ctx.isCurrent()) return;
    jobs.set(job.job_id, { ...job, owned: true });
    selectedId = job.job_id;
    submitStatus.replaceChildren(notice(`任务已由服务接受：${job.job_id}`, "success"));
    renderJobs();
    schedulePoll();
  }
  const presets = ctx.bootstrap.presets ?? [];
  const presetSelect = select(presets.map((p) => ({ value: p.id, label: p.label })), { "aria-label": "实验预设" }), presetDescription = el("p", { class: "muted preset-description" }), requestEditor = el("textarea", { class: "json-editor", rows: 15, spellcheck: false, "aria-label": "实验请求 JSON", "data-testid": "experiment-json" });
  function loadPreset() {
    const preset = presets.find((p) => p.id === presetSelect.value);
    requestEditor.value = preset ? pretty(preset.request) : "";
    presetDescription.textContent = preset?.description ?? "服务未提供实验预设。";
  }
  presetSelect.addEventListener("change", loadPreset);
  loadPreset();
  const experimentForm = el("form", { "data-testid": "experiment-form" }, field("实验预设", presetSelect), presetDescription, field("请求 JSON", requestEditor, "可编辑原始 ExperimentRequest；服务器执行完整契约校验。"), el("button", { type: "submit", class: "button primary", "data-testid": "submit-experiment" }, "提交实验任务"));
  bindAsync(experimentForm, async () => {
    let request;
    try {
      request = JSON.parse(requestEditor.value);
    } catch {
      throw new Error("实验请求不是有效的 JSON");
    }
    await submitted({ kind: "experiment", request });
  }, submitStatus);
  const nativeStatus = el("div", { "aria-live": "polite" }), kind = select([{ value: "inspect", label: "静态 PE 检查 / Inspect" }, { value: "trace", label: "有界原生追踪 / Trace" }, { value: "unpack", label: "解包分析 / Unpack" }], { "aria-label": "本机分析类型" }), profile = select([], { "aria-label": "分析配置" }), file = el("input", { type: "text", placeholder: "E:\\path\\to\\target.exe", "aria-label": "目标文件绝对路径", required: true }), plan = el("textarea", { class: "json-editor", rows: 5, placeholder: "可选：服务器支持的 trace/unpack plan JSON", "aria-label": "分析计划 JSON" });
  function updateProfiles() {
    const options = (ctx.bootstrap.profiles ?? []).filter((p) => p.kind === kind.value);
    profile.replaceChildren(...options.map((p) => el("option", { value: p.id, disabled: !p.available }, `${p.label}${p.available ? "" : "（未安装）"}`)));
    const available = options.find((p) => p.available);
    profile.value = available?.id ?? "";
  }
  kind.addEventListener("change", updateProfiles);
  updateProfiles();
  const nativeForm = el("form", {}, field("分析类型", kind), field("服务器配置", profile, "仅使用服务已登记的本机工具配置。"), field("目标文件", file, "服务器所在机器上的绝对文件路径。"), field("分析计划", plan), el("button", { type: "submit", class: "button secondary", "data-testid": "submit-native" }, "提交本机任务"), nativeStatus);
  bindAsync(nativeForm, async () => {
    if (!profile.value) throw new Error("没有可用的服务器工具配置");
    let parsed;
    if (plan.value.trim()) {
      try {
        parsed = JSON.parse(plan.value);
      } catch {
        throw new Error("分析计划不是有效的 JSON");
      }
    }
    const request = { kind: kind.value, file: file.value.trim(), profileId: profile.value };
    if (parsed !== void 0) request.plan = parsed;
    await submitted(request);
    nativeStatus.replaceChildren(notice("本机任务已提交，见右侧任务列表。", "success"));
  }, nativeStatus);
  const caseStatus = el("div", { "aria-live": "polite" }), label = el("input", { type: "text", required: true, maxlength: 120, placeholder: "例如：边界条件实验", "aria-label": "新案例名称" }), caseForm = el("form", {}, field("案例名称", label), el("button", { type: "submit", class: "button secondary" }, "创建并切换"), caseStatus);
  bindAsync(caseForm, async () => {
    const created = await ctx.api("/api/cases", { method: "POST", body: { label: label.value.trim() } });
    if (!ctx.isCurrent()) return;
    await ctx.refreshCases();
    ctx.selectCase(created.id);
  }, caseStatus);
  const importStatus = el("div", { "aria-live": "polite" }), modelEditor = el("textarea", { class: "json-editor", rows: 10, spellcheck: false, "aria-label": "导入模型 JSON", placeholder: "粘贴完整 WireFit Model JSON" }), importForm = el("form", {}, field("显式模型 JSON", modelEditor, "必须包含 model_id、scope、provenance 与完整类型定义。"), el("div", { class: "row" }, el("button", { type: "submit", class: "button secondary" }, "导入模型"), data.models[0] ? button("加载现有模型作参考", () => {
    modelEditor.value = pretty(data.models[0]);
  }, "ghost") : null), importStatus);
  bindAsync(importForm, async () => {
    let model;
    try {
      model = JSON.parse(modelEditor.value);
    } catch {
      throw new Error("模型不是有效的 JSON");
    }
    const result = await ctx.api(`/api/cases/${encodeURIComponent(caseId)}/models`, { method: "POST", body: model });
    if (ctx.isCurrent()) {
      importStatus.replaceChildren(notice("模型已通过服务校验并导入。", "success"), json(result));
      await refreshData();
    }
  }, importStatus);
  renderJobs();
  renderRuns();
  schedulePoll();
  return el("div", { class: "view" }, heading("TASK CENTRE", "任务中心", "提交可复现的实验与本机分析，跟踪生命周期并导出完整报告。", [button("刷新记录", () => refreshData().catch((error) => {
    if (error.name !== "AbortError" && ctx.isCurrent()) submitStatus.replaceChildren(errorBox(error));
  }), "secondary")]), notice(`任务案例：${data.case.label} (${caseId})${caseId !== ctx.caseId ? " · vmde 研究档案保持只读，所有新任务写入此实验区。" : ""}`, "neutral"), el("div", { class: "tasks-layout" }, el("div", { class: "task-forms" }, panel("实验任务", "Handwired / Simplify / Verify / Compare", el("div", {}, experimentForm, submitStatus)), el("details", { class: "panel" }, el("summary", {}, "本机文件分析"), el("div", { class: "details-body" }, nativeForm)), el("details", { class: "panel" }, el("summary", {}, "创建独立案例"), el("div", { class: "details-body" }, caseForm)), el("details", { class: "panel" }, el("summary", {}, "导入显式模型"), el("div", { class: "details-body" }, importForm))), el("div", { class: "task-monitor" }, panel("任务队列", "真实服务状态 · 自动轮询活跃任务", jobList), panel("任务与结果详情", "Lifecycle / Result / Evidence", jobDetail), panel("报告导出", "Export closure / 保存目录与下载", exportStatus))), panel("运行记录", "Runs / 持久化实验与分析结果", runList));
}
function resultSummary(result) {
  if (!result || typeof result !== "object") return empty("结果未提供结构化字段");
  const dimensions = [["模型证明", result.model_check], ["目标验证", result.target_validation], ["数值拟合", result.fit], ["样本比较", result.sample_comparison], ["目标保真度", result.fidelity]].filter(([, value]) => value && value.status !== "not_run");
  return el("div", { class: "result-dimensions" }, ...dimensions.map(([label, value]) => el("div", { class: "result-dimension" }, el("div", { class: "row" }, el("strong", {}, label), badge(value.status)), el("p", {}, value.reason), value.counts ? kv(Object.entries(value.counts)) : null, value.candidate_model_id ? el("code", {}, value.candidate_model_id) : null)), ...(result.limitations ?? []).map((text) => notice(text, "neutral")));
}
export {
  renderTasks
};
