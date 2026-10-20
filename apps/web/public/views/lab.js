import { collectionNotice, el, svg, heading, panel, badge, button, field, select, loading, errorBox, empty, kv, json, notice, bindAsync, table } from "../components.js";
import { fittingPanel } from "./lab-fit.js";
import { parseTypedValue, formatTypedValue, fp32Number, scopeLabel, curvePath, createGeneration, currentResult, laboratoryCaseId, typedInputText } from "../view-model.js";
async function renderLab(ctx) {
  const caseId = laboratoryCaseId(ctx.selected, ctx.caseId, ctx.managedCaseId), data = await ctx.api(`/api/cases/${encodeURIComponent(caseId)}`), models = data.models ?? [];
  const root = el("div", { class: "view" }, heading("MODEL LABORATORY", "模型实验室", "用明确的位宽与 FP32 语义评估模型，检查每个中间值。", [button("拟合 / 简化任务", () => ctx.navigate("tasks"), "secondary")]), notice(`求值案例：${data.case.label} (${caseId})${caseId !== ctx.caseId ? " · 当前研究档案保持只读，求值使用实验工作区模型。" : !data.case.writable ? " · 只读模型解释求值，不写入历史案例。" : ""}`, "neutral"));
  root.append(...[collectionNotice(data, "models", "模型"), collectionNotice(data, "runs", "拟合来源运行")].filter(Boolean));
  if (!models.length) {
    root.append(panel("可执行模型", "Model / 当前工作区", empty("工作区还没有可执行模型", "在任务中心导入一个显式模型后，即可评估其类型化输入。")));
    return root;
  }
  let model, inputs = /* @__PURE__ */ new Map(), parameters = /* @__PURE__ */ new Map();
  const fitContainer = el("div", { "data-testid": "fitting-evidence" });
  const generation = createGeneration(), form = el("form", { "data-testid": "lab-form" }), inputFields = el("div", { class: "input-fields" }), parameterFields = el("div", { class: "parameter-fields" }), modelMeta = el("div", {}), status = el("div", { "aria-live": "polite" }), results = el("div", { class: "lab-results" }, empty("等待一次真实评估", "输入值后运行模型，即可查看输出与计算过程。")), sweepFields = el("div", {});
  const modelSelect = select(models.map((m) => ({ value: m.model_id, label: `${m.title} · ${m.model_id}` })), { "aria-label": "选择实验模型", onchange: () => choose(modelSelect.value) });
  const saved = sessionStorage.getItem("wirefit.model");
  modelSelect.value = models.some((m) => m.model_id === saved) ? saved : models[0].model_id;
  function choose(id) {
    generation.next();
    model = models.find((m) => m.model_id === id);
    inputs = /* @__PURE__ */ new Map();
    parameters = /* @__PURE__ */ new Map();
    status.replaceChildren();
    results.replaceChildren(empty("等待评估", "模型已切换；请重新评估当前输入。"));
    modelMeta.replaceChildren(badge(model.provenance?.source_kind), el("span", { class: "tag mono" }, model.kind), notice(scopeLabel(model.scope), "neutral"));
    inputFields.replaceChildren(...model.inputs.map((port) => {
      const type = port.type, input = type.kind === "bool" ? select([{ value: "false", label: "false" }, { value: "true", label: "true" }], { "aria-label": `输入 ${port.id}` }) : el("input", { type: "text", value: type.kind === "fp32" ? "1" : "0", class: "mono", spellcheck: false, "aria-label": `输入 ${port.id}` });
      inputs.set(port.id, input);
      return field(el("span", {}, port.id, el("span", { class: "type-label" }, type.kind === "bv" ? `BV${type.width}` : type.kind.toUpperCase())), input, type.kind === "bv" ? "无符号十进制或 0x 十六进制；保留全部位。" : type.kind === "fp32" ? "有限数字或 bits:xxxxxxxx；按 FP32 舍入。" : "严格布尔值");
    }));
    parameterFields.replaceChildren();
    sweepFields.replaceChildren();
    if (model.kind === "numeric_template") {
      parameterFields.append(el("h3", {}, "参数预览"), notice("参数只用于这次评估，不覆盖已保存的模型。", "neutral"));
      for (const [id2, value] of Object.entries(model.definition.parameters)) {
        const control = el("input", { type: "text", class: "mono", value: typedInputText(value), "aria-label": `参数 ${id2}` });
        parameters.set(id2, control);
        const bound = model.definition.parameter_bounds[id2];
        parameterFields.append(field(id2, control, bound ? `登记边界 ${formatTypedValue(bound.lower)} 至 ${formatTypedValue(bound.upper)}` : `原始位 ${value.bits}`));
      }
      const sweepEnabled = el("input", { type: "checkbox", checked: true, id: "sweep-enabled" }), from = el("input", { type: "number", value: "-2", step: "any", "aria-label": "曲线起点" }), to = el("input", { type: "number", value: "2", step: "any", "aria-label": "曲线终点" }), steps = el("input", { type: "number", value: "41", min: "2", max: "101", "aria-label": "曲线采样数" });
      sweepFields.append(el("h3", {}, "输出曲线"), el("label", { class: "checkbox-label", for: "sweep-enabled" }, sweepEnabled, "评估有界输入曲线"), el("div", { class: "sweep-grid" }, field("起点", from), field("终点", to), field("采样数", steps)), el("p", { class: "field-hint" }, `扫描输入 ${model.inputs[0].id} · 最多 101 个点 · 服务器实际求值`));
      sweepFields.values = { sweepEnabled, from, to, steps };
    } else sweepFields.values = null;
    fitContainer.replaceChildren(fittingPanel(ctx, caseId, data, model, (id2) => {
      if (models.some((m) => m.model_id === id2)) {
        modelSelect.value = id2;
        choose(id2);
      }
    }));
  }
  function showResult(result) {
    const outputs = Object.entries(result.outputs ?? {});
    const trace = result.trace ?? [];
    results.replaceChildren(panel("评估结果", "Outputs / 解释器实际计算", el("div", { class: "lab-output" }, el("div", { class: "row" }, badge(result.preview ? "partial" : "completed", result.preview ? "参数预览" : "已评估"), el("span", { class: "small muted" }, result.scope)), outputs.length ? el("div", { class: "output-values" }, outputs.map(([id, value]) => el("div", { class: "output-value" }, el("span", {}, id), el("strong", { class: "mono" }, formatTypedValue(value))))) : empty("模型未返回输出"))), result.curve?.length ? panel("输出曲线", "FP32 sweep / 失败或非有限点保留空缺", chart(result.curve)) : null, panel("中间值", "Execution trace / 有界节点求值", table([{ label: "节点", key: "id", class: "mono" }, { label: "操作", key: "op", class: "mono" }, { label: "值 / BITS", render: (r) => el("code", {}, formatTypedValue(r.value)) }], trace)), el("details", { class: "panel raw-details" }, el("summary", {}, "查看完整评估响应"), json(result)));
  }
  form.append(field("模型", modelSelect), modelMeta, el("div", { class: "form-divider" }), el("h3", {}, "类型化输入"), inputFields, parameterFields, sweepFields, el("button", { type: "submit", class: "button primary full-width", "data-testid": "evaluate-model" }, "运行模型评估"), status);
  bindAsync(form, async () => {
    const ticket = generation.next(), request = { inputs: Object.fromEntries(model.inputs.map((p) => [p.id, parseTypedValue(p.type, inputs.get(p.id).value)])) };
    if (parameters.size) {
      const preview = Object.fromEntries([...parameters].map(([id, control]) => [id, parseTypedValue({ kind: "fp32" }, control.value)]));
      if (Object.entries(preview).some(([id, value]) => value.bits !== model.definition.parameters[id].bits)) request.parameters = preview;
    }
    const sweep = sweepFields.values;
    if (sweep?.sweepEnabled.checked) {
      const from = Number(sweep.from.value), to = Number(sweep.to.value), steps = Number(sweep.steps.value);
      if (!Number.isFinite(from) || !Number.isFinite(to) || from >= to || !Number.isInteger(steps) || steps < 2 || steps > 101) throw new Error("曲线需要有限的起止范围和 2–101 个采样点");
      request.sweep = { input: model.inputs[0].id, from, to, steps };
    }
    const response = await currentResult(ctx.api(`/api/cases/${encodeURIComponent(caseId)}/models/${encodeURIComponent(model.model_id)}/evaluate`, { method: "POST", body: request }), () => ctx.isCurrent() && generation.isCurrent(ticket));
    if (!response.current) return;
    const result = response.value;
    status.replaceChildren();
    showResult(result);
  }, status);
  choose(modelSelect.value);
  root.append(el("div", { class: "lab-layout" }, panel("模型与输入", "Inputs / 类型与位模式", form), results), fitContainer);
  return root;
}
function chart(points) {
  const finite = points.filter((p) => Number.isFinite(p.y));
  if (!finite.length) return empty("没有可绘制的有限输出", "所有扫描点的求值均失败或产生非有限值。");
  const xs = finite.map((p) => p.x), ys = finite.map((p) => p.y), graphic = svg("svg", { viewBox: "0 0 650 220", class: "curve-chart", role: "img", "aria-label": `模型输出曲线，${points.length} 个服务器采样点` });
  for (let y = 24; y <= 196; y += 43) graphic.append(svg("line", { x1: 24, y1: y, x2: 626, y2: y, stroke: "#e5e9e5", "stroke-width": 1 }));
  graphic.append(svg("line", { x1: 24, y1: 196, x2: 626, y2: 196, stroke: "#b9c8c1" }), svg("path", { d: curvePath(points, 650, 220), fill: "none", stroke: "#227868", "stroke-width": 2.4, "stroke-linejoin": "round" }));
  return el("div", {}, el("div", { class: "chart-summary" }, el("span", {}, `${points.length} 个采样点`), el("span", { class: "mono" }, `y: ${Math.min(...ys).toPrecision(5)} … ${Math.max(...ys).toPrecision(5)}`)), graphic, el("div", { class: "chart-x-labels mono" }, el("span", {}, Math.min(...xs)), el("span", {}, "INPUT"), el("span", {}, Math.max(...xs))), points.some((p) => p.error) ? notice(`${points.filter((p) => p.error).length} 个采样点返回错误；曲线保留对应空缺。`) : null);
}
export {
  renderLab
};
