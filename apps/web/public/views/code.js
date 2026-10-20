import { collectionNotice, el, svg, heading, panel, badge, button, select, loading, errorBox, empty, kv, json, notice, evidenceLink } from "../components.js";
import { createGeneration, scopeLabel, pretty } from "../view-model.js";
function graphView(graph, onSelect) {
  const nodes = (graph?.nodes ?? []).slice(0, 60), edges = graph?.edges ?? [];
  if (!nodes.length) return empty("没有登记图结构", "此记录没有可展示的依赖或调用关系。");
  const width = 720, columns = nodes.length > 4 ? 3 : Math.min(nodes.length, 3), rows = Math.ceil(nodes.length / columns), height = Math.max(150, rows * 82 + 35), locations = new Map(nodes.map((n, i) => [n.id, { x: 24 + i % columns * 230, y: 24 + Math.floor(i / columns) * 82 }]));
  const group = svg("svg", { viewBox: `0 0 ${width} ${height}`, class: "dependency-graph", role: "group", "aria-label": "依赖关系图" });
  for (const edge of edges) {
    const a = locations.get(edge.from), b = locations.get(edge.to);
    if (!a || !b) continue;
    group.append(svg("path", { d: `M ${a.x + 98} ${a.y + 42} C ${a.x + 98} ${a.y + 68},${b.x + 98} ${b.y - 20},${b.x + 98} ${b.y}`, fill: "none", stroke: "#9bb2ac", "stroke-width": 1.3 }));
  }
  for (const node of nodes) {
    const p = locations.get(node.id), g = svg("g", { transform: `translate(${p.x},${p.y})`, class: "graph-node", tabindex: 0, role: "button", "aria-label": `选择节点 ${node.label}`, "data-node-id": node.id });
    g.append(svg("rect", { width: 198, height: 48, rx: 5 }), svg("text", { x: 12, y: 20, class: "graph-label" }, String(node.label).slice(0, 25)), svg("text", { x: 12, y: 36, class: "graph-address" }, node.address ?? node.status ?? node.id));
    const choose = () => {
      group.querySelectorAll(".graph-node").forEach((n) => n.classList.remove("selected"));
      g.classList.add("selected");
      onSelect(node);
    };
    g.addEventListener("click", choose);
    g.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        choose();
      }
    });
    group.append(g);
  }
  return el("div", { class: "graph-canvas" }, group, graph.nodes.length > 60 ? notice("图结构仅展示前 60 个节点。") : null);
}
async function renderCode(ctx) {
  const research = ctx.selected.kind === "research" ? await ctx.getResearch() : null;
  const caseData = research ? null : await ctx.api(`/api/cases/${encodeURIComponent(ctx.caseId)}`);
  const entities = research ? research.functions : caseData.models.map((m) => ({ id: m.model_id, name: m.title ?? m.model_id, status: m.provenance?.source_kind, address: m.kind, scope: scopeLabel(m.scope), model: m }));
  const detail = el("div", { class: "code-detail" }), list = el("div", { class: "entity-list" }), generation = createGeneration();
  const mode = research ? "研究函数" : "登记模型";
  async function choose(entity) {
    const ticket = generation.next();
    list.querySelectorAll("button").forEach((b) => b.classList.toggle("active", b.dataset.entity === entity.id));
    detail.replaceChildren(loading());
    try {
      const data = research ? await ctx.api(`/api/research/functions/${encodeURIComponent(entity.id)}`) : await ctx.api(`/api/cases/${encodeURIComponent(ctx.caseId)}/models/${encodeURIComponent(entity.id)}`);
      if (!ctx.isCurrent() || !generation.isCurrent(ticket)) return;
      if (research) renderFunction(data);
      else renderModel(data);
    } catch (error) {
      if (error.name !== "AbortError" && ctx.isCurrent() && generation.isCurrent(ticket)) detail.replaceChildren(errorBox(error, () => choose(entity)));
    }
  }
  function renderFunction(data) {
    const nodeDetail = el("div", { class: "node-detail" }, notice("选择图中节点，查看其登记标识。图连线仅来自归档中声明的关系。", "neutral"));
    const sources = data.sources ?? [];
    const sourceArea = el("div", {});
    const sourceSelect = select(sources.map((s, i) => ({ value: String(i), label: s.label })), { "aria-label": "代码来源", onchange: (event) => renderSource(Number(event.target.value)) });
    function renderSource(index) {
      const source = sources[index];
      sourceArea.replaceChildren(source ? el("div", {}, el("div", { class: "source-file-bar" }, el("span", { class: "mono" }, source.path), el("span", { class: "tag" }, source.format)), source.truncated ? notice("源内容已截断，完整身份见证据 SHA-256。") : null, sourceLines(source.text)) : empty("未提供源文件", "可检查下方登记的指令与证据。"));
    }
    renderSource(0);
    detail.replaceChildren(el("div", { class: "entity-heading" }, el("div", {}, el("h2", {}, data.name), el("p", { class: "mono" }, data.address)), badge(data.status)), notice(data.scope, "neutral"), panel("依赖与调用关系", "Graph / 由归档声明的数据关系", graphView(data.graph, (node) => nodeDetail.replaceChildren(kv([["选中节点", node.label], ["节点 ID", node.id], ["登记地址", node.address ?? "未提供"], ["状态", node.status ?? "未声明"]])))), nodeDetail, panel("代码与来源", "Source / 保留原始文件内容", el("div", {}, sources.length ? el("div", { class: "toolbar" }, sourceSelect) : null, sourceArea)), data.instructions.length ? panel("指令列表", "Listing / 仅展示实际归档记录", el("div", { class: "table-scroll" }, el("table", { class: "listing-table" }, el("tbody", {}, data.instructions.map((i) => el("tr", {}, el("td", { class: "mono address-cell" }, i.address), el("td", { class: "mono muted" }, i.bytes ?? ""), el("td", { class: "mono" }, i.text))))))) : null, panel("来源与证据", "Provenance / 文件身份与研究边界", el("div", { class: "provenance-body" }, el("p", {}, data.description), el("div", { class: "evidence-list" }, data.evidence.map((e) => el("div", { class: "evidence-row" }, evidenceLink(e, ctx), el("span", { class: "mono small" }, `${e.size_bytes} bytes`)))), data.limitations.map((text) => notice(text, "neutral")))));
  }
  function renderModel(model) {
    const graph = { nodes: [...model.inputs.map((i) => ({ id: i.id, label: `${i.id} · INPUT`, status: i.type.kind })), ...(model.nodes ?? []).map((n) => ({ id: n.id, label: `${n.id} · ${n.op}`, status: n.type.kind }))], edges: (model.nodes ?? []).flatMap((n) => n.args.map((a) => ({ from: a, to: n.id }))) };
    const selection = el("div", {}, notice("模型图展示输入与表达式依赖，节点不隐含机器地址。", "neutral"));
    detail.replaceChildren(el("div", { class: "entity-heading" }, el("div", {}, el("h2", {}, model.title), el("p", { class: "mono" }, model.model_id)), badge(model.provenance?.source_kind)), notice(scopeLabel(model.scope), "neutral"), model.kind === "bv_dag" ? panel("表达式依赖", "Bit-vector DAG / 类型化计算图", graphView(graph, (node) => selection.replaceChildren(kv([["节点", node.id]]), json(model.nodes?.find((n) => n.id === node.id) ?? model.inputs.find((n) => n.id === node.id))))) : panel("数值模板", "FP32 template / 固定语义", kv([["模板", model.definition.template], ["输入", model.inputs.map((i) => i.id).join(", ")], ["输出", model.outputs.map((i) => i.id).join(", ")]])), selection, panel("模型定义", "WireFit schema / 原始 JSON", sourceLines(pretty(model))), panel("来源与作用域", "Provenance / Scope", json({ scope: model.scope, provenance: model.provenance })), button("在实验室评估", () => {
      sessionStorage.setItem("wirefit.model", model.model_id);
      ctx.navigate("lab");
    }, "primary"));
  }
  for (const entity of entities) list.append(button(el("span", {}, el("strong", {}, entity.name), el("small", { class: "mono" }, entity.address), badge(entity.status)), () => {
    sessionStorage.setItem("wirefit.function", entity.id);
    choose(entity);
  }, "entity", { "data-entity": entity.id }));
  const saved = sessionStorage.getItem(research ? "wirefit.function" : "wirefit.model");
  if (entities.length) await choose(entities.find((e) => e.id === saved) ?? entities[0]);
  else detail.append(empty("当前案例没有模型", "可以在任务中心导入显式模型。"));
  return el("div", { class: "view" }, heading("CODE & MODELS", "代码与模型", "把源文件、表达式依赖与可追溯证据放在一起阅读。"), el("div", { class: "code-layout" }, panel(mode, `${entities.length} 项 / ${ctx.selected.label}`, el("div", {}, caseData ? collectionNotice(caseData, "models", "模型") : null, list)), detail));
}
function sourceLines(text) {
  return el("div", { class: "source-code", tabindex: 0, "aria-label": "源代码" }, String(text ?? "").split("\n").map((line, i) => el("div", { class: "source-line" }, el("span", { class: "line-number", "aria-hidden": true }, i + 1), el("code", {}, line || " "))));
}
export {
  graphView,
  renderCode
};
