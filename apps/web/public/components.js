import { statusLabel, statusTone, pretty, dateLabel } from "./view-model.js";
function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === void 0 || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2).toLowerCase(), value);
    else if (key === "value") node.value = value;
    else if (key === "checked") node.checked = Boolean(value);
    else if (key === "disabled") node.disabled = Boolean(value);
    else node.setAttribute(key, String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === void 0 || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}
function svg(tag, attrs = {}, ...children) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  for (const child of children.flat()) {
    if (child instanceof Node) node.append(child);
    else if (child != null) node.append(document.createTextNode(String(child)));
  }
  return node;
}
const icons = { overview: "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z", code: "m8 6-6 6 6 6m8-12 6 6-6 6m-3-16-2 20", timeline: "M4 4v16m0-12h5m-5 8h5m3-12h8m-8 8h8m-8 8h8", lab: "M9 3h6m-5 0v6L4 19a1 1 0 0 0 1 2h14a1 1 0 0 0 1-2L14 9V3M8 14h8", validation: "m5 6 2 2 4-4M14 6h7M5 14l2 2 4-4m3 2h7M5 22l2-2m7 2h7", tasks: "M9 4h10v17H5V4h4m0-2h6v4H9zM8 11h8m-8 4h6", arrow: "M4 12h16m-6-6 6 6-6 6", refresh: "M20 8a8 8 0 1 0 0 8m0-14v6h-6", search: "M10 3a7 7 0 1 0 0 14 7 7 0 0 0 0-14m5 12 6 6", check: "m5 12 4 4L20 5", file: "M5 2h9l5 5v15H5zM14 2v6h5M8 12h8m-8 4h8", close: "m6 6 12 12m0-12L6 18" };
function icon(name, size = 18) {
  return svg("svg", { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 1.6, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": true }, svg("path", { d: icons[name] ?? icons.file }));
}
const badge = (value, text) => el("span", { class: `badge ${statusTone(value)}` }, el("span", { class: "status-dot" }), text ?? statusLabel(value));
function heading(kicker, title, description, actions = []) {
  return el("header", { class: "page-heading" }, el("div", {}, el("div", { class: "eyebrow" }, kicker), el("h1", {}, title), el("p", { class: "page-description" }, description)), el("div", { class: "heading-actions" }, actions));
}
const panel = (title, subtitle, content, actions = []) => el("section", { class: "panel" }, el("div", { class: "panel-heading" }, el("div", {}, el("h2", {}, title), subtitle ? el("p", {}, subtitle) : null), el("div", { class: "row" }, actions)), content);
const empty = (title = "暂无记录", detail = "当前作用域内没有可显示的数据。") => el("div", { class: "empty-state" }, icon("file", 28), el("strong", {}, title), el("p", {}, detail));
const loading = (label = "正在读取本地数据…") => el("div", { class: "loading", role: "status" }, el("span", { class: "spinner" }), label);
function errorBox(error, retry) {
  return el("div", { class: "error-box", role: "alert" }, el("strong", {}, error.code ?? "请求失败"), el("p", {}, error.message ?? String(error)), retry ? button("重试", retry, "secondary") : null);
}
function button(label, handler, kind = "secondary", attrs = {}) {
  return el("button", { type: "button", class: `button ${kind}`, onclick: handler, ...attrs }, label);
}
function field(label, control, hint) {
  const id = control.id || `field-${++fieldId}`;
  control.id = id;
  return el("div", { class: "field" }, el("label", { for: id }, label), control, hint ? el("p", { class: "field-hint" }, hint) : null);
}
let fieldId = 0;
function select(options, attrs = {}) {
  const value = attrs.value;
  const s = el("select", attrs, options.map((item) => el("option", { value: item.value, disabled: item.disabled }, item.label)));
  if (value !== void 0) s.value = value;
  return s;
}
const json = (value) => el("pre", { class: "json-block" }, pretty(value));
function kv(items) {
  return el("dl", { class: "key-values" }, items.flatMap(([k, v]) => [el("dt", {}, k), el("dd", {}, v ?? "未记录")]));
}
function table(columns, rows, options = {}) {
  if (!rows.length) return empty(options.emptyTitle, options.emptyDetail);
  return el("div", { class: "table-scroll" }, el("table", {}, el("thead", {}, el("tr", {}, columns.map((c) => el("th", { scope: "col" }, c.label)))), el("tbody", {}, rows.map((row, index) => el("tr", { class: options.selected === index ? "selected" : void 0 }, columns.map((c) => el("td", { class: c.class }, c.render ? c.render(row, index) : String(row[c.key] ?? "—"))))))));
}
function pagination(page, onPage) {
  const end = Math.min(page.offset + page.items.length, page.total);
  return el("div", { class: "pagination" }, el("span", {}, `${page.total ? page.offset + 1 : 0}–${end} / ${page.total} 条`), el("div", { class: "row" }, button("上一页", () => onPage(Math.max(0, page.offset - page.limit)), "ghost", { disabled: page.offset === 0 }), button("下一页", () => onPage(page.offset + page.limit), "ghost", { disabled: page.offset + page.limit >= page.total })));
}
function notice(text, tone = "info") {
  return el("div", { class: `notice ${tone}` }, icon("file", 16), el("span", {}, text));
}
function evidenceLink(evidence, ctx) {
  return button(evidence.label ?? evidence.id, () => showEvidence(evidence, ctx), "text");
}
async function showEvidence(evidence, ctx) {
  const dialog = el("dialog", { class: "evidence-dialog" }, el("div", { class: "dialog-heading" }, el("h2", {}, evidence.label ?? "证据文件"), button("关闭", () => dialog.close(), "ghost", { "aria-label": "关闭证据" })), loading());
  document.body.append(dialog);
  dialog.addEventListener("close", () => dialog.remove());
  dialog.showModal();
  ctx.signal?.addEventListener("abort", () => dialog.close(), { once: true });
  try {
    const data = evidence.text !== void 0 ? evidence : await ctx.api(`/api/research/evidence/${encodeURIComponent(evidence.id)}`);
    if (!dialog.isConnected) return;
    dialog.lastElementChild.remove();
    dialog.append(kv([["来源文件", data.path], ["SHA-256", data.sha256], ["大小", `${data.size_bytes} bytes`], ["格式", data.format]]), data.truncated ? notice("内容已按大小上限截断；文件身份对应原始完整文件。") : null, el("pre", { class: "evidence-text" }, data.text));
  } catch (error) {
    if (error.name === "AbortError") {
      dialog.close();
      return;
    }
    dialog.lastElementChild?.replaceWith(errorBox(error));
  }
}
const time = (value) => el("time", { datetime: value ?? "" }, dateLabel(value));
function bindAsync(form, handler, status) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (form.dataset.busy) return;
    form.dataset.busy = "true";
    const controls = [...form.querySelectorAll("button[type=submit]")];
    controls.forEach((c) => c.disabled = true);
    status.replaceChildren(loading("正在提交…"));
    try {
      await handler();
    } catch (error) {
      if (error.name !== "AbortError") status.replaceChildren(errorBox(error));
    } finally {
      delete form.dataset.busy;
      if (form.isConnected) controls.forEach((c) => c.disabled = false);
    }
  });
}
function collectionNotice(data, key, label = "记录") {
  const bound = data?.collections?.[key];
  if (!bound?.truncated) return document.createDocumentFragment();
  return notice(`${label}仅展示前 ${bound.shown} 项，共 ${bound.total} 项。`, "neutral");
}
export {
  badge,
  bindAsync,
  button,
  collectionNotice,
  el,
  empty,
  errorBox,
  evidenceLink,
  field,
  heading,
  icon,
  icons,
  json,
  kv,
  loading,
  notice,
  pagination,
  panel,
  select,
  showEvidence,
  svg,
  table,
  time
};
