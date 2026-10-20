import { createApi } from "./api.js";
import { el, icon, select, loading, errorBox, badge } from "./components.js";
import { createGeneration } from "./view-model.js";
import { renderOverview } from "./views/overview.js";
import { renderCode } from "./views/code.js";
import { renderTimeline } from "./views/timeline.js";
import { renderLab } from "./views/lab.js";
import { renderValidation } from "./views/validation.js";
import { renderTasks } from "./views/tasks.js";
import {renderIda} from './views/ida.js';
const routes = [["overview", "研究总览", "Overview", renderOverview], ["code", "代码与模型", "Code & models", renderCode], ["timeline", "运行时间线", "Runtime timeline", renderTimeline], ["lab", "模型实验室", "Model laboratory", renderLab], ["validation", "验证与比较", "Validation", renderValidation], ['ida','IDA 分析','IDA analysis',renderIda], ["tasks", "任务中心", "Task centre", renderTasks]];
const api = createApi(), generation = createGeneration();
let bootstrap, caseId, controller, main, casePicker, crumb, caseTag;
let researchPromise;
const root = document.querySelector("#app");
function currentRoute() {
  const hash = location.hash.slice(1).split("?")[0];
  return routes.find((r) => r[0] === hash) || routes[0];
}
function updateCasePicker() {
  casePicker.replaceChildren(...bootstrap.cases.map((c) => el("option", { value: c.id }, c.label)));
  casePicker.value = caseId;
}
async function route() {
  const activeRoute = currentRoute();
  controller?.abort();
  controller = new AbortController();
  const ticket = generation.next(), signal = controller.signal;
  document.querySelectorAll("[data-route]").forEach((link) => {
    const active = link.dataset.route === activeRoute[0];
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  const selected = bootstrap.cases.find((c) => c.id === caseId) || bootstrap.cases[0];
  crumb.textContent = activeRoute[1];
  caseTag.textContent = selected.kind === "research" ? "研究档案 / 只读" : selected.writable ? "实验工作区 / 可写" : "历史案例 / 只读";
  main.setAttribute("data-testid", `view-${activeRoute[0]}`);
  main.replaceChildren(loading());
  const context = { bootstrap, caseId, selected, signal, isCurrent: () => generation.isCurrent(ticket) && !signal.aborted, api: (path, options = {}) => api.request(path, { ...options, signal }), getResearch: () => {
    researchPromise ??= api.request("/api/research").catch((error) => {
      researchPromise = void 0;
      throw error;
    });
    return researchPromise;
  }, managedCaseId: selected.writable ? caseId : bootstrap.writableCaseId, navigate: (id) => {
    location.hash = id;
  }, refreshCases: async () => {
    const cases = await api.request("/api/cases", { signal });
    if (!generation.isCurrent(ticket)) return;
    bootstrap.cases = cases;
    updateCasePicker();
  }, selectCase: (id) => {
    caseId = id;
    updateCasePicker();
    route();
  } };
  try {
    const view = await activeRoute[3](context);
    if (context.isCurrent()) main.replaceChildren(view);
  } catch (error) {
    if (error.name !== "AbortError" && context.isCurrent()) main.replaceChildren(errorBox(error, () => route()));
  }
}
function shell() {
  casePicker = select([], { id: "case-selector", "aria-label": "当前案例", onchange: (event) => {
    caseId = event.target.value;
    route();
  } });
  updateCasePicker();
  main = el("main", { id: "main", tabindex: -1 });
  crumb = el("span", {}, "研究总览");
  caseTag = el("span", { class: "topbar-case" }, "研究档案 / 只读");
  root.replaceChildren(el("aside", { class: "sidebar" }, el("a", { class: "brand", href: "#overview", "aria-label": "WireFit 研究总览" }, el("span", { class: "brand-mark" }, "W"), el("span", {}, "wirefit", el("small", {}, "LOCAL RESEARCH WORKBENCH"))), el("div", { class: "sidebar-project" }, el("span", { class: "sidebar-label" }, "当前项目 / CASE"), casePicker, el("div", { class: "project-meta" }, el("span", { class: "live-dot" }), "本地证据 · 本机执行")), el("div", { class: "sidebar-label nav-label" }, "工作空间"), el("nav", { "aria-label": "主导航" }, routes.map(([id, title, english]) => el("a", { href: `#${id}`, "data-route": id }, icon(id), el("span", {}, title, el("small", {}, english))))), el("div", { class: "sidebar-bottom" }, el("span", { class: "local-pill" }, el("span", { class: "live-dot" }), "LOCAL ONLY"), el("p", {}, "证据驱动。作用域明确。"), el("small", {}, `WireFit ${bootstrap.version ?? "0.1.0"} · 127.0.0.1`))), el("div", { class: "workspace" }, el("div", { class: "topbar" }, el("div", { class: "breadcrumb" }, el("span", {}, "工作台"), el("span", { class: "slash" }, "/"), crumb), el("div", { class: "topbar-right" }, caseTag, el("span", { class: "connection" }, el("span", { class: "live-dot" }), "本地服务已连接"))), main, el("footer", { class: "workspace-footer" }, el("span", {}, "WIREFIT / 从观测走向可验证模型"), el("span", {}, "所有结果均受各自证据与作用域约束"))));
}
async function start() {
  try {
    bootstrap = await api.request("/api/bootstrap");
    api.setToken(bootstrap.token);
    if (bootstrap.research && typeof bootstrap.research === "object") researchPromise = Promise.resolve(bootstrap.research);
    if (!Array.isArray(bootstrap.cases) || !bootstrap.cases.length) throw new Error("服务未返回可用案例");
    caseId = bootstrap.defaultCaseId ?? bootstrap.cases[0].id;
    shell();
    await route();
  } catch (error) {
    root.replaceChildren(el("div", { class: "boot-screen" }, el("h1", {}, "WireFit"), errorBox(error, start)));
  }
}
window.addEventListener("hashchange", () => {
  if (bootstrap) route();
});
start();
document.querySelector(".skip-link")?.addEventListener("click", (event) => {
  event.preventDefault();
  document.querySelector("#main")?.focus();
});
