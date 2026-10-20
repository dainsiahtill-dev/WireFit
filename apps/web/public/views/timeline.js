import { el, heading, panel, badge, button, select, field, loading, errorBox, empty, kv, json, notice, pagination, evidenceLink } from "../components.js";
import { createGeneration, pretty } from "../view-model.js";
async function renderTimeline(ctx) {
  const research = await ctx.getResearch(), traces = research.traces ?? [];
  let selected = traces[0], offset = 0;
  const generation = createGeneration(), events = el("div", {}), detail = el("div", { class: "event-details" }, empty("选择一个事件", "查看寄存器、栈、代码与原始详情。"));
  const runSelect = select(traces.map((t) => ({ value: t.id, label: `${t.label} · PID ${t.pid ?? "未记录"}` })), { "aria-label": "选择运行", onchange: (event) => {
    selected = traces.find((t) => t.id === event.target.value);
    offset = 0;
    load();
  } });
  const type = select([{ value: "", label: "所有事件" }, { value: "api", label: "API 调用" }, { value: "breakpoint", label: "断点" }, { value: "exception", label: "异常" }, { value: "module", label: "模块" }, { value: "snapshot", label: "快照" }], { "aria-label": "事件类型", onchange: () => {
    offset = 0;
    load();
  } }), search = el("input", { type: "search", placeholder: "搜索地址、API、事件…", "aria-label": "搜索事件" });
  const form = el("form", { class: "filter-bar", onsubmit: (event) => {
    event.preventDefault();
    offset = 0;
    load();
  } }, field("事件类型", type), field("关键字", search), el("button", { class: "button secondary", type: "submit" }, "搜索"));
  const meta = el("div", { class: "run-meta" });
  function showEvent(event) {
    detail.replaceChildren(el("div", { class: "event-detail-heading" }, badge(event.type, event.type), el("h3", {}, event.label)), kv([["事件序号", event.index], ["地址", event.address], ["线程", event.thread_id], ["时间", event.time]]), el("h4", {}, "寄存器 / Context"), event.context ? json(event.context) : notice("此事件未记录寄存器。", "neutral"), el("h4", {}, "栈 / Stack"), event.stack != null ? json(event.stack) : el("p", { class: "muted" }, "未记录栈信息"), el("h4", {}, "代码 / Code"), event.code != null ? json(event.code) : el("p", { class: "muted" }, "未记录代码"), el("h4", {}, "内存快照 / Snapshots"), event.details?.snapshots?.length ? el("div", { class: "snapshot-list" }, event.details.snapshots.map((snapshot) => el("div", { class: "snapshot-row" }, evidenceLink({ id: snapshot.evidence_id, label: `${snapshot.phase ?? "快照"} · RVA ${snapshot.rva ?? "未记录"}` }, ctx), el("small", { class: "mono" }, `${snapshot.size_bytes ?? "未知"} bytes`)))) : el("p", { class: "muted small" }, "此事件未登记内存快照"), el("h4", {}, "原始详情"), json(event.details), event.evidence_id ? evidenceLink({ id: event.evidence_id, label: "查看原始证据" }, ctx) : null);
  }
  async function load() {
    if (!selected) return;
    const ticket = generation.next();
    events.replaceChildren(loading());
    detail.replaceChildren(empty("选择一个事件", "所有事件仅属于当前选择的运行。"));
    meta.replaceChildren(badge(selected.status), el("span", { class: "mono" }, `PID ${selected.pid ?? "未记录"}`), el("span", {}, `${selected.event_count} 条归档事件`), el("span", { class: "mono small" }, selected.source));
    try {
      const query = new URLSearchParams({ offset: String(offset), limit: "30" });
      if (type.value) query.set("type", type.value);
      if (search.value.trim()) query.set("q", search.value.trim());
      const page = await ctx.api(`/api/research/traces/${encodeURIComponent(selected.id)}?${query}`);
      if (!ctx.isCurrent() || !generation.isCurrent(ticket)) return;
      events.replaceChildren(page.items.length ? el("div", { class: "timeline-list" }, page.items.map((event, index) => button(el("span", { class: "event-content" }, el("span", { class: "event-index mono" }, String(event.index).padStart(5, "0")), el("span", { class: `event-type type-${["api", "breakpoint", "exception", "module"].includes(event.type) ? event.type : "other"}` }, event.type), el("span", { class: "event-label" }, el("strong", {}, event.label), el("small", { class: "mono" }, event.address ?? event.time ?? "位置未记录")), el("span", { class: "event-thread mono" }, event.thread_id == null ? "—" : `T${event.thread_id}`)), (eventClick) => {
        events.querySelectorAll(".event-row").forEach((n) => n.classList.remove("selected"));
        eventClick.currentTarget.classList.add("selected");
        showEvent(event);
      }, "event-row"))) : empty("没有匹配事件", "请调整事件类型或关键字。"), pagination(page, (next) => {
        offset = next;
        load();
      }));
    } catch (error) {
      if (error.name !== "AbortError" && ctx.isCurrent() && generation.isCurrent(ticket)) events.replaceChildren(errorBox(error, load));
    }
  }
  await load();
  return el("div", { class: "view" }, heading("RUNTIME TIMELINE", "运行时间线", "逐次检查真实运行中的事件。每一条时间线保持独立的进程与证据来源。"), ctx.selected.kind !== "research" ? notice("当前展示 vmde 只读研究档案的运行；实验工作区任务可在任务中心查看。", "neutral") : null, panel("运行选择", "Run / 事件不会跨进程拼接", el("div", { class: "run-selection" }, field("归档运行", runSelect), meta)), el("div", { class: "timeline-layout" }, panel("事件序列", "按归档顺序排列 · 每页 30 条", el("div", {}, form, events)), panel("事件详情", "选中事件的原始上下文", detail)));
}
export {
  renderTimeline
};
