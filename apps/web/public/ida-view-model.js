const kinds = new Set(['overview', 'functions', 'strings', 'function', 'xrefs', 'bytes', 'types']);
function integer(value, minimum, maximum, label) {
  if (!/^[0-9]+$/.test(String(value))) throw new Error(`${label}必须为整数`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) throw new Error(`${label}须在 ${minimum}–${maximum} 之间`);
  return parsed;
}
function address(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{1,16}$/i.test(value.trim())) throw new Error('地址须为 0x 开头的最多 64 位十六进制');
  return '0x' + BigInt(value.trim()).toString(16);
}
function query(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || !kinds.has(value.kind)) throw new Error('查询类型不受支持');
  const fields = value.kind === 'overview' ? ['kind'] : ['function', 'xrefs'].includes(value.kind) ? ['kind', 'address'] : value.kind === 'bytes' ? ['kind', 'address', 'size'] : ['kind', 'pattern', 'offset', 'limit'];
  if (Object.keys(value).some(key => !fields.includes(key))) throw new Error('查询包含未支持的字段');
  const result = {kind: value.kind};
  if (fields.includes('address')) result.address = address(value.address);
  if (fields.includes('size')) result.size = integer(value.size, 1, 4096, '字节数');
  if (fields.includes('offset') && value.offset !== undefined) result.offset = integer(value.offset, 0, 1000000, '偏移');
  if (fields.includes('limit') && value.limit !== undefined) result.limit = integer(value.limit, 1, 200, '条数');
  if (value.pattern !== undefined) {
    if (typeof value.pattern !== 'string' || value.pattern.length > 256 || /[\x00-\x1f]/.test(value.pattern)) throw new Error('搜索条件过长或包含控制字符');
    result.pattern = value.pattern;
  }
  return result;
}
export function buildIdaQueries(input) {
  let queries;
  if (input.preset === 'json') {
    try { queries = JSON.parse(input.json); } catch { throw new Error('IDA 查询不是有效的 JSON'); }
  } else if (input.preset === 'overview') {
    queries = [{kind:'overview'}, {kind:'functions',offset:0,limit:50}, {kind:'strings',offset:0,limit:50}];
  } else if (input.preset === 'function') {
    queries = [{kind:'function',address:input.address}, {kind:'xrefs',address:input.address}];
  } else if (input.preset === 'bytes') {
    queries = [{kind:'bytes',address:input.address,size:input.size}];
  } else if (['functions', 'strings', 'types'].includes(input.preset)) {
    queries = [{kind:input.preset,offset:input.offset ?? 0,limit:input.limit ?? 50,...(input.pattern ? {pattern:input.pattern} : {})}];
  } else throw new Error('请选择一个 IDA 查询预设');
  if (!Array.isArray(queries) || queries.length < 1 || queries.length > 16) throw new Error('每个任务需要 1–16 个查询');
  return queries.map(query);
}
export const idaReadCase = (selected, caseId, writableCaseId) => selected?.kind === 'managed' ? caseId : writableCaseId;
export function idaCapabilityLabel(capability) {
  const labels = {verified:'已实测可用',not_probed:'已配置 · 运行未验证',probe_failed:'运行验证失败',invalid_configuration:'配置无效',not_configured:'未配置'};
  return labels[capability?.status] ?? '状态未验证';
}
export function idaReportSummary(result) {
  const queries = Array.isArray(result?.queries) ? result.queries : [];
  const completed = queries.filter(item => item.status === 'completed').length;
  const failed = queries.filter(item => item.status === 'failed').length;
  const label = {partial:'部分查询完成',failed:'分析失败',cancelled:'已取消',completed:'查询完成'}[result?.status] ?? '查询状态未确认';
  return {completed,failed,other:queries.length-completed-failed,total:queries.length,label};
}
export function idaCodeText(data) {
  for (const value of [data?.pseudocode,data?.code,data?.decompilation,data?.function?.pseudocode,data?.decompile?.code]) {
    if (typeof value === 'string') return value;
  }
  return null;
}
/** Polling a job does not change the selected evidence or invalidate its downloads. */
export function createIdaSelection() {
  let key,ticket=0;
  return {
    select(caseId,jobId,runId){
      const next=JSON.stringify([caseId,jobId??null,runId??null]);
      const changed=next!==key;
      if(changed){key=next;ticket++;}
      return {ticket,changed};
    },
    isCurrent(value){return value===ticket;},
  };
}
