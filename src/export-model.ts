import type { BvModel, BvNode, CoreType } from './types.js';
import { validateBvModel } from './model.js';
function expression(n: BvNode, refs: Map<string, string>, types: Map<string, CoreType>): string {
  const a = refs.get(n.args[0]!)!,
    b = refs.get(n.args[1]!)!,
    c = refs.get(n.args[2]!)!;
  const w = n.type.kind === 'bv' ? n.type.width : 8;
  const aw = (types.get(n.args[0]!) as any)?.width;
  const norm = (s: string) => `u(${s},${w})`;
  if (n.op === 'const') {
    const v = n.attrs.value!;
    return v.kind === 'bool' ? String(v.value) : `BigInt(${JSON.stringify(v.bits)})`;
  }
  const ops: Record<string, string> = {
    bv_add: '+',
    bv_sub: '-',
    bv_mul: '*',
    bv_and: '&',
    bv_or: '|',
    bv_xor: '^',
    bv_eq: '===',
    bv_ne: '!==',
    bv_ult: '<',
    bv_ule: '<=',
    bool_and: '&&',
    bool_or: '||',
  };
  if (ops[n.op]) {
    const code = `(${a}${ops[n.op]}${b})`;
    return n.type.kind === 'bv' ? norm(code) : code;
  }
  switch (n.op) {
    case 'copy':
      return a;
    case 'bv_neg':
      return norm(`-${a}`);
    case 'bv_not':
      return norm(`~${a}`);
    case 'bool_not':
      return `!${a}`;
    case 'bv_slt':
      return `(s(${a},${aw})<s(${b},${aw}))`;
    case 'bv_sle':
      return `(s(${a},${aw})<=s(${b},${aw}))`;
    case 'bv_nonzero':
      return `(${a}!==0n)`;
    case 'bool_to_bv':
      return `(${a}?1n:0n)`;
    case 'select':
      return `(${a}?${b}:${c})`;
    case 'bv_shl':
      return `(${b}>=${w}n?0n:${norm(`${a}<<${b}`)})`;
    case 'bv_lshr':
      return `(${b}>=${w}n?0n:${a}>>${b})`;
    case 'bv_ashr':
      return `(${b}>=${w}n?${norm(`s(${a},${w})<0n?-1n:0n`)}:${norm(`s(${a},${w})>>${b}`)})`;
    case 'bv_zext':
      return a;
    case 'bv_sext':
      return norm(`s(${a},${aw})`);
    case 'bv_extract':
      return norm(`${a}>>${n.attrs.low}n`);
    case 'bv_concat':
      return norm(`(${a}<<${(types.get(n.args[1]!) as any).width}n)|${b}`);
    default:
      throw new Error(`Unsupported ${n.op}`);
  }
}
const tsHelpers = `
export type CoreType = {kind:'bool'} | {kind:'bv';width:8|16|32|64};
export type CoreValue = {kind:'bool';value:boolean} | {kind:'bv';width:8|16|32|64;bits:string};
const u=(v:bigint,w:number):bigint=>BigInt.asUintN(w,v);
const s=(v:bigint,w:number):bigint=>BigInt.asIntN(w,v);
function decode(v:unknown,t:{kind:'bool'}):boolean;
function decode(v:unknown,t:{kind:'bv';width:8|16|32|64}):bigint;
function decode(input:unknown,t:CoreType):boolean|bigint{
 if(!input||typeof input!=='object'||Array.isArray(input))throw Error('INVALID_VALUE');
 const v=input as Record<string,unknown>,keys=Object.keys(v).sort().join(',');
 if(t.kind==='bool'){if(keys!=='kind,value'||v.kind!=='bool'||typeof v.value!=='boolean')throw Error('INVALID_VALUE');return v.value;}
 if(keys!=='bits,kind,width'||v.kind!=='bv'||v.width!==t.width||typeof v.bits!=='string'||!new RegExp('^0x[0-9a-f]{'+t.width/4+'}$').test(v.bits))throw Error('INVALID_VALUE');return BigInt(v.bits);
}
function wire(v:boolean,t:{kind:'bool'}):CoreValue;
function wire(v:bigint,t:{kind:'bv';width:8|16|32|64}):CoreValue;
function wire(v:boolean|bigint,t:CoreType):CoreValue{
 if(t.kind==='bool'){if(typeof v!=='boolean')throw Error('INTERNAL_TYPE_ERROR');return {kind:'bool',value:v};}
 if(typeof v!=='bigint')throw Error('INTERNAL_TYPE_ERROR');return {kind:'bv',width:t.width,bits:'0x'+u(v,t.width).toString(16).padStart(t.width/4,'0')};
}
`;
const jsHelpers = `
const u=(v,w)=>BigInt.asUintN(w,v);
const s=(v,w)=>BigInt.asIntN(w,v);
function decode(v,t){if(!v||typeof v!=='object'||Array.isArray(v))throw Error('INVALID_VALUE');const keys=Object.keys(v).sort().join(',');if(t.kind==='bool'){if(keys!=='kind,value'||v.kind!=='bool'||typeof v.value!=='boolean')throw Error('INVALID_VALUE');return v.value;}if(keys!=='bits,kind,width'||v.kind!=='bv'||v.width!==t.width||typeof v.bits!=='string'||!new RegExp('^0x[0-9a-f]{'+t.width/4+'}$').test(v.bits))throw Error('INVALID_VALUE');return BigInt(v.bits);}
const wire=(v,t)=>t.kind==='bool'?{kind:'bool',value:v}:{kind:'bv',width:t.width,bits:'0x'+u(v,t.width).toString(16).padStart(t.width/4,'0')};
`;
/** Compiles a closed module: no eval, child process, dependency, or source identifier interpolation. */
export function exportModelSource(model: BvModel, language: 'js' | 'ts' = 'js'): string {
  validateBvModel(model);
  const refs = new Map<string, string>(),
    types = new Map<string, CoreType>(),
    lines: string[] = [];
  model.inputs.forEach((p, i) => {
    refs.set(p.id, `v${i}`);
    types.set(p.id, p.type);
    lines.push(`const v${i}=decode(inputs[${JSON.stringify(p.id)}],${JSON.stringify(p.type)});`);
  });
  model.nodes.forEach((n, i) => {
    const name = `v${model.inputs.length + i}`;
    lines.push(`const ${name}=${expression(n, refs, types)};`);
    refs.set(n.id, name);
    types.set(n.id, n.type);
  });
  const constraints = model.domain.constraints.map((c) => {
    const a = refs.get(c.input)!,
      v = c.value;
    const b =
      v.kind === 'bool'
        ? String(v.value)
        : v.kind === 'bv'
          ? `BigInt(${JSON.stringify(v.bits)})`
          : '0n';
    const w = v.kind === 'bv' ? v.width : 8;
    switch (c.op) {
      case 'eq':
        return `(${a}===${b})`;
      case 'ne':
        return `(${a}!==${b})`;
      case 'ule':
        return `(${a}<=${b})`;
      case 'uge':
        return `(${a}>=${b})`;
      case 'sle':
        return `(s(${a},${w})<=s(${b},${w}))`;
      case 'sge':
        return `(s(${a},${w})>=s(${b},${w}))`;
      default:
        throw new Error('Unsupported domain');
    }
  });
  return `// Standalone Wirefit exact BV model. ${model.semantics_profile}\nexport const model=${JSON.stringify(model)}${language === 'ts' ? ' as const' : ''};\n${language === 'ts' ? tsHelpers : jsHelpers}\nexport function evaluate(inputs${language === 'ts' ? ': Record<string, unknown>' : ''})${language === 'ts' ? ': Record<string,CoreValue>' : ''}{\nif(!inputs||typeof inputs!=='object'||Array.isArray(inputs)||Object.keys(inputs).length!==model.inputs.length||!model.inputs.every(p=>Object.hasOwn(inputs,p.id)))throw Error('INVALID_INPUT');\n${lines.slice(0, model.inputs.length).join('\n')}\nif(!(${constraints.length ? constraints.join('&&') : 'true'}))throw Error('OUT_OF_DOMAIN');\n${lines.slice(model.inputs.length).join('\n')}\nreturn Object.fromEntries([${model.outputs.map((o) => `[${JSON.stringify(o.id)},wire(${refs.get(o.ref)},${JSON.stringify(o.type)})]`).join(',')}]);\n}\nexport default evaluate;\n`;
}
