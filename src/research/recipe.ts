import {createHash} from 'node:crypto';
import {assert,WirefitError} from '../shared.js';
import type {CheckComparator,CheckDerivation} from './types.js';

/**
 * The recipe kernel interpreter.
 *
 * A direction contributes data only: a derivation that says which artifact
 * role and which path to read, plus the expected value. The algorithm that
 * turns that into an observation lives here, once, and is mirrored by an
 * independent Python implementation in the research lane. Both implementations
 * follow the specification in docs/RESEARCH-PROTOCOL.md literally.
 *
 * Restricted path language:
 *   path    := segment ('.' segment)*
 *   segment := NAME | NAME '[' '*' ']' | NAME '[' INT ']'
 */

/** Where a kernel reads its inputs from. */
export interface RecipeContext{
 /** A registered JSON document. */
 document(role:string):unknown;
 /** A registered binary artifact. */
 bytes(role:string):Buffer;
}

export type Scalar=string|number|boolean|null;

const SEGMENT_PATTERN=/^([A-Za-z_][A-Za-z0-9_]*)(?:\[(\*|[0-9]+)\])?$/;

interface Segment{ name:string; index:'*'|number|null; }

export function parsePath(path:string):Segment[]{
 assert(typeof path==='string'&&path.length>0,'RECIPE_PATH_INVALID','Recipe path must be a nonempty string');
 assert(!path.includes('\0'),'RECIPE_PATH_INVALID','Recipe path must not contain NUL');
 const segments:Segment[]=[];
 for(const raw of path.split('.')){
  const match=SEGMENT_PATTERN.exec(raw);
  assert(match!==null,'RECIPE_PATH_INVALID','Recipe path segment is invalid: '+raw);
  const index=match[2]===undefined?null:match[2]==='*'?'*':Number(match[2]);
  segments.push({name:match[1]!,index});
 }
 return segments;
}

/** Selects the nodes addressed by a path. */
export function selectPath(root:unknown,path:string):unknown[]{
 let current:unknown[]=[root];
 for(const segment of parsePath(path)){
  const next:unknown[]=[];
  for(const node of current){
   assert(node!==null&&typeof node==='object'&&!Array.isArray(node),
    'RECIPE_PATH_INVALID','Recipe path segment '+segment.name+' does not address an object');
   const record=node as Record<string,unknown>;
   assert(Object.hasOwn(record,segment.name),'RECIPE_PATH_INVALID','Recipe path property is absent: '+segment.name);
   const value=record[segment.name];
   if(segment.index===null)next.push(value);
   else if(segment.index==='*'){
    assert(Array.isArray(value),'RECIPE_PATH_INVALID','Recipe path wildcard requires an array: '+segment.name);
    for(const item of value)next.push(item);
   }else{
    assert(Array.isArray(value),'RECIPE_PATH_INVALID','Recipe path index requires an array: '+segment.name);
    assert(segment.index<value.length,'RECIPE_PATH_INVALID','Recipe path index is out of range: '+segment.name+'['+segment.index+']');
    next.push(value[segment.index]);
   }
  }
  current=next;
 }
 return current;
}

function isScalar(value:unknown):value is Scalar{
 return value===null||typeof value==='string'||typeof value==='boolean'||typeof value==='number';
}

/**
 * Normalizes a scalar for cross-implementation comparison.
 * Integral floating point values collapse onto integers so that a Python
 * auditor reading `1.0` and a TypeScript auditor reading `1` agree.
 */
export function normalizeScalar(value:Scalar):Scalar{
 if(typeof value==='number'&&Number.isFinite(value)&&Number.isInteger(value))return value===0?0:value;
 return value;
}

/** Type-prefixed encoding of a scalar, used for set members. */
export function encodeScalar(value:Scalar):string{
 const normalized=normalizeScalar(value);
 if(normalized===null)return 'z:null';
 if(typeof normalized==='boolean')return 'b:'+(normalized?'true':'false');
 if(typeof normalized==='number')return 'n:'+String(normalized);
 return 's:'+normalized;
}

/** Code-point ordering, matching Python's default string ordering. */
export function compareCodePoints(left:string,right:string):number{
 const a=Array.from(left),b=Array.from(right);
 const length=Math.min(a.length,b.length);
 for(let index=0;index<length;index++){
  const x=a[index]!.codePointAt(0)!,y=b[index]!.codePointAt(0)!;
  if(x!==y)return x<y?-1:1;
 }
 return a.length===b.length?0:a.length<b.length?-1:1;
}

/** Extracts the comparable values of the selected nodes. */
export function selectValues(ctx:RecipeContext,derivation:CheckDerivation):Scalar[]{
 const document=ctx.document(derivation.artifact_role);
 const selected=selectPath(document,derivation.path??'');
 const field=derivation.field;
 const values:Scalar[]=[];
 for(const node of selected){
  let value:unknown=node;
  if(field!==undefined){
   assert(node!==null&&typeof node==='object'&&!Array.isArray(node),
    'RECIPE_VALUE_TYPE_MISMATCH','Recipe field requires selected object nodes');
   const record=node as Record<string,unknown>;
   assert(Object.hasOwn(record,field),'RECIPE_VALUE_TYPE_MISMATCH','Recipe field is absent on a selected node: '+field);
   value=record[field];
  }
  assert(isScalar(value),'RECIPE_VALUE_TYPE_MISMATCH','Recipe values must be scalars');
  values.push(normalizeScalar(value));
 }
 return values;
}

function secondValues(ctx:RecipeContext,derivation:CheckDerivation):Scalar[]{
 const role=derivation.second_artifact_role;
 assert(role!==undefined,'RECIPE_DERIVATION_INVALID','set_equality needs a second artifact role');
 const document=ctx.document(role);
 const selected=selectPath(document,derivation.second_path??'');
 const field=derivation.field;
 const values:Scalar[]=[];
 for(const node of selected){
  let value:unknown=node;
  if(field!==undefined){
   assert(node!==null&&typeof node==='object'&&!Array.isArray(node),
    'RECIPE_VALUE_TYPE_MISMATCH','Recipe field requires selected object nodes');
   const record=node as Record<string,unknown>;
   assert(Object.hasOwn(record,field),'RECIPE_VALUE_TYPE_MISMATCH','Recipe field is absent on a selected node: '+field);
   value=record[field];
  }
  assert(isScalar(value),'RECIPE_VALUE_TYPE_MISMATCH','Recipe values must be scalars');
  values.push(normalizeScalar(value));
 }
 return values;
}

function sameScalar(left:Scalar,right:Scalar):boolean{
 const a=normalizeScalar(left),b=normalizeScalar(right);
 if(typeof a!==typeof b)return false;
 if(typeof a==='number'&&typeof b==='number')return a===b;
 return a===b;
}

function serializeSet(values:Scalar[]):string{
 const encoded=new Set(values.map(encodeScalar));
 return [...encoded].sort(compareCodePoints).join('|');
}

function parseSet(value:string):string[]{
 if(value==='')return [];
 return [...new Set(value.split('|').filter((item)=>item!==''))].sort(compareCodePoints);
}

function countBytePattern(bytes:Buffer,pattern:Buffer):number{
 if(pattern.length===0)return 0;
 let count=0;
 let from=0;
 for(;;){
  const index=bytes.indexOf(pattern,from);
  if(index<0)break;
  count++;
  from=index+1;
 }
 return count;
}

/**
 * Computes one observation from a derivation.
 * Throws a WirefitError with a RECIPE_* code when the derivation cannot be
 * evaluated; the caller turns that into an inconclusive claim.
 */
export function evaluateKernel(ctx:RecipeContext,derivation:CheckDerivation):string|number|boolean{
 switch(derivation.kernel){
  case 'row_count':{
   const document=ctx.document(derivation.artifact_role);
   return selectPath(document,derivation.path??'').length;
  }
  case 'distinct_count':{
   const values=selectValues(ctx,derivation);
   return new Set(values.map(encodeScalar)).size;
  }
  case 'field_count':{
   assert(derivation.value!==undefined,'RECIPE_DERIVATION_INVALID','field_count needs a value');
   const values=selectValues(ctx,derivation);
   return values.filter((value)=>sameScalar(value,derivation.value as Scalar)).length;
  }
  case 'field_sum':
  case 'field_min':
  case 'field_max':{
   const values=selectValues(ctx,derivation);
   assert(values.length>0,'RECIPE_EMPTY_SELECTION','Recipe aggregation requires a nonempty selection');
   for(const value of values)
    assert(typeof value==='number'&&Number.isInteger(value),
     'RECIPE_VALUE_TYPE_MISMATCH','Recipe aggregation requires integer values');
   const numbers=values as number[];
   if(derivation.kernel==='field_sum')return numbers.reduce((total,value)=>total+value,0);
   if(derivation.kernel==='field_min')return Math.min(...numbers);
   return Math.max(...numbers);
  }
  case 'all_equal':{
   assert(derivation.value!==undefined,'RECIPE_DERIVATION_INVALID','all_equal needs a value');
   const values=selectValues(ctx,derivation);
   if(values.length===0)return false;
   return values.every((value)=>sameScalar(value,derivation.value as Scalar));
  }
  case 'any_equal':{
   assert(derivation.value!==undefined,'RECIPE_DERIVATION_INVALID','any_equal needs a value');
   const values=selectValues(ctx,derivation);
   return values.some((value)=>sameScalar(value,derivation.value as Scalar));
  }
  case 'set_equality':{
   if(derivation.second_artifact_role!==undefined){
    const left=serializeSet(selectValues(ctx,derivation));
    const right=serializeSet(secondValues(ctx,derivation));
    return left===right;
   }
   return serializeSet(selectValues(ctx,derivation));
  }
  case 'file_sha256':{
   const bytes=ctx.bytes(derivation.artifact_role);
   return createHash('sha256').update(bytes).digest('hex');
  }
  case 'byte_pattern_count':{
   assert(typeof derivation.pattern_hex==='string'&&derivation.pattern_hex.length>0&&derivation.pattern_hex.length%2===0,
    'RECIPE_DERIVATION_INVALID','byte_pattern_count needs an even-length hex pattern');
   const bytes=ctx.bytes(derivation.artifact_role);
   return countBytePattern(bytes,Buffer.from(derivation.pattern_hex,'hex'));
  }
  default:
   throw new WirefitError('RECIPE_KERNEL_UNKNOWN','Unknown recipe kernel: '+String(derivation.kernel));
 }
}

/** Applies a comparator to an observation and its pre-registered expectation. */
export function compareObservation(
 observed:string|number|boolean,
 expected:string|number|boolean,
 comparator:CheckComparator,
):boolean{
 switch(comparator){
  case 'eq':{
   if(typeof observed==='number'&&typeof expected==='number')return observed===expected;
   if(typeof observed!==typeof expected)return false;
   return observed===expected;
  }
  case 'ne':{
   if(typeof observed==='number'&&typeof expected==='number')return observed!==expected;
   if(typeof observed!==typeof expected)return true;
   return observed!==expected;
  }
  case 'gte':case 'lte':case 'gt':case 'lt':{
   if(typeof observed!=='number'||typeof expected!=='number')return false;
   if(comparator==='gte')return observed>=expected;
   if(comparator==='lte')return observed<=expected;
   if(comparator==='gt')return observed>expected;
   return observed<expected;
  }
  case 'identical_set':{
   const left=parseSet(String(observed)),right=parseSet(String(expected));
   return left.length===right.length&&left.every((item,index)=>item===right[index]);
  }
  case 'subset':{
   const left=parseSet(String(observed)),right=parseSet(String(expected));
   return left.every((item)=>right.includes(item));
  }
  case 'superset':{
   const left=parseSet(String(observed)),right=parseSet(String(expected));
   return right.every((item)=>left.includes(item));
  }
  default:
   throw new WirefitError('RECIPE_COMPARATOR_UNKNOWN','Unknown comparator: '+String(comparator));
 }
}
