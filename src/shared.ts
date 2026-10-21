import {createHash, randomUUID} from 'node:crypto';
import {readFileSync, existsSync} from 'node:fs';
import {readFile,stat} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
import {Ajv2020} from 'ajv/dist/2020.js';
import type {ValidateFunction} from 'ajv';
import type {Budget,StructuredError} from './types.js';

let directory=path.dirname(fileURLToPath(import.meta.url));
while(!existsSync(path.join(directory,'contracts','model.schema.json'))){
 const parent=path.dirname(directory);
 if(parent===directory)throw new Error('Wirefit contracts directory not found');
 directory=parent;
}
export const rootDir=directory;
export class WirefitError extends Error {
 constructor(public code:string,message:string,public details?:unknown){super(message);this.name='WirefitError';}
}
export function assert(condition:unknown,code:string,message:string):asserts condition {
 if(!condition)throw new WirefitError(code,message);
}
export function errorRecord(error:unknown,scope='wirefit'):StructuredError {
 return {code:error instanceof WirefitError?error.code:'INTERNAL_ERROR',message:(error instanceof Error?error.message:String(error)).slice(0,4096),scope,retryable:false,artifacts:[]};
}
export function id(prefix:string):string {return prefix+'_'+randomUUID().replaceAll('-','');}
export function canonical(value:unknown):string {
 const visiting=new Set<object>();
 function encode(item:unknown):string{
  if(item===null)return 'null';
  if(typeof item==='string'||typeof item==='boolean')return JSON.stringify(item);
  if(typeof item==='number'){
   assert(Number.isSafeInteger(item),'CANONICAL_INVALID','Canonical numbers must be safe integers');
   return JSON.stringify(item);
  }
  assert(typeof item==='object'&&item!==null,'CANONICAL_INVALID','Canonical value must be JSON');
  assert(!visiting.has(item),'CANONICAL_INVALID','Canonical value cannot contain a cycle');
  visiting.add(item);
  let result:string;
  if(Array.isArray(item))result='['+item.map(encode).join(',')+']';
  else{
   const prototype=Object.getPrototypeOf(item);
   assert(prototype===Object.prototype||prototype===null,'CANONICAL_INVALID','Canonical objects must be plain');
   const record=item as Record<string,unknown>;
   const keys=Object.keys(record).sort();
   for(const key of keys)assert(/^[\x20-\x7e]*$/.test(key),'CANONICAL_INVALID','Canonical object keys must be ASCII');
   result='{'+keys.map(key=>JSON.stringify(key)+':'+encode(record[key])).join(',')+'}';
  }
  visiting.delete(item);
  return result;
 }
 return encode(value);
}
export function sha256(value:string|Uint8Array):string {return createHash('sha256').update(value).digest('hex');}
export function hashObject(value:unknown):string {return sha256(canonical(value));}
export function semanticHash(model:unknown):string {
 const source=model as Record<string,unknown>;
 const object:Record<string,unknown>={};
 for(const key of ['schema_version','kind','semantics_profile','inputs','nodes','definition','outputs','domain']){
  if(Object.hasOwn(source,key))object[key]=source[key];
 }
 return hashObject(object);
}
export function sourceHash(model:unknown):string {
 const source=model as Record<string,unknown>;
 return hashObject({scope:source.scope,provenance:source.provenance});
}
const validators=new Map<string,ValidateFunction>();
function loadSchemas():void{
 if(validators.size)return;
 const ajv=new Ajv2020({strict:true,allErrors:true,validateFormats:true});
 ajv.addFormat('date-time',{type:'string',validate:(value:string)=>/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(value)&&Number.isFinite(Date.parse(value))});
 const names=['common','model','budget','oracle','oracle-request','oracle-response','input-sample','observation','dataset','experiment-request','experiment-result','research-direction','research-request','research-result'];
 for(const name of names){
  const schema=JSON.parse(readFileSync(path.join(rootDir,'contracts',name+'.schema.json'),'utf8')) as Record<string,unknown>;
  ajv.addSchema(schema);
 }
 for(const name of names){
  const schema=JSON.parse(readFileSync(path.join(rootDir,'contracts',name+'.schema.json'),'utf8')) as {$id:string};
  const compiled=ajv.getSchema(schema.$id);
  assert(compiled,'SCHEMA_INVALID','Could not compile '+name);
  validators.set(name,compiled);
 }
}
export function schemaNames():string[]{loadSchemas();return [...validators.keys()];}
export function validateSchema<T=unknown>(name:string,value:unknown):T{
 loadSchemas();
 const normalized=name.replace(/\.schema\.json$/,'');
 const validator=validators.get(normalized);
 assert(validator,'SCHEMA_INVALID','Unknown local contract '+name);
 if(!validator(value))throw new WirefitError('SCHEMA_INVALID','Invalid '+name+': '+JSON.stringify(validator.errors?.slice(0,8)),validator.errors);
 return value as T;
}
export async function readJson<T=unknown>(file:string):Promise<T>{
 const info=await stat(file);
 assert(info.isFile()&&info.size<=16*1024*1024,'RESOURCE_LIMIT','JSON file size limit exceeded');
 try{return JSON.parse(await readFile(file,'utf8')) as T;}
 catch(error){if(error instanceof SyntaxError)throw new WirefitError('JSON_INVALID','Invalid JSON in '+file+': '+error.message);throw error;}
}
export async function readJsonl<T=unknown>(file:string):Promise<T[]>{
 const info=await stat(file);
 assert(info.isFile()&&info.size<=128*1024*1024,'RESOURCE_LIMIT','JSONL file size limit exceeded');
 const text=await readFile(file,'utf8');
 const lines=text.split(/\r?\n/);
 const result:T[]=[];
 for(const [index,line] of lines.entries()){
  if(line===''){assert(index===lines.length-1||index===lines.length-2&&lines[index+1]==='','JSON_INVALID','Empty JSONL line '+(index+1));continue;}
  assert(Buffer.byteLength(line,'utf8')<=1024*1024,'RESOURCE_LIMIT','JSONL line '+(index+1)+' exceeds size limit');
  try{result.push(JSON.parse(line) as T);}
  catch(error){throw new WirefitError('JSON_INVALID','Invalid JSONL line '+(index+1)+': '+(error instanceof Error?error.message:String(error)));}
 }
 return result;
}
export const defaultBudget:Budget={wall_time_ms:120000,solver_soft_time_ms:10000,solver_hard_time_ms:15000,max_candidates:50000,max_ast_nodes:9,max_oracle_calls:512,max_iterations:2000,seed:20261019};
export function resolveBudget(value:unknown={}):Budget{
 assert(value!==null&&typeof value==='object'&&!Array.isArray(value),'BUDGET_INVALID','Budget must be an object');
 const budget=validateSchema<Budget>('budget',{...defaultBudget,...value});
 assert(budget.solver_soft_time_ms<=budget.solver_hard_time_ms&&budget.solver_hard_time_ms<=budget.wall_time_ms,'BUDGET_INVALID','Solver deadlines must fit wall deadline');
 return budget;
}
