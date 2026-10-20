import path from 'node:path';
import {assert} from './shared.js';

export interface AcquisitionOptions {file:string;config:string;plan:string;out:string;python:string;powershell?:string;capture_at_ms:number;callers:string[]}
const CODE='ACQUISITION_ARGUMENTS_INVALID';
const scalar=['file','config','plan','out','python','powershell','capture-at-ms'];
function filePath(value:unknown,absolute=false):string{
 assert(typeof value==='string'&&value.length>0&&value.length<=32767&&!/[\0\r\n]/.test(value),CODE,'Acquisition paths must be bounded text');
 assert(!absolute||path.isAbsolute(value),CODE,'Observer executables must be explicit absolute paths');
 const result=path.resolve(value);
 if(process.platform==='win32')assert(/^[A-Za-z]:[\\/]/.test(result)&&!result.slice(2).includes(':'),CODE,'Only ordinary local drive paths are supported');
 return result;
}
export function normalizeAcquisitionOptions(value:unknown):AcquisitionOptions{
 assert(value!==null&&typeof value==='object'&&!Array.isArray(value),CODE,'Acquisition options must be an object');
 const record=value as Record<string,unknown>;
 assert(Object.keys(record).every(key=>['file','config','plan','out','python','powershell','capture_at_ms','callers'].includes(key)),CODE,'Unknown acquisition option');
 assert(Number.isSafeInteger(record.capture_at_ms)&&Number(record.capture_at_ms)>=0&&Number(record.capture_at_ms)<60000,CODE,'Capture offset must be an integer from 0 through 59999 milliseconds');
 assert(Array.isArray(record.callers)&&record.callers.length<=16,CODE,'At most sixteen caller RVAs are supported');
 const callers:string[]=[],seen=new Set<string>();
 for(const caller of record.callers){
  assert(typeof caller==='string'&&/^0x[0-9a-f]{1,8}$/i.test(caller),CODE,'Caller RVA must be a 32-bit hexadecimal string');
  const normalized='0x'+BigInt(caller).toString(16);
  assert(!seen.has(normalized),CODE,'Caller RVAs must be unique');seen.add(normalized);callers.push(normalized);
 }
 return {file:filePath(record.file),config:filePath(record.config),plan:filePath(record.plan),out:filePath(record.out),python:filePath(record.python,true),
  ...(record.powershell===undefined?{}:{powershell:filePath(record.powershell,true)}),capture_at_ms:Number(record.capture_at_ms),callers};
}
export function parseAcquisitionArgs(argv:readonly string[]):AcquisitionOptions{
 assert(Array.isArray(argv)&&argv.length<=64&&argv.length%2===0,CODE,'Acquisition arguments must be explicit flag/value pairs');
 const values:Record<string,string>={},callers:string[]=[];
 for(let index=0;index<argv.length;index+=2){
  const flag=argv[index],value=argv[index+1];
  assert(typeof flag==='string'&&flag.startsWith('--')&&typeof value==='string'&&value.length>0&&!value.startsWith('--'),CODE,'Every acquisition flag needs a value');
  const key=flag.slice(2);
  if(key==='caller-rva'){callers.push(value);continue;}
  assert(scalar.includes(key)&&!Object.hasOwn(values,key),CODE,'Unsupported or duplicate acquisition flag: '+flag);values[key]=value;
 }
 for(const name of ['file','config','plan','out','python','capture-at-ms'])assert(Object.hasOwn(values,name),CODE,'Required acquisition flag: --'+name);
 assert(/^(?:0|[1-9][0-9]{0,4})$/.test(values['capture-at-ms']!),CODE,'Capture offset must be an unambiguous decimal integer');
 return normalizeAcquisitionOptions({file:values.file,config:values.config,plan:values.plan,out:values.out,python:values.python,
  ...(values.powershell===undefined?{}:{powershell:values.powershell}),capture_at_ms:Number(values['capture-at-ms']),callers});
}
