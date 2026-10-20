export const binaryVerifyHelper = String.raw`// Standalone file verification only. This helper never executes a PE.
import {readFile,lstat,realpath} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const root=await realpath(path.dirname(fileURLToPath(import.meta.url)));
const fail=message=>{throw Error('EXPORT_INTEGRITY_ERROR '+message);};
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const safePart=part=>typeof part==='string'&&part.length>0&&part.length<=255&&part!=='.'&&part!=='..'&&!/[<>:"/\\|?*\x00-\x1f]/.test(part)&&!/[. ]$/.test(part)&&!/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(part);
async function ownedFile(relative){
 if(typeof relative!=='string'||relative.length>4096||!relative.split('/').every(safePart))fail('invalid relative file');
 let current=root;
 for(const part of relative.split('/')){
  current=path.join(current,part);
  if((await lstat(current)).isSymbolicLink())fail('link alias in '+relative);
 }
 const info=await lstat(current);
 if(!info.isFile()||info.size>128*1024*1024)fail('nonregular or oversized file '+relative);
 return {file:current,size:info.size};
}
const manifestFile=await ownedFile('manifest.json'),hashFile=await ownedFile('manifest.sha256');
if(manifestFile.size>4*1024*1024||hashFile.size>256)fail('manifest budget');
const manifestBytes=await readFile(manifestFile.file);
const detached=(await readFile(hashFile.file,'utf8')).trim();
if(detached!==digest(manifestBytes)+'  manifest.json')fail('manifest digest mismatch');
const manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(manifestBytes));
if(manifest.schema_version!==1||manifest.report_kind!=='binary'||!Array.isArray(manifest.files)||manifest.files.length>10000)fail('invalid manifest');
if(manifest.verification?.target_execution!=='not_run'||manifest.verification?.runnable_verified!==false)fail('invalid verification scope');
const paths=new Set();let total=0;
for(const entry of manifest.files){
 if(!entry||typeof entry.relative_path!=='string'||typeof entry.sha256!=='string'||!/^[a-f0-9]{64}$/.test(entry.sha256)||!Number.isSafeInteger(entry.size_bytes)||entry.size_bytes<0)fail('invalid file entry');
 const key=entry.relative_path.toLowerCase();
 if(paths.has(key))fail('duplicate file identity');paths.add(key);
 total+=entry.size_bytes;if(total>512*1024*1024)fail('file budget');
 const file=await ownedFile(entry.relative_path);
 if(file.size!==entry.size_bytes)fail('size mismatch '+entry.relative_path);
 const bytes=await readFile(file.file);
 if(bytes.length!==entry.size_bytes||digest(bytes)!==entry.sha256)fail('hash mismatch '+entry.relative_path);
}
if(!paths.has('result.json')||!paths.has('run.json')||!paths.has('verify.mjs'))fail('missing required file');
const result=JSON.parse(await readFile(path.join(root,'result.json'),'utf8'));
if(!['inspect_binary','unpack_binary','trace_binary'].includes(result.operation)||!['completed','failed','cancelled'].includes(result.status)||result.validation?.runnable_verified!==false)fail('invalid original result');
if(manifest.operation!==result.operation||manifest.original_status!==result.status||manifest.run_id!==result.result_id)fail('result identity mismatch');
console.log(JSON.stringify({file_integrity:{status:'matched',checked:manifest.files.length},original_operation:result.operation,original_status:result.status,recorded_source_unchanged:result.validation.source_unchanged,target_execution:'not_run',runnable_verified:false,behavioral_equivalence:'not_established'}));
`;
