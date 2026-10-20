import {lstat,open,realpath} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import path from 'node:path';

const RECEIPT='artifacts/native/deployment.json';
const CONFIG='.local/rea-native.json';
const MAX_RECEIPT=256*1024;
const MAX_FILE=16*1024*1024;
const MAX_TOTAL=64*1024*1024;
type JsonObject=Record<string,unknown>;
type ToolPresence={path:string|null;present:boolean};
export interface CurrentNativeTools {
 status:'available'|'incomplete'|'not_configured'|'invalid_configuration';
 configuration:string;verification:'regular_file_presence_only';executed:false;
 java_home:string|null;ghidra_install_dir:string|null;
 java:ToolPresence;javac:ToolPresence;ghidra_headless:ToolPresence;node:ToolPresence;rea_runtime:ToolPresence;
 reason?:string;
}
export interface RecordedNativeAnalysis {
 status:'validated'|'missing'|'invalid';receipt_path:string;
 scope:'local_expression_analysis';validation:'receipt_structure_and_referenced_bytes';
 current_execution_verified:false;archives_rechecked:false;
 matches_current_tool_paths:boolean;referenced_files_verified:number;
 verified_at?:string;recorded_scope?:string;provider_version?:string;
 code?:string;reason?:string;
}
class StatusError extends Error {constructor(readonly code:string,message:string){super(message);}}
function requireValue(condition:unknown,code:string,message:string):asserts condition {if(!condition)throw new StatusError(code,message);}
function object(value:unknown,label:string):JsonObject {
 requireValue(typeof value==='object'&&value!==null&&!Array.isArray(value),'INVALID_STRUCTURE',label+' must be an object');return value as JsonObject;
}
function text(value:unknown,label:string,maximum=4096):string {
 requireValue(typeof value==='string'&&value.length>0&&value.length<=maximum&&!value.includes('\0'),'INVALID_STRUCTURE',label+' must be a bounded nonempty string');return value;
}
function integer(value:unknown,label:string,maximum=Number.MAX_SAFE_INTEGER):number {
 requireValue(Number.isSafeInteger(value)&&Number(value)>=0&&Number(value)<=maximum,'INVALID_STRUCTURE',label+' must be a bounded nonnegative integer');return value as number;
}
function list(value:unknown,label:string,minimum:number,maximum:number):unknown[] {
 requireValue(Array.isArray(value)&&value.length>=minimum&&value.length<=maximum,'INVALID_STRUCTURE',label+' must be a bounded array');return value;
}
function equalPath(left:string,right:string):boolean {return process.platform==='win32'?path.normalize(left).toLowerCase()===path.normalize(right).toLowerCase():path.normalize(left)===path.normalize(right);}
function localAbsolute(value:unknown,label:string):string {
 const selected=text(value,label);
 requireValue(path.isAbsolute(selected)&&!selected.startsWith('\\\\')&&!selected.startsWith('//'),'INVALID_PATH',label+' must be an absolute local path');return path.normalize(selected);
}
function relativePath(value:unknown,label:string):string {
 const selected=text(value,label);
 requireValue(!path.isAbsolute(selected)&&!/[\\:]/.test(selected)&&selected.split('/').every(part=>part!==''&&part!=='.'&&part!=='..'),'INVALID_PATH',label+' must be a contained relative path');return selected;
}
function containedRelative(root:string,absolute:unknown,label:string):string {
 const selected=localAbsolute(absolute,label);const relative=path.relative(root,selected).split(path.sep).join('/');return relativePath(relative,label);
}
function missing(error:unknown):boolean {return typeof error==='object'&&error!==null&&'code'in error&&error.code==='ENOENT';}
function diagnostic(error:unknown):{code:string;reason:string} {
 return {code:error instanceof StatusError?error.code:'FILE_UNAVAILABLE',reason:(error instanceof Error?error.message:'File could not be validated').slice(0,1024)};
}

/** Bounded, stable reads reject links in every component below the selected root. */
async function readBounded(root:string,relative:string,maximum:number):Promise<Buffer>{
 const safe=relativePath(relative,'File path');let selected=root;
 const parts=safe.split('/');
 for(const [index,part]of parts.entries()){
  selected=path.join(selected,part);const info=await lstat(selected);
  requireValue(!info.isSymbolicLink(),'LINK_NOT_ALLOWED','Referenced paths must not traverse links');
  requireValue(index===parts.length-1?info.isFile():info.isDirectory(),'INVALID_FILE','Referenced path must lead to a regular file');
 }
 requireValue(equalPath(await realpath(selected),selected),'LINK_NOT_ALLOWED','Referenced paths must not traverse aliases');
 const beforePath=await lstat(selected);
 requireValue(beforePath.isFile()&&beforePath.size<=maximum,'RESOURCE_LIMIT','Referenced file exceeds its byte limit');
 const handle=await open(selected,'r');
 try{
  const before=await handle.stat();
  requireValue(before.isFile()&&before.size<=maximum&&before.dev===beforePath.dev&&before.ino===beforePath.ino&&before.size===beforePath.size&&before.mtimeMs===beforePath.mtimeMs,'SOURCE_CHANGED','Referenced file changed before reading');
  const buffer=Buffer.alloc(before.size+1);let length=0;
  while(length<buffer.length){const result=await handle.read(buffer,length,buffer.length-length,null);if(result.bytesRead===0)break;length+=result.bytesRead;}
  const after=await handle.stat();const afterPath=await lstat(selected);
  requireValue(length===before.size&&after.size===before.size&&after.mtimeMs===before.mtimeMs&&after.ctimeMs===before.ctimeMs&&afterPath.isFile()&&afterPath.dev===before.dev&&afterPath.ino===before.ino&&afterPath.mtimeMs===before.mtimeMs&&equalPath(await realpath(selected),selected),'SOURCE_CHANGED','Referenced file changed while reading');
  return buffer.subarray(0,length);
 }finally{await handle.close();}
}
function parseJson(bytes:Buffer,label:string):unknown {
 try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)) as unknown;}
 catch{throw new StatusError('INVALID_JSON',label+' must contain valid UTF-8 JSON');}
}
async function toolPresence(selected:string):Promise<ToolPresence>{
 try{const info=await lstat(selected);return {path:selected,present:info.isFile()&&equalPath(await realpath(selected),selected)};}
 catch{return {path:selected,present:false};}
}
async function currentTools(root:string):Promise<CurrentNativeTools>{
 const absent=():ToolPresence=>({path:null,present:false});
 const base:CurrentNativeTools={status:'not_configured',configuration:CONFIG,verification:'regular_file_presence_only',executed:false,java_home:null,ghidra_install_dir:null,java:absent(),javac:absent(),ghidra_headless:absent(),node:absent(),rea_runtime:absent()};
 let bytes:Buffer;
 try{bytes=await readBounded(root,CONFIG,64*1024);}
 catch(error){return {...base,status:missing(error)?'not_configured':'invalid_configuration',reason:diagnostic(error).reason};}
 try{
  const config=object(parseJson(bytes,'Native configuration'),'Native configuration');const environment=object(config.env,'Native environment');
  const javaHome=localAbsolute(environment.JAVA_HOME,'JAVA_HOME');const ghidraHome=localAbsolute(environment.GHIDRA_INSTALL_DIR,'GHIDRA_INSTALL_DIR');
  const command=localAbsolute(config.command,'REA command');const args=list(config.args,'REA arguments',2,16);
  requireValue(args[1]==='--mcp'&&args.every(argument=>typeof argument==='string'&&argument.length<=4096&&!argument.includes('\0')),'INVALID_STRUCTURE','Native configuration must select the REA MCP script');
  const runtime=localAbsolute(args[0],'REA runtime script');
  const selected={java:await toolPresence(path.join(javaHome,'bin',process.platform==='win32'?'java.exe':'java')),javac:await toolPresence(path.join(javaHome,'bin',process.platform==='win32'?'javac.exe':'javac')),ghidra_headless:await toolPresence(path.join(ghidraHome,'support',process.platform==='win32'?'analyzeHeadless.bat':'analyzeHeadless')),node:await toolPresence(command),rea_runtime:await toolPresence(runtime)};
  return {...base,...selected,java_home:javaHome,ghidra_install_dir:ghidraHome,status:Object.values(selected).every(tool=>tool.present)?'available':'incomplete'};
 }catch(error){return {...base,status:'invalid_configuration',reason:diagnostic(error).reason};}
}
interface Identity {path:string;sha256:string;size_bytes:number}
function identity(value:unknown,label:string,field='path'):Identity {
 const selected=object(value,label);const digest=text(selected.sha256,label+' digest',64);
 requireValue(/^[a-f0-9]{64}$/.test(digest),'INVALID_STRUCTURE',label+' digest must be SHA-256');
 return {path:relativePath(selected[field],label+' path'),sha256:digest,size_bytes:integer(selected.size_bytes,label+' size',MAX_FILE)};
}

async function recordedAnalysis(root:string,tools:CurrentNativeTools):Promise<RecordedNativeAnalysis>{
 const base:RecordedNativeAnalysis={status:'missing',receipt_path:RECEIPT,scope:'local_expression_analysis',validation:'receipt_structure_and_referenced_bytes',current_execution_verified:false,archives_rechecked:false,matches_current_tool_paths:false,referenced_files_verified:0};
 let receiptBytes:Buffer;
 try{receiptBytes=await readBounded(root,RECEIPT,MAX_RECEIPT);}
 catch(error){return {...base,status:missing(error)?'missing':'invalid',...diagnostic(error)};}
 try{
  const receipt=object(parseJson(receiptBytes,'Native receipt'),'Native receipt');
  requireValue(receipt.schema_version===1&&receipt.status==='PASS','INVALID_STRUCTURE','Unsupported native receipt version or status');
  const scope=text(receipt.scope,'Recorded scope',2048);const verified=text(receipt.verified_at,'Verification time',64);
  requireValue(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z$/.test(verified)&&Number.isFinite(Date.parse(verified)),'INVALID_STRUCTURE','Invalid recorded verification time');
  const host=object(receipt.host,'Recorded host');text(host.platform,'Recorded platform',32);text(host.arch,'Recorded architecture',32);
  const javaHome=localAbsolute(receipt.java_home,'Recorded JAVA_HOME');const ghidraHome=localAbsolute(receipt.ghidra_install_dir,'Recorded Ghidra directory');
  const java=object(receipt.java,'Recorded Java');const javac=object(receipt.javac,'Recorded Java compiler');
  requireValue(java.exit_code===0&&javac.exit_code===0&&receipt.jdk_compiler_present===true,'INVALID_STRUCTURE','Receipt does not record a successful JDK check');
  requireValue(equalPath(localAbsolute(java.executable,'Recorded Java executable'),path.join(javaHome,'bin',host.platform==='win32'?'java.exe':'java'))&&equalPath(localAbsolute(javac.executable,'Recorded compiler executable'),path.join(javaHome,'bin',host.platform==='win32'?'javac.exe':'javac')),'INVALID_STRUCTURE','Recorded JDK paths disagree');
  const rea=object(receipt.rea,'Recorded REA');const provider=object(rea.provider,'Recorded provider');
  requireValue(rea.package==='rea-agents'&&provider.id==='ghidra'&&rea.persisted===true&&object(rea.cleanup,'Recorded cleanup').closed===true,'INVALID_STRUCTURE','Receipt does not record completed Ghidra evidence acquisition');
  const providerVersion=text(provider.version,'Ghidra version',64);text(rea.version,'REA version',64);const evidenceId=text(rea.evidence_id,'Evidence identity',256);
  const flow=object(receipt.native_value_flow,'Recorded native value flow');
  requireValue(flow.available===true&&flow.provenance==='ghidra-high-pcode'&&flow.truncated===false&&flow.omitted_operations===0,'INVALID_STRUCTURE','Recorded native value flow is incomplete');
  const operationCount=integer(flow.operation_count,'Operation count',100000);const edgeCount=integer(flow.edge_count,'Edge count',100000);
  requireValue(operationCount>0,'INVALID_STRUCTURE','Recorded value flow is empty');
  const expression=object(receipt.local_expression,'Recorded local expression');const expressionScope=object(expression.scope,'Recorded expression scope');
  requireValue(expressionScope.kind==='expression'&&object(expressionScope.execution_guard,'Recorded execution guard').kind==='unknown'&&object(expressionScope.observation_point,'Recorded observation point').kind==='local_value'&&expression.target_replay_eligible===false,'INVALID_STRUCTURE','Receipt exceeds the supported local-expression scope');
  const sources=list(receipt.source_files,'Recorded source identities',1,30).map((value,index)=>identity(value,'Source '+index));
  const portable=identity(rea.portable_evidence,'Portable evidence');
  const caseRelative=containedRelative(root,rea.case_directory,'Recorded case directory');
  const raw=identity(rea.raw_acquisition,'Raw acquisition','relative_path');raw.path=caseRelative+'/'+raw.path;
  const references=[...sources,portable,raw];let total=0;const seen=new Set<string>();const bytesByPath=new Map<string,Buffer>();
  for(const reference of references){
   const key=reference.path.toLowerCase();requireValue(!seen.has(key),'INVALID_STRUCTURE','Duplicate recorded file identity');seen.add(key);
   total+=reference.size_bytes;requireValue(total<=MAX_TOTAL,'RESOURCE_LIMIT','Recorded evidence exceeds the total byte limit');
   const bytes=await readBounded(root,reference.path,Math.min(MAX_FILE,reference.size_bytes));
   requireValue(bytes.length===reference.size_bytes&&createHash('sha256').update(bytes).digest('hex')===reference.sha256,'EVIDENCE_CHANGED','Recorded evidence bytes or digest changed: '+reference.path);
   if(reference===portable||reference===raw)bytesByPath.set(reference.path,bytes);
  }
  // Bind the retained receipt to its evidence and completed acquisition. This
  // checks recorded facts; it does not rerun native analysis or prove semantics.
  const bundle=object(parseJson(bytesByPath.get(portable.path)!,'Portable evidence'),'Portable evidence');
  const records=list(bundle.records,'Evidence records',1,256).map((value,index)=>object(value,'Evidence record '+index));
  const recordIdentities=records.map(item=>text(item.evidence_id,'Portable evidence identity',256));
  requireValue(new Set(recordIdentities).size===recordIdentities.length,'INVALID_EVIDENCE','Portable evidence identities must be unique');
  const record=records.find(item=>item.evidence_id===evidenceId);
  requireValue(record&&record.operation==='analyze_function','INVALID_EVIDENCE','Recorded analysis is absent from portable evidence');
  const recordProvider=object(record.provider,'Evidence provider');requireValue(recordProvider.id==='ghidra'&&recordProvider.version===providerVersion,'INVALID_EVIDENCE','Recorded provider disagrees with portable evidence');
  const normalized=object(record.normalized_result,'Normalized native result');requireValue(text(normalized.pseudocode,'Recorded pseudocode',MAX_FILE).trim().length>0,'INVALID_EVIDENCE','Recorded pseudocode is empty');
  const nativeFlow=object(normalized.native_value_flow,'Portable native value flow');
  requireValue(nativeFlow.available===true&&nativeFlow.provenance==='ghidra-high-pcode'&&nativeFlow.truncated===false&&nativeFlow.known_omitted_edges===0&&nativeFlow.known_omitted_inputs===0&&nativeFlow.omitted_operations_lower_bound===0&&list(nativeFlow.operations,'Native operations',1,100000).length===operationCount&&list(nativeFlow.def_use,'Native edges',0,100000).length===edgeCount,'INVALID_EVIDENCE','Portable value flow disagrees with the receipt');
  const subject=object(record.subject,'Evidence subject');const subjectPath=containedRelative(root,subject.local_path,'Evidence target');const subjectDigest=object(subject.digest,'Evidence target digest').sha256;
  requireValue(sources.some(source=>equalPath(source.path,subjectPath)&&source.sha256===subjectDigest),'INVALID_EVIDENCE','Evidence target has no matching verified source identity');
  const acquisition=object(parseJson(bytesByPath.get(raw.path)!,'Raw acquisition'),'Raw acquisition');const saved=object(acquisition.saved,'Saved portable evidence');const savedArtifact=object(saved.artifact,'Saved portable artifact');
  requireValue(acquisition.status==='completed'&&acquisition.persisted===true&&object(acquisition.cleanup,'Acquisition cleanup').closed===true&&acquisition.bundleSha256===portable.sha256&&saved.status==='supported'&&savedArtifact.sha256===portable.sha256&&savedArtifact.size_bytes===portable.size_bytes,'INVALID_EVIDENCE','Raw acquisition does not corroborate the recorded portable evidence');
  const matches=host.platform===process.platform&&host.arch===process.arch&&tools.java_home!==null&&tools.ghidra_install_dir!==null&&equalPath(tools.java_home,javaHome)&&equalPath(tools.ghidra_install_dir,ghidraHome);
  return {...base,status:'validated',matches_current_tool_paths:matches,referenced_files_verified:references.length,verified_at:verified,recorded_scope:scope,provider_version:providerVersion};
 }catch(error){return {...base,status:'invalid',...diagnostic(error)};}
}

/** No native tools or targets are executed. Availability and retained evidence stay separate. */
export async function loadNativeStatus(directory:string){
 let root:string;
 try{root=await realpath(path.resolve(directory));}
 catch{root=path.resolve(directory);}
 const tools=await currentTools(root);const recorded=await recordedAnalysis(root,tools);
 const usableRecord=tools.status==='available'&&recorded.status==='validated'&&recorded.matches_current_tool_paths;
 return {native_ghidra:usableRecord?'RECORDED_LOCAL_ANALYSIS' as const:'NOT_VERIFIED' as const,last_recorded_native_gate:'BLOCKED' as const,
  native_reason:usableRecord?'Configured tool files are present and retained local-analysis evidence matches its recorded hashes. No native process was run; full ABI, execution guards and original-binary equivalence remain unverified.':'Current configured tool presence and validated matching local-analysis evidence are both required. See current_native_tools and recorded_native_analysis; no native process was run.',
  current_native_tools:tools,recorded_native_analysis:recorded,historical_native_gate:{status:'BLOCKED' as const,scope:'full_acceptance' as const,current_proof:false as const},full_binary_equivalence:false as const};
}
