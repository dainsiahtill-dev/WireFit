import path from 'node:path';
import {normalizeAcquisitionOptions,type AcquisitionOptions} from './native-acquisition-options.js';
import type {Snapshot} from './binary-files.js';
import {validateNativeTraceRequest,type NativeTracePlan} from './native-trace.js';
import type {BinaryCommand} from './binary-service.js';
import {readAcquisitionFile,assertNewAcquisitionOutput,decodeAcquisitionJson} from './native-acquisition-files.js';
import {inspectPe} from './pe.js';
import {assert} from './shared.js';
export interface PreparedAcquisition {options:AcquisitionOptions;source:Snapshot;config_file:Snapshot;plan_file:Snapshot;tool:BinaryCommand;plan:NativeTracePlan;image_size:number}
export async function prepareAcquisition(input:AcquisitionOptions):Promise<PreparedAcquisition>{
 const options=normalizeAcquisitionOptions(input);await assertNewAcquisitionOutput(options.out);
 const [source,config_file,plan_file]=await Promise.all([readAcquisitionFile(options.file),readAcquisitionFile(options.config,65536),readAcquisitionFile(options.plan,65536)]);
 const request:unknown={file:source.path,tool:decodeAcquisitionJson(config_file.bytes),plan:decodeAcquisitionJson(plan_file.bytes)};
 validateNativeTraceRequest(request);
 const inspection=inspectPe(source.bytes),code='ACQUISITION_PROFILE_INVALID';
 assert(path.extname(source.path).toLowerCase()==='.exe'&&inspection.architecture==='x86',code,'Owned acquisition currently requires a PE32/x86 executable');
 const optional=source.bytes.readUInt32LE(0x3c)+24,image_size=source.bytes.readUInt32LE(optional+56);
 assert(image_size>0&&image_size<=67108864,code,'Main image must fit the bounded 64 MiB collector');
 assert(request.plan.breakpoints_rva.length===0&&request.plan.api_hooks.length===0&&request.plan.max_events>=2,code,'Owned acquisition requires a passive plan and room for agent-ready metadata');
 assert(options.capture_at_ms<request.plan.duration_ms,code,'Capture offset must be inside the trace duration');
 for(const range of request.plan.ranges)if(range.module===undefined)assert(BigInt(range.rva)+BigInt(range.size_bytes)<=BigInt(image_size),code,'Main snapshot lies outside SizeOfImage');
 for(const caller of options.callers)assert(BigInt(caller)+6n<=BigInt(image_size),code,'Caller needs a complete six-byte window inside SizeOfImage');
 await readAcquisitionFile(options.python,134217728);
 if(options.powershell!==undefined)await readAcquisitionFile(options.powershell,134217728);
 return {options,source,config_file,plan_file,tool:request.tool,plan:request.plan,image_size};
}
