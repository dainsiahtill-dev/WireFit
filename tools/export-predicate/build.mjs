import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {lstat} from 'node:fs/promises';
import {instrumentAgent} from './agent-variant.mjs';
import {absolute,canonical,readStable,writeNew,jsonBytes,newDir,need} from '../../artifacts/research/vmde/native-kernel/io.mjs';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const args=process.argv.slice(2);
need(args.length===4&&args[0]==='--config'&&args[2]==='--out','Usage: build.mjs --config ABS_CONFIG --out NEW_ABS_DIR');
const configPath=absolute(args[1]),out=absolute(args[3]);
const inputs=[];
async function input(file){const value=await readStable(file);inputs.push({path:value.path,size_bytes:value.size_bytes,sha256:value.sha256});return value;}
const configFile=await input(configPath);
const config=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(configFile.bytes));
need(config&&typeof config==='object'&&!Array.isArray(config)&&Object.keys(config).length===2&&typeof config.command==='string'&&Array.isArray(config.args),'Expected an explicit command/args config');
absolute(config.command);
need(config.args.length===7&&config.args.every(value=>typeof value==='string')&&config.args.slice(0,4).join('\0')===['-X','utf8','-I','-S'].join('\0')&&config.args[5]==='--module-path','Expected the frozen native worker launch contract');
const worker=await input(path.join(root,'tools/native-trace/worker.py'));
need(worker.sha256==='7e71b0624fb6a3331e98cc42487d13e83301b5fbad3a18e4d029ef76283772dc','Frozen native worker differs');
need((await canonical(config.args[4])).toLowerCase()===worker.path.toLowerCase(),'Config worker differs from the frozen source');
const modulePath=await canonical(config.args[6]);need((await lstat(modulePath)).isDirectory(),'Frida module path must be an ordinary canonical directory');
const agent=await input(path.join(root,'tools/native-trace/agent.js'));
const variant=instrumentAgent(agent.bytes);
need(Buffer.isBuffer(variant.bytes)&&variant.bytes.length<=1048576&&variant.source_sha256===agent.sha256,'Diagnostic transform did not return the fixed input identity');
for(const file of [fileURLToPath(import.meta.url),path.join(root,'tools/export-predicate/agent-variant.mjs'),path.join(root,'artifacts/research/vmde/native-kernel/io.mjs')])await input(file);
await newDir(out);
const receipt={schema_version:1,kind:'exact_source_export_predicate_variant_build',status:'failed',started_at:new Date().toISOString(),inputs,outputs:[],error:null,finalization_errors:[],inputs_unchanged:true,target_executed:false,hook_policy_changed:false};
try{
 const outputConfig={command:config.command,args:[...config.args.slice(0,4),path.join(out,'worker.py'),...config.args.slice(5)]};
 for(const [name,bytes] of [['worker.py',worker.bytes],['agent.js',variant.bytes],['config.json',jsonBytes(outputConfig)]]){
  const f=await writeNew(path.join(out,name),bytes);receipt.outputs.push({path:f.path,size_bytes:f.size_bytes,sha256:f.sha256});
 }
 receipt.status='built';
}catch(e){receipt.error={code:e?.code??'BUILD_FAILED',message:String(e?.message??e)};}
for(const expected of inputs){try{const f=await readStable(expected.path);need(f.sha256===expected.sha256&&f.size_bytes===expected.size_bytes,'Build input changed');}catch(e){receipt.inputs_unchanged=false;receipt.finalization_errors.push({code:e?.code??'INPUT_CHANGED',message:String(e?.message??e)});}}
if(!receipt.inputs_unchanged)receipt.status='failed';
receipt.finished_at=new Date().toISOString();
try{await writeNew(path.join(out,'build-receipt.json'),jsonBytes(receipt));}
catch(e){receipt.receipt_write_error={code:e?.code??'RECEIPT_WRITE_FAILED',message:String(e?.message??e)};receipt.error??=receipt.receipt_write_error;receipt.status='failed';process.stderr.write(JSON.stringify(receipt)+'\n','utf8');}
process.stdout.write(JSON.stringify({status:receipt.status,out,inputs_unchanged:receipt.inputs_unchanged,outputs:receipt.outputs,error:receipt.error,receipt_write_error:receipt.receipt_write_error})+'\n','utf8');
if(receipt.status!=='built')process.exitCode=1;
