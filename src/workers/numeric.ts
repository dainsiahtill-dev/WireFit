import {fitNumeric,type FitOptions} from '../numeric.js';
import type {NumericModel,Observation} from '../types.js';
import {assert,errorRecord} from '../shared.js';

const maximumRequestBytes=32*1024*1024;
let job_id='unknown';
try {
  let byteCount=0;const chunks:Buffer[]=[];
  for await(const raw of process.stdin){const chunk=Buffer.isBuffer(raw)?raw:Buffer.from(raw);byteCount+=chunk.length;assert(byteCount<=maximumRequestBytes,'INPUT_TOO_LARGE','Numeric worker request exceeds 32 MiB');chunks.push(chunk);}
  const decoder=new TextDecoder('utf-8',{fatal:true}),text=decoder.decode(Buffer.concat(chunks)),lines=text.split(/\r?\n/).filter(line=>line.trim().length>0);
  assert(lines.length===1,'INVALID_PROTOCOL','Numeric worker requires one JSONL request');
  const request=JSON.parse(lines[0]!) as {protocol_version:number;job_id:string;template:NumericModel;train:Observation[];validation:Observation[];options:FitOptions};
  if(typeof request?.job_id==='string'&&/^[A-Za-z][A-Za-z0-9_.:-]{0,127}$/.test(request.job_id))job_id=request.job_id;
  assert(request?.protocol_version===1&&job_id!=='unknown'&&Object.keys(request).sort().join(',')==='job_id,options,protocol_version,template,train,validation','INVALID_PROTOCOL','Invalid numeric worker envelope');
  assert(!!request.options&&typeof request.options==='object'&&Object.keys(request.options).sort().join(',')==='backend,budget,comparison_policy,training','INVALID_PROTOCOL','Invalid numeric worker options');
  const result=fitNumeric(request.template,request.train,request.validation,request.options);
  process.stdout.write(JSON.stringify({protocol_version:1,job_id,status:'completed',result})+'\n');
} catch(error) {
  process.stdout.write(JSON.stringify({protocol_version:1,job_id,status:'failed',error:errorRecord(error,'numeric-worker')})+'\n');
  process.exitCode=1;
}
