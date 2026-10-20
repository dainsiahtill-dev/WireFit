import {describe,it,expect} from 'vitest';
import {runProcess} from '../src/process.js';
import path from 'node:path';
const worker=path.resolve('tools/native-kernel/worker.py');
const python=process.env.WIREFIT_PYTHON??'C:\\Users\\dains\\AppData\\Local\\Python\\pythoncore-3.14-64\\python.exe';
async function invoke(body:string,value:unknown={}){
 const source="import json,sys;from pathlib import Path;ns={'__name__':'kernel_test','__file__':sys.argv[1]};exec(compile(Path(sys.argv[1]).read_text(encoding='utf-8'),sys.argv[1],'exec'),ns);v=json.loads(sys.stdin.read());"+body;
 const result=await runProcess(python,['-X','utf8','-I','-S','-c',source,worker],{input:JSON.stringify(value),timeout_ms:10000});
 expect(result.code,result.stderr).toBe(0);return JSON.parse(result.stdout);
}
const sample=()=>({id:'edge-1',width:2,height:2,node_stride:3,source_stride:2,labels:[-2147483648,-1,0,2147483647]});
describe('fixed native kernel worker without target execution',()=>{
 it('accepts the bounded six-field int32 case contract',async()=>expect(await invoke("print(json.dumps(ns['validate_case'](v)))",sample())).toEqual(sample()));
 it.each([{width:true},{height:17},{node_stride:2},{source_stride:11},{labels:[0]},{labels:[0,1,2,2147483648]},{labels:[0,1,2,0.5]},{id:'bad\u0000id'},{pid:3}])('rejects invalid case before any Frida work (%#)',async patch=>{
  expect(await invoke("\ntry: ns['validate_case'](v);print(json.dumps({'accepted':True}))\nexcept Exception as e: print(json.dumps({'code':e.code}))",{...sample(),...patch})).toEqual({code:'INVALID_CORPUS'});
 });
 it('hashes canonical cases independently of key order',async()=>{
  const result=await invoke("print(json.dumps({'a':ns['cases_hash']([v]),'b':ns['cases_hash']([dict(reversed(list(v.items())))])}))",sample());expect(result.a).toBe(result.b);expect(result.a).toMatch(/^[a-f0-9]{64}$/);
 });
 it('rejects duplicate object keys rather than silently accepting a substituted field',async()=>expect(await invoke("\ntry: ns['decode_json'](b'{\"x\":1,\"x\":2}');print(json.dumps({'accepted':True}))\nexcept Exception as e: print(json.dumps({'code':e.code}))")).toEqual({code:'PROTOCOL_ERROR'}));
 it('uses the fixed vmde and independently compiled positive-control source identities',async()=>{
  const result=await invoke("print(json.dumps(ns['PROFILES']))");expect(result['vmde-grid']).toMatchObject({source_sha256:'9a0fa724e4a2f189da4cafdd700842d5b6c7aa6c571269500e5eb56cc3fa9a5d',rva:'0x98a50',size_bytes:637});expect(result['positive-control']).toMatchObject({source_sha256:'09cfe13ed66a35bf87144bfa9792857ce722cf0b6a9547bcc3c51d2767efd46b',rva:'0x1030',size_bytes:64});
 });
});
