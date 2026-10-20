import {describe,it,expect} from 'vitest';
import {readFile,mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {canonical,hashObject,validateSchema,schemaNames,readJsonl} from '../src/shared.js';

describe('canonical contracts',()=>{
 it('uses stable ASCII key ordering and preserves BV64 strings',()=>{
   expect(canonical({z:{bits:'0x0020000000000001',kind:'bv',width:64},a:[1,true]})).toBe('{"a":[1,true],"z":{"bits":"0x0020000000000001","kind":"bv","width":64}}');
   expect(hashObject({b:2,a:1})).toBe(hashObject({a:1,b:2}));
 });
 it('rejects unsafe numbers and non-ASCII keys in canonical objects',()=>{
   expect(()=>canonical({a:9007199254740992})).toThrow();
   expect(()=>canonical({a:1.5})).toThrow();
   expect(()=>canonical({'中文':1})).toThrow();
   expect(()=>canonical({a:undefined})).toThrow();
 });
 it('compiles all eleven JSON Schema 2020-12 contracts offline',()=>{
   expect(schemaNames()).toHaveLength(11);
   for(const name of schemaNames()) expect(name.length).toBeGreaterThan(0);
 });
 it('rejects injected verdicts and malformed typed values',async()=>{
   const model=JSON.parse(await readFile('examples/model.add-u8.json','utf8'));
   expect(()=>validateSchema('model',model)).not.toThrow();
   expect(()=>validateSchema('model',{...model,verdict:'proved'})).toThrow();
   model.nodes[0].type.width=7;
   expect(()=>validateSchema('model',model)).toThrow();
 });
 it('rejects cross-operation request fields',async()=>{
   const request=JSON.parse(await readFile('examples/request.compare-equivalent.json','utf8'));
   expect(()=>validateSchema('experiment-request',request)).not.toThrow();
   expect(()=>validateSchema('experiment-request',{...request,verdict:'proved'})).toThrow();
 });
 it('bounds JSONL lines and reports malformed line numbers',async()=>{
   const dir=await mkdtemp(path.join(tmpdir(),'wirefit-jsonl-'));
   try{
    await writeFile(path.join(dir,'bad.jsonl'),'{}\n{nope}\n','utf8');
    await expect(readJsonl(path.join(dir,'bad.jsonl'))).rejects.toThrow(/line 2/i);
    await writeFile(path.join(dir,'big.jsonl'),JSON.stringify({a:'a'.repeat(1048577)})+'\n','utf8');
    await expect(readJsonl(path.join(dir,'big.jsonl'))).rejects.toThrow(/limit/i);
   }finally{await rm(dir,{recursive:true,force:true});}
 });
});
