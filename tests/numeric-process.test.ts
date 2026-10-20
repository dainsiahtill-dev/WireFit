import {describe,it,expect} from 'vitest';
import {readFileSync,mkdtempSync,writeFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {exportNumericModelSource} from '../src/numeric.js';
const affine:any=JSON.parse(readFileSync(new URL('../examples/model.affine-initial.json',import.meta.url),'utf8'));

describe('numeric external process boundaries',()=>{
  it('executes exported standalone code without the original case or repository dependencies',()=>{
    const folder=mkdtempSync(path.join(tmpdir(),'wirefit-numeric-'));
    try {
      const model=structuredClone(affine);model.definition.parameters={a:{kind:'fp32',bits:'0x00000000'},b:{kind:'fp32',bits:'0x80000000'}};
      writeFileSync(path.join(folder,'model.mjs'),exportNumericModelSource(model),'utf8');
      writeFileSync(path.join(folder,'run.mjs'),"import {evaluate} from './model.mjs'; console.log(JSON.stringify(evaluate({x:{kind:'fp32',bits:'0xbf800000'}})));",'utf8');
      const child=spawnSync(process.execPath,[path.join(folder,'run.mjs')],{cwd:folder,encoding:'utf8',timeout:10000});
      expect(child.status,child.stderr).toBe(0);
      expect(JSON.parse(child.stdout)).toEqual({result:{kind:'fp32',bits:'0x80000000'}});
    } finally {rmSync(folder,{recursive:true,force:true});}
  });
  it('worker reports a versioned protocol failure without accepting arbitrary options',()=>{
    const worker=new URL('../src/workers/numeric.ts',import.meta.url);
    const child=spawnSync(process.execPath,['--import','tsx',worker.pathname.replace(/^\/([A-Za-z]:)/,'$1')],{cwd:new URL('..',import.meta.url),input:JSON.stringify({protocol_version:2,job_id:'test_numeric'})+'\n',encoding:'utf8',timeout:10000});
    expect(child.stdout.trim()).not.toBe('');
    const response=JSON.parse(child.stdout);expect(response.protocol_version).toBe(1);expect(response.status).toBe('failed');expect(response.error.code).toBe('INVALID_PROTOCOL');
  });
});

it('exports a standalone TypeScript module that typechecks strictly and runs in a fresh process',()=>{
 const folder=mkdtempSync(path.join(tmpdir(),'wirefit-numeric-ts-'));
 try {
  const modelPath=path.join(folder,'model.mts');writeFileSync(modelPath,(exportNumericModelSource as any)(affine,'ts'),'utf8');
  const checked=spawnSync(process.execPath,[path.resolve('node_modules/typescript/bin/tsc'),'--ignoreConfig','--noEmit','--strict','--noUncheckedIndexedAccess','--skipLibCheck','--target','ES2023','--module','NodeNext',modelPath],{encoding:'utf8',timeout:10000});expect(checked.status,checked.stdout+checked.stderr).toBe(0);
  writeFileSync(path.join(folder,'run.mjs'),"import {evaluate} from './model.mts';console.log(JSON.stringify(evaluate({x:{kind:'fp32',bits:'0x3f800000'}})));",'utf8');
  const child=spawnSync(process.execPath,[path.join(folder,'run.mjs')],{encoding:'utf8',cwd:folder,timeout:10000});expect(child.status,child.stderr).toBe(0);expect(JSON.parse(child.stdout)).toEqual({result:{kind:'fp32',bits:'0x3f800000'}});
 } finally {rmSync(folder,{recursive:true,force:true});}
});

