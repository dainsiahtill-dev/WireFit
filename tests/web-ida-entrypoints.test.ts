import {it,expect,vi} from 'vitest';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {main} from '../src/cli.js';
import {CaseStore} from '../src/store.js';
it('exposes IDA status through the existing CLI without requiring a writable case',async()=>{
 const stdout=vi.spyOn(process.stdout,'write').mockImplementation(()=>true);
 try{expect(await main(['ida','status'])).toBe(0);const value=JSON.parse(stdout.mock.calls.map(call=>call[0]).join(''));expect(value.read_only).toBe(true);expect(value.native_execution).toBe(false);expect(typeof value.configured).toBe('boolean');}
 finally{stdout.mockRestore();}
});
it('rejects invalid IDA CLI queries and duplicate flags before scheduling native analysis',async()=>{
 const dir=await mkdtemp(path.join(os.tmpdir(),'wirefit-ida-cli-')),casePath=path.join(dir,'case');const store=await CaseStore.create(casePath);await store.close();
 try{
  const queryPath=path.join(dir,'query.json');await writeFile(queryPath,'[{"kind":"py_eval","code":"bad"}]','utf8');
  await expect(main(['ida','analyze','--case',casePath,'--file','missing.exe','--query',queryPath])).rejects.toMatchObject({code:'IDA_REQUEST_INVALID'});
  await expect(main(['ida','analyze','--case',casePath,'--file','missing.exe','--query',queryPath,'--query',queryPath])).rejects.toMatchObject({code:'CLI_USAGE'});
  const reader=await CaseStore.open(casePath,false);try{expect(await reader.listObjects('jobs')).toEqual([]);}finally{await reader.close();}
 }finally{const selected=path.resolve(dir);if(path.dirname(selected)!==path.resolve(os.tmpdir())||!path.basename(selected).startsWith('wirefit-ida-cli-'))throw new Error('Unsafe cleanup');await rm(selected,{recursive:true,force:true});}
});
