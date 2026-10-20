import {it,expect} from 'vitest';
import {spawnSync} from 'node:child_process';
import {mkdtempSync,readFileSync,rmSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
it('benchmarks all three real configurations with cold/warm fits and post-freeze holdout',()=>{
  const folder=mkdtempSync(path.join(tmpdir(),'wirefit-benchmark-'));
  try {
    const artifact=path.join(folder,'benchmark.json');
    const child=spawnSync(process.execPath,['--import','tsx',fileURLToPath(new URL('../src/numeric-benchmark.ts',import.meta.url)),'--smoke','--output',artifact],{encoding:'utf8',timeout:30000,cwd:fileURLToPath(new URL('..',import.meta.url))});
    expect(child.status,child.stderr).toBe(0);
    expect(existsSync(artifact)).toBe(true);
    const result=JSON.parse(readFileSync(artifact,'utf8'));
    expect(result.entries).toHaveLength(3);
    expect(result.entries.map((x:any)=>x.backend)).toEqual(['analytic_baseline','reference','handwired']);
    for(const entry of result.entries){expect(entry.status).toBe('PASS');expect(entry.trials.map((x:any)=>x.mode)).toEqual(['cold','warm']);for(const trial of entry.trials){expect(trial.holdout_read_after_freeze).toBe(true);expect(trial.holdout.mismatched).toBe(0);expect(trial.original_target_calls).toBe(0);}}
  } finally {rmSync(folder,{recursive:true,force:true});}
},35000);
