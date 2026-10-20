import {existsSync} from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawnSync} from 'node:child_process';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const local=path.join(root,'.tools/runtime/node_modules/node-win-x64/bin/node.exe');
const node=process.platform==='win32'&&existsSync(local)?local:process.execPath;
const version=spawnSync(node,['--version'],{encoding:'utf8',windowsHide:true});
if(version.status!==0||!/^v24\./.test(version.stdout??'')){
 process.stderr.write('Wirefit requires Node 24. See README.md for the project-local runtime setup.\n');process.exit(1);
}
const commands={
 build:['node_modules/typescript/bin/tsc','-p','tsconfig.json'],
 typecheck:['node_modules/typescript/bin/tsc','-p','tsconfig.json','--noEmit'],
 test:['node_modules/vitest/vitest.mjs','run'],
 'test:watch':['node_modules/vitest/vitest.mjs'],
 doctor:['dist/src/cli.js','doctor','--json'],
 demo:['dist/src/demo.js'],
 acceptance:['dist/src/acceptance.js'],
 benchmark:['dist/src/numeric-benchmark.js'],
 web:['dist/src/web/main.js'],
 'test:web':['node_modules/vitest/vitest.mjs','run','tests/web-'],
 'test:ida':['node_modules/vitest/vitest.mjs','run','tests/ida-','tests/web-ida-'],
 'test:e2e':['node_modules/@playwright/test/cli.js','test','--config','playwright.config.mjs'],
};
const command=process.argv[2];
if(!Object.hasOwn(commands,command)){process.stderr.write('Unknown local development command\n');process.exit(2);}
const result=spawnSync(node,[...commands[command],...process.argv.slice(3)],{cwd:root,stdio:'inherit',windowsHide:true,shell:false});
if(result.error){process.stderr.write(result.error.message+'\n');process.exit(1);}
process.exitCode=result.status??1;
