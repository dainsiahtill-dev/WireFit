import {defineConfig} from '@playwright/test';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.dirname(fileURLToPath(import.meta.url));
const node=process.platform==='win32'?path.join(root,'.tools/runtime/node_modules/node-win-x64/bin/node.exe'):process.execPath;
const quote=value=>'"'+value.replaceAll('"','')+'"';
export default defineConfig({
 testDir:'./tests/browser',globalTeardown:'./tests/browser/teardown.mjs',timeout:90000,expect:{timeout:12000},workers:1,fullyParallel:false,
 outputDir:'artifacts/web-workbench/browser-results',reporter:[['list'],['json',{outputFile:'artifacts/web-workbench/browser-results.json'}]],
 use:{baseURL:'http://127.0.0.1:4329',browserName:'chromium',channel:'msedge',headless:true,viewport:{width:1440,height:1000},trace:'retain-on-failure',screenshot:'only-on-failure'},
 webServer:{command:quote(node)+' '+quote(path.join(root,'dist/src/web/main.js'))+' --port 4329',url:'http://127.0.0.1:4329/api/bootstrap',reuseExistingServer:false,timeout:30000,stdout:'pipe',stderr:'pipe'},
});
