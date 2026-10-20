import {stat} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
export default async function teardown(){
 const base='http://127.0.0.1:4329';
 const bootstrap=await (await fetch(base+'/api/bootstrap')).json();
 if(bootstrap.data?.product!=='WireFit')throw new Error('Browser test server identity changed');
 const response=await fetch(base+'/api/shutdown',{method:'POST',headers:{'Content-Type':'application/json',Origin:base,'X-Wirefit-Token':bootstrap.data.token},body:'{}'});
 if(!response.ok)throw new Error('Browser test server refused graceful shutdown');
 const state=path.join(root,'.local/workbench/server-4329.json'),deadline=Date.now()+10000;
 while(Date.now()<deadline){
  try{await stat(state);}catch(error){if(error.code==='ENOENT')return;throw error;}
  await new Promise(resolve=>setTimeout(resolve,50));
 }
 throw new Error('Owned browser-test server did not clean up its state');
}
