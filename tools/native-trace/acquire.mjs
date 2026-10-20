// Public project command: only starts a new staged target through Wirefit CLI.
import {acquireNativeEvidence} from '../../dist/src/native-acquisition.js';
import {parseAcquisitionArgs} from '../../dist/src/native-acquisition-options.js';
import {errorRecord} from '../../dist/src/shared.js';

const controller=new AbortController(),cancel=()=>controller.abort();
const print=value=>process.stdout.write(JSON.stringify(value)+'\n','utf8');
if(process.argv.length===3&&process.argv[2]==='--help'){
 print({usage:'node tools/native-trace/acquire.mjs --file EXE --config JSON --plan JSON --out NEW_DIRECTORY --python ABSOLUTE_PYTHON --capture-at-ms INTEGER [--caller-rva HEX ...] [--powershell ABSOLUTE_PWSH]',
  profile:'PE32/x86, passive owned trace, bounded read-only observers; no existing PID or case accepted'});
}else{
 process.on('SIGINT',cancel);process.on('SIGTERM',cancel);
 try{
  const receipt=await acquireNativeEvidence(parseAcquisitionArgs(process.argv.slice(2)),{signal:controller.signal,onEvent:print});
  process.exitCode=receipt.status==='observations_collected'?0:receipt.status==='cancelled'?130:1;
 }catch(error){print({event:'failed',error:errorRecord(error,'native-acquisition')});process.exitCode=controller.signal.aborted?130:2;}
 finally{process.removeListener('SIGINT',cancel);process.removeListener('SIGTERM',cancel);}
}
