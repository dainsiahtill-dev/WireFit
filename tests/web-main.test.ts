import {describe,it,expect,vi} from 'vitest';
import {webOptions,runWeb} from '../src/web/main.js';
import {main} from '../src/cli.js';
describe('workbench launcher',()=>{
 it('uses the installed loopback port and explicit stop/help options',()=>{expect(webOptions([])).toEqual({port:4318,stop:false,showHelp:false});expect(webOptions(['--port','4329','--stop'])).toEqual({port:4329,stop:true,showHelp:false});});
 it.each([['--port','0'],['--port','65536'],['--port','abc'],['--host','0.0.0.0'],['--stop','--stop']])('rejects unsupported launch arguments %j',(...argv)=>{expect(()=>webOptions(argv)).toThrow();});
 it('exposes help through both standalone and existing wirefit CLI without starting services',async()=>{const output=vi.spyOn(process.stdout,'write').mockImplementation(()=>true);try{expect(await runWeb(['--help'])).toBe(0);expect(await main(['web','--help'])).toBe(0);expect(output.mock.calls.flat().join('')).toContain('127.0.0.1:4318');}finally{output.mockRestore();}});
});
