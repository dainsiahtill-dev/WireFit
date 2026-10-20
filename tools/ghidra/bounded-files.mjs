import {lstat, realpath, open, readdir} from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export function requireThat(condition, code, message) {
  if (!condition) { const error = new Error(message); error.code = code; throw error; }
}
export const identity = snapshot => ({path:snapshot.path,size_bytes:snapshot.size_bytes,sha256:snapshot.sha256});
const samePath = (left,right) => process.platform==='win32' ? left.toLowerCase()===right.toLowerCase() : left===right;
const sameStat = (left,right) => ['dev','ino','size','mtimeNs','ctimeNs','nlink'].every(key=>left[key]===right[key]);

export function safePath(value, platform=process.platform) {
  requireThat(typeof value==='string' && value.length>0 && value.length<=4096,
    'GHIDRA_PATH_INVALID','Expected a bounded ordinary path');
  if(platform==='win32') requireThat(!/^[\\/]/.test(value) && !/^[A-Za-z]:(?![\\/])/.test(value)
    && !/[%&!^()]/.test(value),'GHIDRA_PATH_INVALID','Network, drive-relative and batch-expansion paths are not accepted');
  const selected=path.resolve(value), parsed=path.parse(selected);
  const pieces=selected.slice(parsed.root.length).split(path.sep);
  requireThat(pieces.every(piece=>piece && piece!=='.' && piece!=='..' && !/[<>:"|?*\x00-\x1f]/.test(piece)
    && !/[. ]$/.test(piece) && !/^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(piece)),
    'GHIDRA_PATH_INVALID','Path contains an aliased or special component');
  return selected;
}

export async function ordinaryPath(value,kind='file') {
  const selected=safePath(value);
  for(let current=selected;;current=path.dirname(current)) {
    requireThat(!(await lstat(current)).isSymbolicLink(),'GHIDRA_PATH_INVALID','Links and junctions are not accepted');
    if(path.dirname(current)===current)break;
  }
  requireThat(samePath(selected,await realpath(selected)),'GHIDRA_PATH_INVALID','Path resolves through an alias');
  const info=await lstat(selected,{bigint:true});
  requireThat(kind==='directory'?info.isDirectory():info.isFile(),'GHIDRA_PATH_INVALID','Unexpected path kind');
  return selected;
}

export async function assertNewOutput(value) {
  let selected;
  try {
    selected=safePath(value);
    await ordinaryPath(path.dirname(selected),'directory');
    try { await lstat(selected); } catch(error) { if(error.code==='ENOENT')return selected;throw error; }
  } catch(error) {
    if(error.code==='GHIDRA_OUTPUT_INVALID')throw error;
    const wrapped=new Error('New output parent/path is invalid: '+error.message);wrapped.code='GHIDRA_OUTPUT_INVALID';throw wrapped;
  }
  requireThat(false,'GHIDRA_OUTPUT_INVALID','Output already exists; previous evidence will not be replaced');
}

export async function readStable(value,limit=4*1024*1024) {
  const selected=await ordinaryPath(value),entry=await lstat(selected,{bigint:true});
  requireThat(Number.isSafeInteger(limit)&&limit>0&&limit<=128*1024*1024,
    'GHIDRA_PATH_INVALID','Invalid file byte bound');
  requireThat(entry.nlink===1n && entry.size>=0n && entry.size<=BigInt(limit),
    'GHIDRA_PATH_INVALID','File is hardlinked or exceeds its byte bound');
  const handle=await open(selected,'r');
  let bytes;
  try {
    const before=await handle.stat({bigint:true});
    requireThat(sameStat(entry,before),'GHIDRA_FILE_CHANGED','File changed before HANDLE opened');
    const buffer=Buffer.alloc(Number(before.size)+1);let length=0;
    while(length<buffer.length) {
      const next=await handle.read(buffer,length,buffer.length-length,length);
      if(next.bytesRead===0)break;
      length+=next.bytesRead;
    }
    const after=await handle.stat({bigint:true});
    await ordinaryPath(selected);
    const current=await lstat(selected,{bigint:true});
    requireThat(length===Number(before.size)&&sameStat(before,after)&&sameStat(entry,current),
      'GHIDRA_FILE_CHANGED','File changed during retained-HANDLE snapshot');
    bytes=buffer.subarray(0,length);
  } finally { await handle.close(); }
  return {path:selected,bytes,size_bytes:bytes.length,sha256:sha256(bytes)};
}

export async function writeNew(value,data) {
  const selected=safePath(value),bytes=typeof data==='string'?Buffer.from(data,'utf8'):Buffer.from(data);
  requireThat(bytes.length<=128*1024*1024,'GHIDRA_RESOURCE_LIMIT','New file exceeds the byte bound');
  await ordinaryPath(path.dirname(selected),'directory');
  const handle=await open(selected,'wx');
  try { await handle.writeFile(bytes);await handle.sync(); } finally { await handle.close(); }
  const saved=await readStable(selected,Math.max(1,bytes.length));
  requireThat(saved.bytes.equals(bytes),'GHIDRA_FILE_CHANGED','New output changed after writing');
  return saved;
}

export async function generatedFiles(directory) {
  await ordinaryPath(directory,'directory');
  const names=await readdir(directory);
  requireThat(names.length<=32,'GHIDRA_RESOURCE_LIMIT','Too many generated analysis files');
  const rows=[];let total=0;
  for(const name of names.sort()) {
    requireThat(/^[A-Za-z0-9_.-]{1,120}$/.test(name),'GHIDRA_PATH_INVALID','Unexpected generated file name');
    const snapshot=await readStable(path.join(directory,name));total+=snapshot.size_bytes;
    requireThat(total<=128*1024*1024,'GHIDRA_RESOURCE_LIMIT','Generated analysis byte budget exceeded');
    rows.push(identity(snapshot));
  }
  return rows;
}
