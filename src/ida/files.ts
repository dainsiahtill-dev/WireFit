import { open, lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { assert } from '../shared.js';

/** Hash bounded runtime code without allocating DLL-sized buffers; empty modules are valid. */
export async function fingerprintIdaFile(
  file: string,
  maximum = 256 * 1024 * 1024,
): Promise<{ sha256: string; size_bytes: number }> {
  const requested = path.resolve(file),
    resolved = await realpath(requested);
  const equivalent = (left: string, right: string) =>
    process.platform === 'win32' ? left.toLowerCase() === right.toLowerCase() : left === right;
  assert(
    equivalent(requested, resolved) && !(await lstat(requested)).isSymbolicLink(),
    'IDA_PROBE_PATH_ALIAS',
    'Runtime file may not use path aliases',
  );
  const handle = await open(resolved, 'r');
  try {
    const before = await handle.stat();
    assert(
      before.isFile() && before.size >= 0 && before.size <= maximum,
      'IDA_PROBE_BUDGET',
      'Runtime file exceeds its bounded regular-file limit',
    );
    const hash = createHash('sha256'),
      buffer = Buffer.alloc(Math.min(1024 * 1024, before.size + 1));
    let length = 0;
    while (length <= before.size) {
      const read = await handle.read(buffer, 0, Math.min(buffer.length, before.size + 1 - length), length);
      if (read.bytesRead === 0) break;
      length += read.bytesRead;
      hash.update(buffer.subarray(0, read.bytesRead));
    }
    const after = await handle.stat(),
      current = await lstat(requested);
    assert(
      length === before.size &&
        after.size === before.size &&
        after.mtimeMs === before.mtimeMs &&
        after.ctimeMs === before.ctimeMs &&
        current.ino === before.ino &&
        current.dev === before.dev &&
        equivalent(await realpath(requested), resolved),
      'IDA_PROBE_FILE_CHANGED',
      'Runtime file changed while hashing',
    );
    return { sha256: hash.digest('hex'), size_bytes: length };
  } finally {
    await handle.close();
  }
}
