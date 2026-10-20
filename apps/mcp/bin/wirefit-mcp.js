#!/usr/bin/env node
import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const root = fileURLToPath(new URL('../../../', import.meta.url));
const local = path.join(root, '.tools/runtime/node_modules/node-win-x64/bin/node.exe');
const runtime = process.platform === 'win32' && existsSync(local) ? local : process.execPath;
const probe = spawnSync(runtime, ['--version'], { encoding: 'utf8', windowsHide: true });
const major = Number(/^v(\d+)/.exec(probe.stdout ?? '')?.[1]);
if (probe.error || probe.status !== 0 || !Number.isInteger(major) || major !== 24) {
  process.stderr.write(
    JSON.stringify({
      error: {
        code: 'NODE_VERSION_UNSUPPORTED',
        message:
          'Wirefit MCP requires Node 24.x. Install the documented pinned runtime or use a supported system Node.',
      },
    }) + '\n',
  );
  process.exitCode = 1;
} else {
  const built = path.join(root, 'dist/src/mcp.js'),
    source = path.join(root, 'src/mcp.ts'),
    compiled = existsSync(built);
  const child = spawn(
    runtime,
    [...(compiled ? [] : ['--import', 'tsx']), compiled ? built : source, ...process.argv.slice(2)],
    { stdio: 'inherit', windowsHide: true },
  );
  const interrupt = () => {
    if (process.platform !== 'win32') child.kill('SIGINT');
  };
  const terminate = () => child.kill('SIGTERM');
  process.on('SIGINT', interrupt);
  process.on('SIGTERM', terminate);
  child.on('error', (error) => {
    process.stderr.write(
      JSON.stringify({ error: { code: 'MCP_START_FAILED', message: error.message } }) + '\n',
    );
    process.exitCode = 1;
  });
  child.on('close', (code, signal) => {
    process.removeListener('SIGINT', interrupt);
    process.removeListener('SIGTERM', terminate);
    process.exitCode = code ?? (signal ? 130 : 1);
  });
}
