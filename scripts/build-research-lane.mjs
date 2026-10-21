import {existsSync} from 'node:fs';
import {mkdir,readdir,readFile,rm,stat,writeFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {createHash, randomBytes} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const local = path.join(root, '.tools/runtime/node_modules/node-win-x64/bin/node.exe');
const runtime = process.platform === 'win32' && existsSync(local) ? local : process.execPath;
const lane = path.join(root, 'artifacts/research/vmde/directions');
const directions = ['D01','D02','D03','D04','D05','D06','D07','D08','D09','D10','D11','D12','D13','D14','D15','D16','D17'];

function run(args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(runtime, ['--import','tsx',path.join(root,'src/cli.ts'),...args], {
      cwd: root,
      windowsHide: true,
      stdio: ['ignore','pipe','pipe'],
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('close', (code) => {
      if (code === 0 || options.allowFailure) resolve({ code, stdout, stderr });
      else reject(new Error('command failed (' + code + '): wirefit ' + args.join(' ') + '\n' + stderr));
    });
  });
}

function parseJson(text) {
  const line = text.split('\n').filter((entry) => entry.trim() !== '').pop();
  return line === undefined ? null : JSON.parse(line);
}

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

async function walk(directory, prefix = '') {
  const output = [];
  for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name < b.name ? -1 : 1)) {
    const relative = prefix === '' ? entry.name : prefix + '/' + entry.name;
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walk(full, relative));
    else if (entry.isFile()) output.push({ relative_path: relative, full });
  }
  return output;
}

async function main() {
  const caseDir = process.argv.includes('--case')
    ? path.resolve(process.argv[process.argv.indexOf('--case') + 1])
    : path.join(root, 'cases/research-vmde');
  if (!existsSync(caseDir)) {
    await run(['case','create','--dir',caseDir]);
  }
  await mkdir(lane, { recursive: true });
  // The auditor and the manifest verifier are source controlled. The lane
  // carries a frozen copy so that a package can be audited on its own, and
  // the manifest pins the copy it was built from.
  for (const name of ['audit.py', 'verify-manifest.py']) {
    await writeFile(path.join(lane, name), await readFile(path.join(root, 'tools/research', name)));
  }
  /*
   * The pre-registration evidence. The specification lives in the product
   * source, not in the lane, so the proof that the plan predates the run is
   * the build of that source: the product build is strictly older than every
   * run below, and the plan digest pins the exact bytes that were used.
   */
  const productSources = [
    'src/research/catalog.ts',
    'src/research/types.ts',
    'src/research/recipe.ts',
    'src/research/runner.ts',
    'src/research/verdict.ts',
    'src/research/split.ts',
  ];
  let productBuiltAt = 0;
  for (const relative of productSources) {
    const info = await stat(path.join(root, ...relative.split('/')));
    productBuiltAt = Math.max(productBuiltAt, info.mtimeMs);
  }
  const productBuiltAtIso = new Date(productBuiltAt).toISOString();
  const summaries = [];
  for (const direction of directions) {
    // A direction package holds exactly one run. A stale run folder would
    // make the auditor discover the same artifact role twice and recompute
    // against an arbitrary one of them.
    await rm(path.join(lane, direction), { recursive: true, force: true });
    const runStartedAt = new Date().toISOString();
    const executed = await run(['research','run','--case',caseDir,'--direction',direction]);
    const payload = parseJson(executed.stdout);
    const runId = payload.job.result_id;
    const folder = 'run-' + randomBytes(3).toString('hex');
    const target = path.join(lane, direction, folder);
    await run(['report','export','--case',caseDir,'--run',runId,'--out',target]);
    for (const name of ['plan.json','checks.json','receipt.json','report.md']) {
      await writeFile(path.join(lane, direction, name), await readFile(path.join(target, name)));
    }
    const exported = JSON.parse(await readFile(path.join(target, 'manifest.json'), 'utf8'));
    await writeFile(path.join(lane, direction, 'manifest.json'), JSON.stringify({
      schema_version: 1,
      direction,
      run_id: runId,
      verdict: exported.verdict,
      plan_sha256: exported.plan_sha256,
      frozen_candidate_sha256: exported.frozen_candidate_sha256,
      run_folder: folder,
      files: exported.files,
      product_sources: exported.product_sources,
    }, null, 2) + '\n');
    summaries.push({ direction, run_id: runId, verdict: exported.verdict, run_started_at: runStartedAt });
    process.stderr.write(direction + ' ' + exported.verdict + ' ' + runId + '\n');
  }
  const files = [];
  for (const entry of await walk(lane)) {
    if (entry.relative_path === 'manifest.json') continue;
    if (entry.relative_path === 'README.md') continue;
    const bytes = await readFile(entry.full);
    files.push({ relative_path: entry.relative_path, sha256: sha256(bytes), size_bytes: bytes.length });
  }
  const pinnedSources = [];
  const exported = JSON.parse(await readFile(path.join(lane, directions[0], 'manifest.json'), 'utf8'));
  for (const source of exported.product_sources) pinnedSources.push(source);
  await writeFile(path.join(lane, 'manifest.json'), JSON.stringify({
    schema_version: 1,
    product: 'Wirefit',
    lane: 'research/vmde/directions',
    product_built_at: productBuiltAtIso,
    directions: summaries,
    files,
    product_sources: pinnedSources,
  }, null, 2) + '\n');
  process.stderr.write('lane manifest written for ' + String(summaries.length) + ' directions\n');
}

await main();
