import path from 'node:path';
import { lstat, readFile } from 'node:fs/promises';
import { snapshot } from '../binary-files.js';
import { assert, errorRecord, rootDir, WirefitError } from '../shared.js';
import { boundedText, dataObject } from './validation.js';
import { verifyConfiguredIdaProbe, verifiedIdaSamples } from './probe.js';
import type { IdaConfiguration, IdaCapabilities, IdaProvider } from './types.js';

const CODE = 'IDA_CONFIGURATION_INVALID';
export const IDA_QUERY_KINDS = [
  'overview',
  'functions',
  'strings',
  'function',
  'xrefs',
  'bytes',
  'types',
] as const;
export function validateIdaConfiguration(value: unknown): IdaConfiguration {
  const config = dataObject(
    value,
    ['schema_version', 'command', 'args', 'env', 'provider', 'lifecycle', 'probe_receipt'],
    'IDA configuration',
    CODE,
  );
  assert(
    config.schema_version === 1 && config.lifecycle === 'owned-stdio',
    CODE,
    'Only schema 1 owned-stdio runtime configuration is supported',
  );
  boundedText(config.command, 4096, 'Executable', false, CODE);
  assert(
    path.isAbsolute(config.command),
    CODE,
    'IDA executable must be an absolute administrator-selected path',
  );
  assert(Array.isArray(config.args) && config.args.length <= 128, CODE, 'IDA argv must be bounded');
  for (const arg of config.args) boundedText(arg, 4096, 'Argument', true, CODE);
  assert(
    config.args.includes('{input}') && config.args.includes('{database}'),
    CODE,
    'Owned runtime must accept isolated input and database placeholders',
  );
  assert(
    config.args.every((arg: string) => !arg.includes('{') || arg === '{input}' || arg === '{database}'),
    CODE,
    'IDA argv contains an unknown placeholder',
  );
  const provider = dataObject(config.provider, ['version', 'server', 'revision'], 'IDA provider', CODE);
  boundedText(provider.version, 128, 'IDA version', false, CODE);
  boundedText(provider.server, 256, 'IDA server', false, CODE);
  assert(
    typeof provider.revision === 'string' && /^[a-f0-9]{40}$/.test(provider.revision),
    CODE,
    'IDA runtime must pin its source revision',
  );
  let env: Record<string, string> | undefined;
  if (config.env !== undefined) {
    assert(
      config.env !== null &&
        typeof config.env === 'object' &&
        !Array.isArray(config.env) &&
        Object.keys(config.env).length <= 64,
      CODE,
      'IDA environment must be bounded',
    );
    env = {};
    for (const key of Reflect.ownKeys(config.env)) {
      const descriptor = Object.getOwnPropertyDescriptor(config.env, key);
      assert(
        typeof key === 'string' &&
          /^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(key) &&
          descriptor?.enumerable &&
          'value' in descriptor,
        CODE,
        'Environment names must be plain data',
      );
      boundedText(descriptor.value, 32768, 'Environment value', true, CODE);
      Object.defineProperty(env, key, { value: descriptor.value, enumerable: true, writable: true });
    }
  }
  if (config.probe_receipt !== undefined) {
    boundedText(config.probe_receipt, 4096, 'Probe receipt', false, CODE);
    assert(path.isAbsolute(config.probe_receipt), CODE, 'Probe receipt must be absolute');
  }
  return {
    schema_version: 1,
    lifecycle: 'owned-stdio',
    command: config.command,
    args: [...config.args] as string[],
    provider: { version: provider.version, server: provider.server, revision: provider.revision },
    ...(env ? { env } : {}),
    ...(config.probe_receipt ? { probe_receipt: config.probe_receipt as string } : {}),
  };
}
export async function loadIdaConfiguration(root = rootDir): Promise<IdaConfiguration | undefined> {
  const file = path.join(root, '.local', 'ida-mcp.json');
  let selected;
  try {
    selected = await snapshot(file, 64 * 1024);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw error;
  }
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(selected.bytes));
  } catch {
    throw new WirefitError(CODE, 'IDA configuration is not valid UTF-8 JSON');
  }
  return validateIdaConfiguration(value);
}
export function providerIdentity(configuration: IdaConfiguration): IdaProvider {
  return { id: 'ida', ...configuration.provider };
}
/** A persisted real probe is evidence, executable presence by itself is not. Never starts IDA. */
export async function idaCapabilities(root = rootDir): Promise<IdaCapabilities> {
  const output: IdaCapabilities = {
    configured: false,
    installed: false,
    status: 'not_configured',
    provider: null,
    configuration_path: path.join(root, '.local', 'ida-mcp.json'),
    probe: null,
    samples: [],
    queries: IDA_QUERY_KINDS,
    read_only: true,
    native_execution: false,
  };
  let config: IdaConfiguration | undefined;
  try {
    config = await loadIdaConfiguration(root);
  } catch (error) {
    output.configured = true;
    output.status = 'invalid_configuration';
    output.error = errorRecord(error, 'ida-configuration');
    return output;
  }
  if (!config) return output;
  output.configured = true;
  output.provider = providerIdentity(config);
  output.status = 'not_probed';
  try {
    const info = await lstat(config.command);
    output.installed = info.isFile() && !info.isSymbolicLink();
  } catch {
    /* Capability records absence without trying a command. */
  }
  if (!config.probe_receipt) return output;
  try {
    const { probe, receipt_sha256, ...runtime } = await verifyConfiguredIdaProbe(
      config,
      output.configuration_path,
    );
    output.status = 'verified';
    output.probe = {
      checked_at: probe.checked_at,
      receipt_sha256,
      ...runtime,
      native_initialized: true,
      mcp_handshake: true,
      identity_verified: true,
      fixture: { disassembly: true, decompilation: true },
      ...(probe.capabilities ? { capabilities: probe.capabilities } : {}),
      ...(Array.isArray(probe.limitations)
        ? {
            limitations: probe.limitations
              .filter((item: unknown) => typeof item === 'string' && item.length <= 4096)
              .slice(0, 16),
          }
        : {}),
    };
    output.samples = await verifiedIdaSamples(probe.samples);
  } catch (error) {
    output.status = 'probe_failed';
    output.error = errorRecord(error, 'ida-probe');
  }
  return output;
}
