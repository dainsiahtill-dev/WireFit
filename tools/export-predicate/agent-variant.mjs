import { createHash } from 'node:crypto';

const SOURCE_SHA256 = 'e98e21e5e6922560db05326d78b391f101a390f00841e1106750a8bc0b572e4d';
const MARKER = 'wirefit_export_predicate_v1=';
const GUARD = '            if (exported === undefined || exported.type !== "function" || range === null || !range.protection.includes("x")) {\n';
const OLD_THROW = '                throw new Error("Requested export is not an executable function");\n';
const ANCHOR = GUARD + OLD_THROW + '            }\n';
const NEW_THROW = `                let diagnostic;
                try {
                    const bounded = value => String(value).slice(0, 32);
                    diagnostic = JSON.stringify({
                        target: bounded(target), export_present: exported !== undefined,
                        export_type: exported === undefined ? null : bounded(exported.type),
                        export_address: exported === undefined ? null : bounded(exported.address),
                        range_present: range !== null, range_base: range === null ? null : bounded(range.base),
                        range_size: range === null ? null : (Number.isSafeInteger(range.size) && range.size >= 0 ? range.size : bounded(range.size)),
                        range_protection: range === null ? null : bounded(range.protection)
                    });
                    if (typeof diagnostic !== "string" || diagnostic.length > 1536) throw new Error("Diagnostic exceeds its bound");
                } catch (_) {
                    diagnostic = '{"diagnostic_error":"diagnostic_build_failed"}';
                }
                throw new Error("Requested export is not an executable function; ${MARKER}" + diagnostic);
`;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function invalid(message) {
  throw Object.assign(new Error(message), { code: 'AGENT_VARIANT_SOURCE_INVALID' });
}

/** Transform the one reviewed agent; never evaluates it or reads any file/target. */
export function instrumentAgent(source) {
  if (!Buffer.isBuffer(source) || source.length !== 15444 || source.length > 65536) invalid('Unexpected agent source type/size');
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(source); }
  catch { invalid('Agent source is not strict UTF-8'); }
  const source_sha256 = hash(source);
  if (source_sha256 !== SOURCE_SHA256) invalid('Agent source identity is not reviewed');
  const start = text.indexOf(ANCHOR);
  if (start < 0 || text.indexOf(ANCHOR, start + 1) !== -1 || text.split(GUARD).length !== 2) {
    invalid('Expected one exact installHooks guard anchor');
  }
  const replacement = GUARD + NEW_THROW + '            }\n';
  const bytes = Buffer.from(text.slice(0, start) + replacement + text.slice(start + ANCHOR.length), 'utf8');
  return { bytes, source_sha256, sha256: hash(bytes), diagnostic_marker: MARKER,
    source_size_bytes: source.length, size_bytes: bytes.length };
}
