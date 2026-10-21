#!/usr/bin/env python3
"""Independent auditor of the vmde research direction packages.

This auditor is the authoritative layer of the three layer audit described in
docs/RESEARCH-PROTOCOL.md:

    L1  src/research/recheck.ts        TypeScript, product side, convenience
    L2  this file                      Python, lane side, authoritative
    L3  L1 versus L2                   cross implementation consistency

This file shares NO code with the product. It re-implements the restricted
path language, the eleven recipe kernels and the nine comparators from the
normative specification, and re-derives every recorded observation from the
raw artifacts inside each direction package.

It is strictly read only. It never re-runs an experiment, never writes into a
package and never touches the product tree. It only reads.

Usage:
    python audit.py --all
    python audit.py --direction D01
    python audit.py --all --json

Exit code 0 when every direction agrees, 1 otherwise.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..', '..'))

SEGMENT_PATTERN = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)(?:\[(\*|[0-9]+)\])?$')

# The lane directory. It defaults to the directory of this script, so a
# frozen package audits itself, and it can be pointed at any other lane.
LANE = HERE

DIRECTION_IDS = [
    'D01', 'D02', 'D03', 'D04', 'D05', 'D06', 'D07', 'D08', 'D09',
    'D10', 'D11', 'D12', 'D13', 'D14', 'D15', 'D16', 'D17',
]


class AuditError(Exception):
    """A package could not be audited at all."""


# --------------------------------------------------------------------------
# Normalisation, mirroring section 3.3 of the protocol.
# --------------------------------------------------------------------------

def normalize_scalar(value):
    """Collapse integral floats onto integers so both implementations agree."""
    if isinstance(value, bool):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def encode_scalar(value):
    """The type prefixed encoding of a set member, per section 4.2."""
    value = normalize_scalar(value)
    if value is None:
        return 'z:null'
    if isinstance(value, bool):
        return 'b:true' if value else 'b:false'
    if isinstance(value, int):
        return 'n:' + str(value)
    if isinstance(value, float):
        return 'n:' + str(int(value)) if value.is_integer() else 'n:' + repr(value)
    return 's:' + str(value)


def serialize_set(values):
    """A sorted, deduplicated, pipe joined set encoding."""
    return '|'.join(sorted({encode_scalar(value) for value in values}))


def parse_set(text):
    if text == '':
        return []
    return sorted({part for part in text.split('|') if part != ''})


# --------------------------------------------------------------------------
# The restricted path language, section 3.
# --------------------------------------------------------------------------

def parse_path(path):
    if not isinstance(path, str) or path == '':
        raise AuditError('RECIPE_PATH_INVALID: the path must be a nonempty string')
    segments = []
    for raw in path.split('.'):
        match = SEGMENT_PATTERN.match(raw)
        if match is None:
            raise AuditError('RECIPE_PATH_INVALID: invalid path segment ' + repr(raw))
        index = None
        if match.group(2) is not None:
            index = '*' if match.group(2) == '*' else int(match.group(2))
        segments.append((match.group(1), index))
    return segments


def select_path(root, path):
    current = [root]
    for name, index in parse_path(path):
        following = []
        for node in current:
            if not isinstance(node, dict):
                raise AuditError('RECIPE_PATH_INVALID: a path segment does not address an object')
            if name not in node:
                raise AuditError('RECIPE_PATH_INVALID: absent path property ' + repr(name))
            value = node[name]
            if index is None:
                following.append(value)
            elif index == '*':
                if not isinstance(value, list):
                    raise AuditError('RECIPE_PATH_INVALID: a wildcard requires an array')
                following.extend(value)
            else:
                if not isinstance(value, list):
                    raise AuditError('RECIPE_PATH_INVALID: an index requires an array')
                if index >= len(value):
                    raise AuditError('RECIPE_PATH_INVALID: path index out of range')
                following.append(value[index])
        current = following
    return current


def select_values(document, derivation):
    selected = select_path(document, derivation.get('path', ''))
    field = derivation.get('field')
    values = []
    for node in selected:
        value = node
        if field is not None:
            if not isinstance(node, dict):
                raise AuditError('RECIPE_VALUE_TYPE_MISMATCH: a field requires object nodes')
            if field not in node:
                raise AuditError('RECIPE_VALUE_TYPE_MISMATCH: absent field ' + repr(field))
            value = node[field]
        if not (value is None or isinstance(value, (str, int, float, bool))):
            raise AuditError('RECIPE_VALUE_TYPE_MISMATCH: values must be scalars')
        values.append(normalize_scalar(value))
    return values


def second_values(documents, derivation):
    role = derivation.get('second_artifact_role')
    if role is None:
        raise AuditError('RECIPE_DERIVATION_INVALID: set_equality needs a second artifact role')
    document = documents.get(role)
    if document is None:
        raise AuditError('RECIPE_DERIVATION_INVALID: unknown artifact role ' + repr(role))
    selected = select_path(document, derivation.get('second_path', ''))
    field = derivation.get('field')
    values = []
    for node in selected:
        value = node
        if field is not None:
            if not isinstance(node, dict):
                raise AuditError('RECIPE_VALUE_TYPE_MISMATCH: a field requires object nodes')
            if field not in node:
                raise AuditError('RECIPE_VALUE_TYPE_MISMATCH: absent field ' + repr(field))
            value = node[field]
        if not (value is None or isinstance(value, (str, int, float, bool))):
            raise AuditError('RECIPE_VALUE_TYPE_MISMATCH: values must be scalars')
        values.append(normalize_scalar(value))
    return values


def same_scalar(left, right):
    left = normalize_scalar(left)
    right = normalize_scalar(right)
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if type(left) is not type(right):
        return False
    return left == right


def count_byte_pattern(data, pattern):
    if not pattern:
        return 0
    count = 0
    start = 0
    while True:
        index = data.find(pattern, start)
        if index < 0:
            break
        count += 1
        start = index + 1
    return count


# --------------------------------------------------------------------------
# The recipe kernels, section 4.
# --------------------------------------------------------------------------

def evaluate_kernel(documents, binaries, derivation):
    kernel = derivation.get('kernel')
    role = derivation.get('artifact_role')
    if role is None:
        raise AuditError('RECIPE_DERIVATION_INVALID: a derivation needs an artifact role')
    if kernel == 'row_count':
        document = documents.get(role)
        if document is None:
            raise AuditError('RECIPE_DERIVATION_INVALID: unknown artifact role ' + repr(role))
        return len(select_path(document, derivation.get('path', '')))
    if kernel == 'distinct_count':
        values = select_values(documents.get(role), derivation)
        return len({encode_scalar(value) for value in values})
    if kernel == 'field_count':
        expected = derivation.get('value')
        if expected is None:
            raise AuditError('RECIPE_DERIVATION_INVALID: field_count needs a value')
        values = select_values(documents.get(role), derivation)
        return sum(1 for value in values if same_scalar(value, expected))
    if kernel in ('field_sum', 'field_min', 'field_max'):
        values = select_values(documents.get(role), derivation)
        if not values:
            raise AuditError('RECIPE_EMPTY_SELECTION: aggregation requires a nonempty selection')
        numbers = []
        for value in values:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise AuditError('RECIPE_VALUE_TYPE_MISMATCH: aggregation requires integers')
            if not float(value).is_integer():
                raise AuditError('RECIPE_VALUE_TYPE_MISMATCH: aggregation requires integers')
            numbers.append(int(value))
        if kernel == 'field_sum':
            return sum(numbers)
        if kernel == 'field_min':
            return min(numbers)
        return max(numbers)
    if kernel == 'all_equal':
        expected = derivation.get('value')
        if expected is None:
            raise AuditError('RECIPE_DERIVATION_INVALID: all_equal needs a value')
        values = select_values(documents.get(role), derivation)
        if not values:
            return False
        return all(same_scalar(value, expected) for value in values)
    if kernel == 'any_equal':
        expected = derivation.get('value')
        if expected is None:
            raise AuditError('RECIPE_DERIVATION_INVALID: any_equal needs a value')
        values = select_values(documents.get(role), derivation)
        return any(same_scalar(value, expected) for value in values)
    if kernel == 'set_equality':
        if derivation.get('second_artifact_role') is not None:
            left = serialize_set(select_values(documents.get(role), derivation))
            right = serialize_set(second_values(documents, derivation))
            return left == right
        return serialize_set(select_values(documents.get(role), derivation))
    if kernel == 'file_sha256':
        data = binaries.get(role)
        if data is None:
            raise AuditError('RECIPE_DERIVATION_INVALID: unknown binary role ' + repr(role))
        return hashlib.sha256(data).hexdigest()
    if kernel == 'byte_pattern_count':
        pattern_hex = derivation.get('pattern_hex')
        if not isinstance(pattern_hex, str) or len(pattern_hex) == 0 or len(pattern_hex) % 2 != 0:
            raise AuditError('RECIPE_DERIVATION_INVALID: byte_pattern_count needs an even hex pattern')
        data = binaries.get(role)
        if data is None:
            raise AuditError('RECIPE_DERIVATION_INVALID: unknown binary role ' + repr(role))
        return count_byte_pattern(data, bytes.fromhex(pattern_hex))
    raise AuditError('RECIPE_KERNEL_UNKNOWN: unknown kernel ' + repr(kernel))


# --------------------------------------------------------------------------
# The comparators, section 5.
# --------------------------------------------------------------------------

def compare_observation(observed, expected, comparator):
    if comparator == 'eq':
        return same_scalar(observed, expected)
    if comparator == 'ne':
        return not same_scalar(observed, expected)
    if comparator in ('gte', 'lte', 'gt', 'lt'):
        if isinstance(observed, bool) or isinstance(expected, bool):
            return False
        if not isinstance(observed, (int, float)) or not isinstance(expected, (int, float)):
            return False
        if comparator == 'gte':
            return observed >= expected
        if comparator == 'lte':
            return observed <= expected
        if comparator == 'gt':
            return observed > expected
        return observed < expected
    if comparator == 'identical_set':
        left = parse_set(str(observed))
        right = parse_set(str(expected))
        return left == right
    if comparator == 'subset':
        left = parse_set(str(observed))
        right = parse_set(str(expected))
        return all(item in right for item in left)
    if comparator == 'superset':
        left = parse_set(str(observed))
        right = parse_set(str(expected))
        return all(item in left for item in right)
    raise AuditError('RECIPE_COMPARATOR_UNKNOWN: unknown comparator ' + repr(comparator))


# --------------------------------------------------------------------------
# Package loading.
# --------------------------------------------------------------------------

def load_json(path):
    with open(path, 'r', encoding='utf-8') as handle:
        return json.load(handle)


def load_package(direction):
    """Loads one direction package and returns its documents and binaries."""
    directory = os.path.join(LANE, direction)
    if not os.path.isdir(directory):
        raise AuditError('the direction package ' + direction + ' is missing')
    plan_path = os.path.join(directory, 'plan.json')
    checks_path = os.path.join(directory, 'checks.json')
    receipt_path = os.path.join(directory, 'receipt.json')
    for required in (plan_path, checks_path, receipt_path):
        if not os.path.isfile(required):
            raise AuditError('the direction package ' + direction + ' is incomplete')
    plan = load_json(plan_path)
    checks = load_json(checks_path)
    receipt = load_json(receipt_path)
    documents = {}
    binaries = {}
    artifact_roots = []
    direct = os.path.join(directory, 'artifacts')
    if os.path.isdir(direct):
        artifact_roots.append(direct)
    for name in sorted(os.listdir(directory)):
        candidate = os.path.join(directory, name, 'artifacts')
        if os.path.isdir(candidate):
            artifact_roots.append(candidate)
    for artifact_root in artifact_roots:
        for base, _dirs, names in os.walk(artifact_root):
            for name in sorted(names):
                if not name.endswith('.json'):
                    continue
                full = os.path.join(base, name)
                relative = os.path.relpath(full, artifact_root).replace(os.sep, '/')
                role = relative[:-len('.json')]
                with open(full, 'rb') as handle:
                    raw = handle.read()
                binaries[role] = raw
                try:
                    documents[role] = json.loads(raw.decode('utf-8'))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    pass
    return {
        'direction': direction,
        'plan': plan,
        'checks': checks,
        'receipt': receipt,
        'documents': documents,
        'binaries': binaries,
    }


def evidence_documents(plan):
    """Resolves the pinned evidence documents of a plan from the repository."""
    documents = {}
    binaries = {}
    for pin in plan.get('evidence_pins', []):
        path = os.path.join(REPO_ROOT, pin['path'].replace('/', os.sep))
        if not os.path.isfile(path):
            continue
        with open(path, 'rb') as handle:
            raw = handle.read()
        binaries[pin['role']] = raw
        if pin['path'].endswith('.jsonl'):
            # A JSON Lines corpus is addressed as {"rows": [...]}, exactly as
            # the product corpus loader addresses it.
            rows = []
            for line in raw.decode('utf-8').splitlines():
                if line.strip() != '':
                    rows.append(json.loads(line))
            documents[pin['role']] = {'rows': rows}
            continue
        try:
            documents[pin['role']] = json.loads(raw.decode('utf-8'))
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return documents, binaries


# --------------------------------------------------------------------------
# The audit.
# --------------------------------------------------------------------------

def audit_direction(direction):
    """Audits one direction package and returns its report."""
    package = load_package(direction)
    plan = package['plan']
    receipt = package['receipt']
    documents = dict(package['documents'])
    binaries = dict(package['binaries'])
    evidence_docs, evidence_binaries = evidence_documents(plan)
    for role, value in evidence_docs.items():
        documents.setdefault(role, value)
    for role, value in evidence_binaries.items():
        binaries.setdefault(role, value)
    records = []
    agreed = 0
    # The derivation and the expectation are owned by the frozen plan. The
    # checks file only records what the run observed, so the audit replays
    # the pre-registered derivation and compares it with the record.
    registered = {}
    for claim in plan.get('claims', []):
        for check in claim.get('checks', []):
            registered[check.get('check_id')] = check
    for check in package['checks'].get('checks', []):
        record = {
            'check_id': check.get('check_id', ''),
            'claim_id': check.get('claim_id', ''),
            'role': check.get('role', ''),
            'recorded_observed': check.get('observed'),
            'recomputed_observed': None,
            'recorded_passed': check.get('passed'),
            'recomputed_passed': None,
            'status': 'AGREE',
            'code': '',
        }
        source = registered.get(check.get('check_id'))
        if source is None:
            record['status'] = 'ERROR'
            record['code'] = 'CHECK_NOT_IN_PLAN'
            records.append(record)
            continue
        derivation = source.get('derivation')
        if derivation is None:
            record['status'] = 'ERROR'
            record['code'] = 'DERIVATION_ABSENT'
            records.append(record)
            continue
        try:
            observed = evaluate_kernel(documents, binaries, derivation)
        except AuditError as error:
            record['status'] = 'ERROR'
            record['code'] = str(error).split(':')[0]
            records.append(record)
            continue
        record['recomputed_observed'] = observed
        try:
            passed = compare_observation(observed, source.get('expected'), source.get('comparator'))
        except AuditError as error:
            record['status'] = 'ERROR'
            record['code'] = str(error).split(':')[0]
            records.append(record)
            continue
        record['recomputed_passed'] = passed
        if not same_scalar(observed, check.get('observed')):
            record['status'] = 'MISMATCH'
            record['code'] = 'AUDIT_METRIC_MISMATCH'
        elif passed != check.get('passed'):
            record['status'] = 'MISMATCH'
            record['code'] = 'AUDIT_PASS_MISMATCH'
        else:
            agreed += 1
        records.append(record)
    checked = len(records)
    statuses = {record['status'] for record in records}
    if 'MISMATCH' in statuses:
        status = 'DISAGREE'
    elif 'ERROR' in statuses:
        status = 'ERROR'
    else:
        status = 'AGREE'
    return {
        'direction': direction,
        'status': status,
        'checked_count': checked,
        'agreed_count': agreed,
        'recorded_verdict': receipt.get('verdict'),
        'recorded_verdict_reason': receipt.get('verdict_reason'),
        'plan_sha256': package['checks'].get('plan_sha256'),
        'checks': records,
    }


def run_fixture(path):
    """Evaluates a fixture of derivations.

    This is the cross implementation surface: the product test feeds the same
    fixture to the TypeScript kernel interpreter and to this file and asserts
    that both produce byte identical output.
    """
    with open(path, 'r', encoding='utf-8') as handle:
        fixture = json.load(handle)
    documents = {role: value for role, value in fixture.get('documents', {}).items()}
    binaries = {}
    for role, encoded in fixture.get('binaries', {}).items():
        binaries[role] = bytes.fromhex(encoded)
    results = []
    for entry in fixture.get('cases', []):
        derivation = entry['derivation']
        try:
            observed = evaluate_kernel(documents, binaries, derivation)
            passed = compare_observation(observed, entry['expected'], entry['comparator'])
            results.append({'id': entry['id'], 'observed': observed, 'passed': passed, 'error': None})
        except AuditError as error:
            results.append({'id': entry['id'], 'observed': None, 'passed': None, 'error': str(error).split(':')[0]})
    sys.stdout.write(json.dumps({'results': results}, ensure_ascii=False, sort_keys=True) + '\n')
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description='Audit the vmde research direction packages.')
    parser.add_argument('--all', action='store_true', help='audit every direction package')
    parser.add_argument('--direction', action='append', default=[], help='audit one direction')
    parser.add_argument('--json', action='store_true', help='emit the full report as JSON')
    parser.add_argument('--fixture', help='evaluate a fixture file of derivations and print the results')
    parser.add_argument('--lane', help='the lane directory that holds the direction packages')
    arguments = parser.parse_args(argv)
    if arguments.lane is not None:
        global LANE
        LANE = os.path.abspath(arguments.lane)
    if arguments.fixture is not None:
        return run_fixture(arguments.fixture)
    if not arguments.all and not arguments.direction:
        parser.error('either --all or --direction is required')
    directions = DIRECTION_IDS if arguments.all else arguments.direction
    reports = []
    for direction in directions:
        try:
            reports.append(audit_direction(direction))
        except AuditError as error:
            reports.append({
                'direction': direction,
                'status': 'ERROR',
                'checked_count': 0,
                'agreed_count': 0,
                'checked': [],
                'checks': [],
                'error': str(error),
            })
    if arguments.json:
        sys.stdout.write(json.dumps({'reports': reports}, ensure_ascii=False, indent=2) + '\n')
    else:
        for report in reports:
            line = '{0} {1} checked={2} agreed={3} verdict={4}'.format(
                report['direction'], report['status'], report['checked_count'],
                report['agreed_count'], report.get('recorded_verdict'))
            sys.stdout.write(line + '\n')
            for record in report.get('checks', []):
                if record['status'] != 'AGREE':
                    sys.stdout.write('    {0} {1} {2}\n'.format(
                        record['status'], record['check_id'], record['code']))
    failed = [report for report in reports if report['status'] != 'AGREE']
    sys.stdout.write('{0}/{1} directions agree\n'.format(
        len(reports) - len(failed), len(reports)))
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
