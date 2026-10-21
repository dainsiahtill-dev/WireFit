#!/usr/bin/env python3
"""Verify the frozen research lane manifest.

The lane manifest pins two things:

1. `files`          the identity of every file inside the lane package
2. `product_sources` the identity of the product sources the lane depends on

A product change invalidates the lane: the product source digests no longer
match, and the lane must be re-run and re-signed. This script is read only.

Usage:
    python verify-manifest.py
    python verify-manifest.py --manifest PATH
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
# The verifier is executed from the lane directory, so the lane is the parent
# of the script and the repository root is four levels above it. When the
# script runs from the source tree the repository root is two levels above.
if os.path.isdir(os.path.join(HERE, '..', '..', '..', '..', 'contracts')):
    REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..', '..', '..'))
else:
    REPO_ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description='Verify the research lane manifest.')
    parser.add_argument('--manifest', default=os.path.join(HERE, 'manifest.json'))
    arguments = parser.parse_args(argv)
    manifest_path = os.path.abspath(arguments.manifest)
    lane = os.path.dirname(manifest_path)
    with open(manifest_path, 'r', encoding='utf-8') as handle:
        manifest = json.load(handle)
    errors = []
    checked = 0
    for entry in manifest.get('files', []):
        target = os.path.join(lane, entry['relative_path'].replace('/', os.sep))
        if not os.path.isfile(target):
            errors.append('missing file ' + entry['relative_path'])
            continue
        observed = sha256_file(target)
        checked += 1
        if observed != entry['sha256']:
            errors.append('digest mismatch for ' + entry['relative_path'])
    for entry in manifest.get('product_sources', []):
        target = os.path.join(REPO_ROOT, entry['path'].replace('/', os.sep))
        if not os.path.isfile(target):
            errors.append('missing product source ' + entry['path'])
            continue
        observed = sha256_file(target)
        checked += 1
        if observed != entry['sha256']:
            errors.append('product source changed: ' + entry['path'])
    for error in errors:
        sys.stdout.write('FAIL ' + error + '\n')
    sys.stdout.write('{0}/{1} identities verified\n'.format(checked - len(errors), checked))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
