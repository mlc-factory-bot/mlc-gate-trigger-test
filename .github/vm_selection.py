#!/usr/bin/env python3
"""Trusted-main VM selection. Unknown inputs run; invalid evidence fails."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ALLOWLIST = frozenset('docs/corpus-analysis/' + name + '.md' for name in (
    'catalogue-gap', 'linkage-and-hygiene', 'metadata-analysis', 'model-fit',
    'provenance-and-currency', 'template-anatomy', 'version-history'))
POLICY_PATH = '.github/vm-selection-policy.json'
COMMIT = re.compile(r'[0-9a-f]{40}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')


def git(repo, *args):
    run = subprocess.run(['git', '-C', str(repo), *args], capture_output=True)
    if run.returncode:
        raise ValueError('git could not establish complete selection evidence')
    return run.stdout


def commit(repo, value):
    if not COMMIT.fullmatch(value):
        raise ValueError('selection requires full immutable commit IDs')
    if git(repo, 'rev-parse', '--verify', value+'^{commit}').decode().strip() != value:
        raise ValueError('selection commit identity mismatch')


def fingerprint(repo, ref):
    commit(repo, ref)
    digest = hashlib.sha256()
    for record in git(repo, 'ls-tree', '-r', '-z', '--full-tree', ref).split(b'\0'):
        if not record:
            continue
        metadata, name = record.split(b'\t', 1)
        path = name.decode('utf-8', errors='strict')
        if path not in ALLOWLIST and path != POLICY_PATH:
            digest.update(metadata + b'\t' + name + b'\0')
    return digest.hexdigest()


def decide(args):
    if args.head_repo != args.repository:
        raise ValueError('fork pull request refused')
    for value in (args.base, args.head):
        commit(args.repo, value)
    git(args.repo, 'merge-base', '--is-ancestor', args.base, args.head)
    policy = json.loads(Path(args.policy).read_text())
    if (set(policy) != {'version', 'consumer_fingerprint'} or policy['version'] != 1
            or not isinstance(policy['consumer_fingerprint'], str)
            or not DIGEST.fullmatch(policy['consumer_fingerprint'])):
        raise ValueError('invalid trusted selection policy')
    actual = fingerprint(args.repo, args.base)
    raw = git(args.repo, 'diff', '--raw', '-z', '--no-abbrev', '--no-renames',
              args.base, args.head, '--').split(b'\0')
    if raw[-1] != b'':
        raise ValueError('incomplete changed-path evidence')
    fields = raw[:-1]
    if len(fields) % 2:
        raise ValueError('incomplete changed-path records')
    paths, eligible = [], True
    for index in range(0, len(fields), 2):
        metadata = fields[index].decode('ascii').split()
        if len(metadata) != 5 or not metadata[0].startswith(':'):
            raise ValueError('invalid changed-path metadata')
        path = fields[index+1].decode('utf-8', errors='strict')
        paths.append(path)
        eligible &= (metadata[0] == ':100644' and metadata[1] == '100644'
                     and metadata[4] == 'M' and path in ALLOWLIST)
    if len(set(paths)) != len(paths):
        raise ValueError('duplicate changed-path evidence')
    skip = bool(paths) and eligible and actual == policy['consumer_fingerprint']
    return {'version': 1, 'head': args.head, 'base': args.base,
            'consumer_fingerprint': actual, 'action': 'skip' if skip else 'run',
            'paths': sorted(paths), 'reason': 'known-non-inputs' if skip else
            ('consumer-inventory-changed' if actual != policy['consumer_fingerprint']
             else 'full-check-required')}


def result(args):
    data = json.loads(args.decision)
    if args.decide_result != 'success':
        raise ValueError('trusted decision did not succeed')
    if (set(data) != {'version', 'head', 'base', 'consumer_fingerprint',
                     'action', 'paths', 'reason'} or data['version'] != 1
            or data['head'] != args.head or data['base'] != args.base
            or not COMMIT.fullmatch(args.head) or not COMMIT.fullmatch(args.base)
            or not isinstance(data['consumer_fingerprint'], str)
            or not DIGEST.fullmatch(data['consumer_fingerprint'])
            or not isinstance(data['paths'], list)
            or not all(isinstance(p, str) for p in data['paths'])):
        raise ValueError('required result has invalid identity or decision evidence')
    if data['action'] == 'run' and data['reason'] in (
            'full-check-required', 'consumer-inventory-changed', 'bootstrap'):
        if args.verify_result != 'success':
            raise ValueError('required VM work did not succeed')
    elif (data['action'] == 'skip' and data['reason'] == 'known-non-inputs'
          and data['paths'] and data['paths'] == sorted(set(data['paths']))
          and all(p in ALLOWLIST for p in data['paths'])):
        if args.verify_result != 'skipped':
            raise ValueError('VM result disagrees with validated skip')
    else:
        raise ValueError('unknown or unsupported selection decision')
    return {'result': 'success', 'action': data['action'], 'head': args.head}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    fp = commands.add_parser('fingerprint')
    fp.add_argument('--repo', required=True)
    fp.add_argument('--ref', required=True)
    choose = commands.add_parser('decide')
    for name in ('repo', 'base', 'head', 'head-repo', 'repository', 'policy'):
        choose.add_argument('--'+name, required=True)
    final = commands.add_parser('result')
    for name in ('decision', 'decide-result', 'verify-result', 'head', 'base'):
        final.add_argument('--'+name, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'fingerprint':
            print(fingerprint(args.repo, args.ref))
        else:
            print(json.dumps(decide(args) if args.command == 'decide' else result(args),
                             sort_keys=True, separators=(',', ':')))
    except (ValueError, OSError, TypeError, KeyError, UnicodeError) as error:
        print('vm-selection REFUSED: '+str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
