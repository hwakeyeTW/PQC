"""Offline, single-file legacy import into an existing private Run Store."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from tools import assessment, cff, evidence, import_legacy, run_store

RULES_PATH = Path(__file__).resolve().parents[1] / 'config/assessment_rules.yml'


class ImportErrorCode(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(ok, code):
    if not ok:
        raise ImportErrorCode(code)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _read_local(path, limit):
    """Pin every directory; read only a bounded, unchanged regular file."""
    path = os.fspath(path)
    _require(type(path) is str and path.startswith('/') and len(path) <= 4096
             and '\x00' not in path, 'INVALID_INPUT_PATH')
    parts = path[1:].split('/')
    _require(all(p not in ('', '.', '..') for p in parts), 'INVALID_INPUT_PATH')
    parent = fd = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        parent = os.open('/', flags)
        for part in parts[:-1]:
            nxt = os.open(part, flags, dir_fd=parent)
            os.close(parent)
            parent = nxt
        name = parts[-1]
        original = os.stat(name, dir_fd=parent, follow_symlinks=False)
        _require(stat.S_ISREG(original.st_mode), 'UNSAFE_INPUT_FILE')
        _require(0 < original.st_size <= limit, 'INPUT_SIZE_LIMIT')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode), 'UNSAFE_INPUT_FILE')
        _require(_identity(original) == _identity(before), 'INPUT_CHANGED')
        out = bytearray()
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - len(out)))
            if not chunk:
                break
            out.extend(chunk)
            _require(len(out) <= limit, 'INPUT_SIZE_LIMIT')
        _require(len(out) == before.st_size and
                 _identity(before) == _identity(os.fstat(fd)) ==
                 _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                 'INPUT_CHANGED')
        return bytes(out)
    except OSError:
        raise ImportErrorCode('INPUT_IO') from None
    finally:
        if fd is not None:
            os.close(fd)
        if parent is not None:
            os.close(parent)


def _rules():
    try:
        raw = _read_local(RULES_PATH, assessment.MAX_RULE_BYTES)
        return raw, assessment.load_rules(raw)
    except (ImportErrorCode, assessment.AssessmentError):
        raise ImportErrorCode('INVALID_RULES_SOURCE') from None


def _prepare(input_path, format_id, run_id, recorded_at, origin_ref, source_version):
    # Read the fixed trusted policy once. Every downstream operation uses
    # this parsed object and its exact original bytes, never another file.
    raw_rules, rules = _rules()
    raw = _read_local(input_path, import_legacy.MAX_BYTES)
    result = import_legacy.import_legacy(
        raw, format_id=format_id, run_id=run_id, recorded_at=recorded_at,
        origin_ref=origin_ref, source_version=source_version, rules=rules,
        disabled_manifest=None)
    doc, prov, diagnostics = result
    source = doc['run']['source']
    _require(prov['original_run_id'] != run_id, 'REUSED_ORIGINAL_RUN_ID')
    _require(source == {'source_kind': 'LEGACY_IMPORT',
                         'producer_id': prov['format_id'],
                         'producer_version': prov['source_version'],
                         'origin_ref': prov['origin_ref'],
                         'input_sha256': prov['input_sha256']} and
             source['input_sha256'] == hashlib.sha256(raw).hexdigest(),
             'IMPORT_PROVENANCE_MISMATCH')
    legacy = {'format_version': '1.0.0', 'source': source,
              'original_run_id': prov['original_run_id'],
              'original_generated_at': prov['original_generated_at'],
              'diagnostics': [{'reason_code': key, 'count': count}
                              for key, count in sorted(diagnostics.items())]}
    assessed = assessment.evaluate_document(doc, rules)
    projection = cff.project_cff(doc, rules)
    projection_raw = cff.canonical_projection_bytes(projection, assessed, rules)
    # Preflight the tighter producer and store limits before reserving an ID.
    # Store's public finalize/open still validate the same artifacts.
    try:
        legacy_raw = run_store._json_bytes(legacy, run_store.MAX_DETAIL)
        store_cff = run_store._json_bytes(projection, run_store.MAX_CFF)
        _require(store_cff == projection_raw, 'PROJECTION_ENCODING_MISMATCH')
        core = (evidence.canonical_bytes(doc), evidence.canonical_bytes(assessed),
                raw_rules, projection_raw, legacy_raw)
        _require(all(0 < len(x) <= cap for x, cap in zip(core, (
            run_store.MAX_EVIDENCE, run_store.MAX_EVIDENCE,
            assessment.MAX_RULE_BYTES, min(cff.MAX_BYTES, run_store.MAX_CFF),
            run_store.MAX_DETAIL))) and
            sum(map(len, core)) <= run_store.MAX_CORE, 'IMPORT_CAPACITY_LIMIT')
    except run_store.StoreError as exc:
        raise ImportErrorCode('IMPORT_' + exc.code) from None
    expected = [{key: host[key] for key in
                 ('target_id', 'inventory_authority_id', 'identity_key')}
                for host in doc['hosts']]
    return raw, doc, legacy, expected, assessed, raw_rules, projection


def _publish(prepared, report_root):
    raw, doc, legacy, expected, assessed, raw_rules, projection = prepared
    run = doc['run']
    with run_store.RunStore(report_root) as store:
        with store.begin(run_id=run['run_id'], run_kind='LEGACY_IMPORT',
                         evidence_schema_version='1.0.0', source=run['source'],
                         recorded_at=run['recorded_at'], started_at=None,
                         expected_hosts=expected, legacy_raw=raw,
                         legacy_provenance=legacy,
                         requirements={'assessment': True, 'cff': True, 'details': []}) as writer:
            run_store.require([h['host_id'] for h in writer.scope['hosts']] ==
                              sorted(run['expected_host_ids']), 'IMPORT_SCOPE_MISMATCH')
            for hid in sorted(run['expected_host_ids']):
                writer.record_host(run_store.host_fragment(doc, hid),
                                   attempted=None, terminal=None)
            published = writer.finalize(doc, assessed=assessed,
                                        rules_raw=raw_rules, cff=projection)
        verified = store.open(run['run_id'])
        run_store.require(verified == published, 'IMPORT_READBACK_MISMATCH')
        return verified


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default diagnostics can echo arbitrary caller paths/data.
        raise ImportErrorCode('INVALID_ARGUMENTS')


def main(argv=None):
    parser = _Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--input', required=True)
    parser.add_argument('--format', required=True, choices=import_legacy.FORMATS)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--recorded-at', required=True)
    parser.add_argument('--origin-ref', required=True)
    parser.add_argument('--source-version')
    parser.add_argument('--report-root', required=True)
    try:
        args = parser.parse_args(argv)
        prepared = _prepare(args.input, args.format, args.run_id,
                            args.recorded_at, args.origin_ref, args.source_version)
        result = _publish(prepared, args.report_root)
    except (ImportErrorCode, import_legacy.LegacyImportError,
            evidence.EvidenceError, assessment.AssessmentError, cff.ProjectionError) as exc:
        print(json.dumps({'reason_code': exc.code}), file=sys.stderr)
        return 2
    except run_store.StoreError as exc:
        print(json.dumps({'reason_code': exc.code}), file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print(json.dumps({'reason_code': 'INTERRUPTED'}), file=sys.stderr)
        return 130
    except Exception:
        # No input values or tracebacks escape this controller CLI boundary.
        print(json.dumps({'reason_code': 'IMPORT_FAILED'}), file=sys.stderr)
        return 3
    print(json.dumps({key: result.manifest[key] for key in
                      ('run_id', 'publication_state', 'run_kind', 'run_state', 'reason_code')},
                     sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
