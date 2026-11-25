"""Controller-only, immutable derived overview of an existing PublishedRun.

No inventory, managed dispatch, assessment engine, or untrusted template input.
The private Run Store remains the authority for publication and artifact links.
"""
import argparse
from collections import Counter, defaultdict
import os
from pathlib import Path
import sys

from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError

from tools import evidence, run_store

_TEMPLATES = Path(__file__).resolve().parents[1] / 'templates' / 'portal'
_MAX_HTML = 16 * 1024 * 1024
_MAX_CSS = 256 * 1024
_LEVELS = ('Installed', 'Supported (runtime)', 'Configured',
           'Negotiable (service)', 'Observed in use')
_LABELS = {'evidence': 'Evidence JSON', 'assessed': 'Assessed Evidence JSON',
           'rules': 'Assessment rules', 'batch': 'Batch manifest',
           'cff': 'CFF projection', 'legacy': 'Legacy provenance', 'detail': 'Detail JSON'}


def _counts(values, states):
    counts = Counter(values)
    return [(state, counts[state]) for state in states]


def _observations(document, kind, field, states):
    # These are recorded observation counts, not derived support or security
    # verdicts. Preserve the stored taxonomy, including missing algorithms.
    groups = defaultdict(Counter)
    for row in document['evidence']:
        if row['evidence_kind'] != kind:
            continue
        alg = row['algorithm']
        key = (alg['family'], alg['primitive']) if alg is not None else ('UNKNOWN', 'UNKNOWN')
        value = row['data'][field]
        if field == 'supported':
            value = 'SUPPORTED' if value is True else 'UNSUPPORTED' if value is False else 'UNKNOWN'
        groups[key][value] += 1
    return [{'family': family, 'primitive': primitive,
             'counts': [counts[state] for state in states], 'total': sum(counts.values())}
            for (family, primitive), counts in sorted(groups.items())]


def _view(published):
    """Project only a validated PublishedRun; callers cannot supply raw JSON."""
    run_store.require(type(published) is run_store.PublishedRun, 'INVALID_PUBLICATION')
    m, doc, assessed, artifacts = published
    by_host = Counter(c['host_id'] for c in doc['collections'])
    hosts = []
    collectors = []
    for host in m['hosts']:
        hid = host['host_id']
        hosts.append({k: host[k] for k in ('host_id', 'target_id', 'host_state',
                      'reason_code', 'attempted', 'attempt_status', 'dispatch_intent')} |
                     {'scopes': by_host[hid]})
        if m['flags'] is not None:
            terminal = host['terminal']
            rows = {} if terminal is None else {
                run_store.NATIVE_COLLECTORS.get(c['collector_id'], c['collector_id']): c
                for c in terminal['collectors']}
            for collector, requested in sorted(m['flags'][hid].items()):
                row = rows.get(collector)
                collectors.append({'host_id': hid, 'target_id': host['target_id'],
                                   'collector': collector, 'requested': requested,
                                   'state': row['state'] if row is not None else None,
                                   'reason': row['reason_code'] if row is not None else None,
                                   'rc': row['rc'] if row is not None else None,
                                   'scopes': len(row['collection_ids']) if row is not None else None})
    links = []
    for item in m['artifacts']:
        # Only validated, present slots; construct the relative href from the
        # closed Store slot grammar, never an Evidence/metadata URL.
        parts, _ = run_store._slot(item['kind'], item['host_id'], item['slot'])
        path = '/'.join(parts)
        run_store.require(path == item['path'] and path in artifacts, 'INVALID_ARTIFACT_LINK')
        label = _LABELS[item['kind']]
        links.append({'path': path, 'label': label, 'size': item['size'],
                      'version': item['format_version']})
    gaps = Counter((c['collection_state'], c['reason_code']) for c in doc['collections']
                   if c['collection_state'] != 'COLLECTED')
    algorithm_counts = Counter((row['algorithm']['family'], row['algorithm']['primitive'])
                               for row in doc['evidence'] if row['algorithm'] is not None)
    claims = [] if assessed is None else assessed['claims']
    claim_counts = Counter((c['level'], c['assessment_state']) for c in claims)
    return {'run': {k: m[k] for k in ('run_id', 'run_kind', 'publication_state', 'run_state',
                    'reason_code', 'recovery', 'source', 'started_at', 'finished_at', 'recorded_at',
                    'profile', 'evidence_schema_version', 'rule_version', 'rules_sha256',
                    'batch_contract', 'batch_rc', 'batch_missing_reason')},
            'host_counts': [(s, m['counts'][s]) for s in evidence.HOST_STATES],
            'expected': len(m['expected_host_ids']), 'hosts': hosts,
            'collection_total': len(doc['collections']),
            'coverage': _counts((c['collection_state'] for c in doc['collections']), evidence.ACQUISITIONS),
            'gaps': [(state, reason, count) for (state, reason), count in sorted(gaps.items())],
            'flags_known': m['flags'] is not None, 'collectors': collectors,
            'assessed': assessed is not None, 'claim_total': len(claims),
            'levels': [{'level': level, 'label': label,
                        'counts': [claim_counts[level, s] for s in evidence.ASSESSMENTS],
                        'total': sum(claim_counts[level, s] for s in evidence.ASSESSMENTS)}
                       for level, label in zip(evidence.LEVELS, _LEVELS)],
            'assessment_states': evidence.ASSESSMENTS,
            'findings': _counts((f['assessment_state'] for f in assessed['findings'])
                                if assessed is not None else (), evidence.ASSESSMENTS),
            'finding_total': len(assessed['findings']) if assessed is not None else 0,
            'runtime': _observations(doc, 'RUNTIME_CAPABILITY', 'supported',
                                      ('SUPPORTED', 'UNSUPPORTED', 'UNKNOWN')),
            'negotiation': _observations(doc, 'AUTHORIZED_NEGOTIATION', 'outcome',
                                         ('NEGOTIATED', 'REJECTED', 'UNKNOWN', 'ERROR', 'TIMEOUT')),
            'algorithm_counts': [(family, primitive, count)
                                 for (family, primitive), count in sorted(algorithm_counts.items())],
            'links': links, 'missing': m['missing_artifacts'],
            'optional_missing': [_LABELS[k] for k, (name, _) in run_store.FILES.items()
                                 if k in ('assessed', 'rules', 'cff') and name not in artifacts
                                 and not any(x['path'] == name for x in m['missing_artifacts'])]}


def _render(published):
    try:
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES)), autoescape=True,
                          undefined=StrictUndefined, keep_trailing_newline=True)
        out = bytearray()
        for chunk in env.get_template('run_index.html.j2').generate(v=_view(published)):
            raw = chunk.encode('utf-8')
            run_store.require(len(raw) <= _MAX_HTML - len(out), 'PORTAL_SIZE_LIMIT')
            out.extend(raw)
        with (_TEMPLATES / 'portal.css').open('rb') as f:
            css = f.read(_MAX_CSS + 1)
        run_store.require(0 < len(css) <= _MAX_CSS, 'PORTAL_SIZE_LIMIT')
        css.decode('utf-8')
        return bytes(out), css
    except (OSError, TemplateError, UnicodeError):
        raise run_store.StoreError('PORTAL_RENDER_ERROR') from None


def _identity(fd):
    s = os.fstat(fd)
    return s.st_dev, s.st_ino


@run_store._public
def render_run(report_root, run_id):
    """Create index.html and portal.css in one existing, private published run.

    Return the index Path. Equal derived bytes may be reused; different or
    unsafe outputs are never replaced. Run Store is a package-private peer.
    """
    with run_store.RunStore(report_root) as store:
        device = store._device
        # Capture the original directory identity and canonical marker under a
        # shared lock. Never attempt a shared-to-exclusive lock upgrade.
        with store._locked_run(run_id, shared=True) as (fd, _):
            identity = _identity(fd)
            run_store.require(run_store._exists(fd, 'run_manifest.json'), 'INCOMPLETE_RUN')
            marker = run_store._read(fd, 'run_manifest.json', device, run_store.MAX_MANIFEST)
            journal_raw = run_store._read(fd, 'journal.json', device, run_store.MAX_MANIFEST)
        published = store.open(run_id)
        run_store.require(marker == run_store._json_bytes(published.manifest), 'ARTIFACT_CHANGED')
        html, css = _render(published)
        with store._locked_run(run_id, shared=False) as (fd, _):
            run_store.require(_identity(fd) == identity, 'ARTIFACT_CHANGED')
            run_store.require(run_store._read(fd, 'run_manifest.json', device, run_store.MAX_MANIFEST)
                              == marker, 'ARTIFACT_CHANGED')
            run_store.require(run_store._read(fd, 'journal.json', device, run_store.MAX_MANIFEST)
                              == journal_raw, 'ARTIFACT_CHANGED')
            journal = run_store._journal(run_store._unseal(journal_raw, run_store.MAX_MANIFEST), run_id)
            # Recheck frozen scope and all indexed bytes against the already
            # validated publication, without independently evaluating claims.
            run_store._read_publication(fd, device, published.manifest, run_id,
                                        frozen_scope=journal['scope'], verified=published)
            outputs = (('portal.css', css, _MAX_CSS), ('index.html', html, _MAX_HTML))
            absent = []
            for name, raw, limit in outputs:
                if run_store._exists(fd, name):
                    run_store.require(run_store._read(fd, name, device, limit) == raw,
                                      'PORTAL_OUTPUT_COLLISION')
                else:
                    absent.append((name, raw))
            # A preexisting index without CSS is inconsistent, not a supported
            # partial publication. CSS-only is the recoverable write order.
            run_store.require(not (len(absent) == 1 and absent[0][0] == 'portal.css'),
                              'PORTAL_OUTPUT_COLLISION')
            for name, raw in absent:
                run_store._write(fd, name, raw, device)
    return Path(report_root) / run_id / 'index.html'


def main(argv=None):
    parser = argparse.ArgumentParser(description='Render a private published Run dashboard offline')
    parser.add_argument('--report-root', required=True)
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args(argv)
    try:
        render_run(args.report_root, args.run_id)
    except run_store.StoreError as exc:
        print(exc.code, file=sys.stderr)
        return 1
    print('PORTAL_RENDERED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
