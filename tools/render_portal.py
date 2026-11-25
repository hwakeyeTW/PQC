"""Controller-only, versioned derived portal of an existing PublishedRun.

No inventory, managed dispatch, assessment engine, or untrusted template input.
The private Run Store remains the authority for publication and artifact links.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import os
import re
import secrets
from pathlib import Path
import sys

from jinja2 import Environment, FileSystemLoader, StrictUndefined, TemplateError

from tools import evidence, run_store

_TEMPLATES = Path(__file__).resolve().parents[1] / 'templates' / 'portal'
_MAX_HTML = 16 * 1024 * 1024
_MAX_CSS = 256 * 1024
_MAX_TOTAL_HTML = 128 * 1024 * 1024
_MAX_RECEIPT = 256 * 1024
_GENERATION = "portal-v2"
_RECEIPT = "portal_receipt.json"
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


# Host pages use a closed vocabulary and explicit typed data fields. Neither
# legacy text nor an opaque source reference determines a link or a verdict.
_SECTIONS = (('platform', 'OS / platform / packages / tools'),
             ('runtime', 'OpenSSL / runtime capability'),
             ('policy', 'Crypto policy / FIPS'), ('ssh', 'SSH'),
             ('certificates', 'Certificates / public keys'),
             ('tls', 'TLS service observations'), ('other', 'Other / unknown evidence'))
_COLLECTOR_SECTIONS = {'pqc-platform': 'platform', 'pqc-openssl-runtime': 'runtime',
                       'pqc-crypto-policy': 'policy', 'pqc-ssh-posture': 'ssh',
                       'pqc-cert-assets': 'certificates', 'packages': 'platform',
                       'openssl': 'runtime', 'crypto_policy': 'policy', 'sshd': 'ssh',
                       'ssh_host_keys': 'ssh', 'system_certs': 'certificates',
                       'nginx_certs': 'certificates', 'tls_services': 'tls'}
_LEGACY_SECTIONS = {'platform': 'platform', 'packages': 'platform',
                    'openssl-version': 'runtime', 'tls-groups': 'runtime',
                    'system-certificates': 'certificates', 'nginx-certificates': 'certificates',
                    'ssh-host-keys': 'ssh', 'tls-services': 'tls',
                    'crypto-policy': 'policy', 'sshd-config': 'ssh'}
_FIELDS = {
    'PLATFORM_INFO': ('os_family', 'os_version', 'distribution', 'major', 'minor', 'patch',
                      'architecture', 'platform_status'),
    'PACKAGE_INVENTORY': ('name', 'version', 'present', 'release', 'architecture'),
    'TOOL_AVAILABILITY': ('tool_id', 'lookup_scope', 'available'),
    'RUNTIME_CAPABILITY': ('capability', 'supported'),
    'EFFECTIVE_CONFIGURATION': ('setting', 'effective_value', 'allowed'),
    'AUTHORIZED_NEGOTIATION': ('outcome',), 'OBSERVED_USAGE': ('outcome',),
    'ASSET_METADATA': ('name', 'version'),
    'COLLECTION_SUMMARY': ('scope', 'attempted', 'coverage', 'observation_count', 'applicable'),
    'LEGACY_OBSERVATION': ('field',),
}
_LEGACY_FIELDS = frozenset(('original-collected-at', 'os-distribution', 'release', 'architecture',
    'openssl-version-result', 'tls-group-result', 'tls-group', 'public-key-algorithm',
    'public-key-type', 'signature-algorithm', 'public-key-bits', 'algorithm', 'nginx-present',
    'legacy-tls-port', 'tls-protocol', 'key-exchange', 'cipher', 'peer-signature',
    'server-signature', 'crypto-policy-result', 'sshd-crypto-lines-count',
    'sshd-crypto-lines-commented-count'))


def _collection_section(row):
    if row['collector_id'] == 'legacy-import' and row['source']['source_kind'] == 'LEGACY_IMPORT':
        return _LEGACY_SECTIONS.get(row['scope_key'], 'other')
    return _COLLECTOR_SECTIONS.get(row['collector_id'], 'other')


def _section(row, collection, asset):
    kind = row['evidence_kind']
    if kind in ('PLATFORM_INFO', 'PACKAGE_INVENTORY', 'TOOL_AVAILABILITY'):
        return 'platform'
    if kind == 'AUTHORIZED_NEGOTIATION':
        return {'SSH': 'ssh', 'TLS': 'tls'}[row['data']['conditions']['protocol']]
    section = _collection_section(collection)
    if kind == 'RUNTIME_CAPABILITY':
        return 'ssh' if section == 'ssh' else 'runtime'
    if asset and asset['asset_kind'] in ('certificate', 'public-key', 'public_key'):
        return 'ssh' if section == 'ssh' and asset['asset_kind'] != 'certificate' else 'certificates'
    return section


def _facts(row, collection):
    kind, data = row['evidence_kind'], row['data']
    facts = [(key, data.get(key)) for key in _FIELDS.get(kind, ())]
    if kind == 'LEGACY_OBSERVATION':
        # Only the reviewed legacy field vocabulary has a display value.
        if (collection['collector_id'] == 'legacy-import' and
                row['source']['source_kind'] == 'LEGACY_IMPORT' and data['field'] in _LEGACY_FIELDS):
            facts.append(('value', data['value']))
        else:
            facts.append(('value', 'Not displayed (unclassified legacy field)'))
    if kind in ('AUTHORIZED_NEGOTIATION', 'OBSERVED_USAGE'):
        fields = ('protocol', 'endpoint_ref', 'context_ref', 'authorization_ref') if kind == 'AUTHORIZED_NEGOTIATION' else (
            'method', 'business_source_ref', 'started_at', 'finished_at')
        facts.extend((key, data['conditions'][key]) for key in fields)
    return facts


def _host_views(published, overview):
    m, doc, assessed, artifacts = published
    ids = m['expected_host_ids']
    run_store.require(len(ids) <= 1000 and ids == sorted(set(ids)) and
                      all(re.fullmatch(r'h-[0-9a-f]{64}', hid) for hid in ids), 'PORTAL_HOST_IDS')
    by_host = {hid: {key: [] for key in ('collections', 'assets', 'evidence', 'claims', 'findings',
                                       'collectors', 'links', 'missing')} for hid in ids}
    for key in ('collections', 'assets', 'evidence'):
        for row in doc[key]:
            by_host[row['host_id']][key].append(row)
    if assessed is not None:
        for key in ('claims', 'findings'):
            for row in assessed[key]:
                by_host[row['subject']['host_id']][key].append(row)
    for row in overview['collectors']:
        by_host[row['host_id']]['collectors'].append(row)
    run_links, run_missing = [], []
    for item in m['artifacts']:
        parts, _ = run_store._slot(item['kind'], item['host_id'], item['slot'])
        path = '/'.join(parts)
        run_store.require(path == item['path'] and path in artifacts, 'INVALID_ARTIFACT_LINK')
        link = {'path': '../' + path, 'label': _LABELS[item['kind']], 'slot': item['slot']}
        (run_links if item['host_id'] is None else by_host[item['host_id']]['links']).append(link)
    for item in m['missing_artifacts']:
        parts = item['path'].split('/')
        if len(parts) == 3 and parts[0] == 'details' and parts[1] in by_host:
            by_host[parts[1]]['missing'].append(item)
        else:
            run_missing.append(item)
    hosts = sorted(overview['hosts'], key=lambda h: h['host_id'])
    run_store.require([h['host_id'] for h in hosts] == ids, 'PORTAL_HOST_IDS')
    views = []
    for i, h in enumerate(hosts):
        hid = h['host_id']; rows = by_host[hid]
        sections = {key: {'key': key, 'title': title, 'collections': [], 'assets': [], 'evidence': []}
                    for key, title in _SECTIONS}
        collections = {c['collection_id']: c for c in rows['collections']}
        assets = {a['asset_id']: a for a in rows['assets']}
        evidence_sections = {}
        for row in rows['evidence']:
            c = collections[row['collection_id']]
            section = _section(row, c, assets.get(row['asset_id']))
            evidence_sections[row['evidence_id']] = section
            sections[section]['evidence'].append({**row, 'facts': _facts(row, c)})
        for c in rows['collections']:
            groups = {evidence_sections[x] for x in c['evidence_ids']}
            section = next(iter(groups)) if len(groups) == 1 else _collection_section(c)
            sections[section]['collections'].append(c)
        for a in rows['assets']:
            groups = {evidence_sections[x] for x in a['evidence_ids']}
            section = next(iter(groups)) if len(groups) == 1 else (
                'certificates' if a['asset_kind'] in ('certificate', 'public-key', 'public_key') else 'other')
            sections[section]['assets'].append(a)
        # Present rows only; the validated model owns every identity/backref.
        # Do not manufacture empty facts, nor use opaque text as hrefs.
        views.append({**h, 'sections': list(sections.values()), 'collectors': rows['collectors'],
            'claims': rows['claims'], 'findings': rows['findings'], 'assessed': assessed is not None,
            'coverage': _counts((c['collection_state'] for c in rows['collections']), evidence.ACQUISITIONS),
            'previous': hosts[i-1] if i else None, 'next': hosts[i+1] if i+1 < len(hosts) else None,
            'links': rows['links'], 'missing': rows['missing'], 'run_links': run_links,
            'run_missing': run_missing, 'optional_missing': overview['optional_missing']})
    return hosts, views


def _render_v2(published, marker, css):
    """Bounded buffers for the entire fixed generation, before any writes."""
    try:
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES)), autoescape=True,
                          undefined=StrictUndefined, keep_trailing_newline=True)
        v = _view(published)
        hosts, views = _host_views(published, v)
        remaining = _MAX_TOTAL_HTML
        def page(template, **context):
            nonlocal remaining
            out = bytearray()
            limit = min(_MAX_HTML, remaining)
            for chunk in env.get_template(template).generate(v=v, portal_v2=True, **context):
                raw = chunk.encode('utf-8')
                run_store.require(len(raw) <= limit - len(out), 'PORTAL_SIZE_LIMIT')
                out.extend(raw)
            remaining -= len(out)
            return bytes(out)
        index = page('run_index.html.j2')
        pages = {'hosts.html': page('hosts.html.j2', nested=True, hosts=hosts)}
        for host in views:
            pages[host['host_id'] + '.html'] = page('host.html.j2', nested=True, host=host)
        receipt = run_store._json_bytes({'format': 2, 'run_id': v['run']['run_id'],
            'manifest_sha256': _digest(marker), 'index_sha256': _digest(index), 'css_sha256': _digest(css),
            'pages': [{'name': name, 'size': len(raw), 'sha256': _digest(raw)}
                      for name, raw in sorted(pages.items())]}, _MAX_RECEIPT)
        return index, pages, receipt
    except (OSError, TemplateError, UnicodeError):
        raise run_store.StoreError('PORTAL_RENDER_ERROR') from None


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _index_stat(fd, device):
    s = run_store._check_file_stat(os.stat('index.html', dir_fd=fd, follow_symlinks=False), device)
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _replace_v1_index(fd, device, old, new, signature):
    """Only the already-proven #19 stable derived index can be replaced."""
    def check():
        run_store.require(_index_stat(fd, device) == signature and
                          run_store._read(fd, 'index.html', device, _MAX_HTML) == old and
                          _index_stat(fd, device) == signature, 'PORTAL_OUTPUT_COLLISION')
    check()
    temp = '.portal-index-' + secrets.token_hex(16)
    out = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                  os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        try:
            os.fchmod(out, 0o600)  # Only the exclusively created inode.
            run_store._stat_file(out, device)
            view = memoryview(new)
            while view:
                count = os.write(out, view)
                run_store.require(count > 0, 'STORE_IO')
                view = view[count:]
            run_store._sync(out)
        finally:
            os.close(out)
        check()
        os.replace(temp, 'index.html', src_dir_fd=fd, dst_dir_fd=fd)
        run_store._sync(fd)  # failure is DURABILITY_UNCONFIRMED, never rollback
    finally:
        if run_store._exists(fd, temp):
            os.unlink(temp, dir_fd=fd)
            run_store._sync(fd)


def _generation(fd, device, pages, receipt, *, complete):
    expected = set(pages) | {_RECEIPT}
    present = set(run_store._entries(fd, len(expected)))
    run_store.require(present <= expected, 'PORTAL_GENERATION_COLLISION')
    if complete or _RECEIPT in present:
        run_store.require(present == expected, 'PORTAL_GENERATION_INCOMPLETE')
    for name in sorted(present):
        raw, cap = (receipt, _MAX_RECEIPT) if name == _RECEIPT else (pages[name], _MAX_HTML)
        run_store.require(run_store._read(fd, name, device, cap) == raw, 'PORTAL_OUTPUT_COLLISION')
    return present


def _publish_portal(fd, device, old, index, css, pages, receipt, refresh):
    # Preflight the entire fixed output set before creating anything. Receipt
    # bytes are compared with our deterministic expected value, not parsed as
    # an authority for opening paths.
    css_exists = run_store._exists(fd, 'portal.css')
    index_exists = run_store._exists(fd, 'index.html')
    if css_exists:
        run_store.require(run_store._read(fd, 'portal.css', device, _MAX_CSS) == css,
                          'PORTAL_OUTPUT_COLLISION')
    signature = None
    current = None
    if index_exists:
        run_store.require(css_exists, 'PORTAL_OUTPUT_COLLISION')
        signature = _index_stat(fd, device)
        current = run_store._read(fd, 'index.html', device, _MAX_HTML)
        run_store.require(_index_stat(fd, device) == signature, 'ARTIFACT_CHANGED')
        run_store.require(current == index or (refresh and current == old), 'PORTAL_OUTPUT_COLLISION')
    complete = current == index
    gen = None
    try:
        present = set()
        if run_store._exists(fd, _GENERATION):
            gen = run_store._open_dir(fd, _GENERATION, device)
            present = _generation(gen, device, pages, receipt, complete=complete)
        else:
            run_store.require(not complete, 'PORTAL_GENERATION_INCOMPLETE')
        if complete:
            # Re-confirm directory durability on retry, without rewriting files.
            run_store._sync(gen)
            run_store._sync(fd)
            return
        if not css_exists:
            run_store._write(fd, 'portal.css', css, device)
        if gen is None:
            gen = run_store._mkdir(fd, _GENERATION, device)
        for name, content in sorted(pages.items()):
            if name not in present:
                run_store._write(gen, name, content, device)
        # Verify exact page bytes and closed set before sealing the receipt.
        present = _generation(gen, device, pages, receipt, complete=False)
        run_store.require(set(pages) <= present, 'PORTAL_GENERATION_INCOMPLETE')
        if _RECEIPT not in present:
            run_store._write(gen, _RECEIPT, receipt, device)
        _generation(gen, device, pages, receipt, complete=True)
        run_store._sync(gen)
        # Ensure the generation is still the directory pinned above.
        check = run_store._open_dir(fd, _GENERATION, device)
        try:
            run_store.require(_identity(check) == _identity(gen), 'ARTIFACT_CHANGED')
        finally:
            os.close(check)
        run_store.require(run_store._read(fd, 'portal.css', device, _MAX_CSS) == css,
                          'PORTAL_OUTPUT_COLLISION')
        if index_exists:
            _replace_v1_index(fd, device, old, index, signature)
        else:
            run_store._write(fd, 'index.html', index, device)
    finally:
        if gen is not None:
            os.close(gen)


def _identity(fd):
    s = os.fstat(fd)
    return s.st_dev, s.st_ino


@run_store._public
def render_run(report_root, run_id, *, refresh_portal=False):
    """Render the fixed v2 generation in a private published run.

    Default no-replace; explicit refresh allows only an exact v1 index.
    Run Store remains a package-private peer.
    """
    run_store.require(type(refresh_portal) is bool, 'INVALID_REFRESH_FLAG')
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
        old, css = _render(published)
        index, pages, receipt = _render_v2(published, marker, css)
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
            _publish_portal(fd, device, old, index, css, pages, receipt, refresh_portal)
    return Path(report_root) / run_id / 'index.html'


def main(argv=None):
    parser = argparse.ArgumentParser(description='Render a private published Run dashboard offline',
                                     allow_abbrev=False)
    parser.add_argument('--report-root', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--refresh-portal', action='store_true')
    args = parser.parse_args(argv)
    try:
        render_run(args.report_root, args.run_id, refresh_portal=args.refresh_portal)
    except run_store.StoreError as exc:
        print(exc.code, file=sys.stderr)
        return 1
    print('PORTAL_RENDERED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
