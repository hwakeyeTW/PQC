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
_HISTORY_GENERATION = "portal-v3"
_HISTORY_MARKER = b"<!-- PQC portal-v3 -->\n"
_CRYPTO_GENERATION = "portal-v4"
_CRYPTO_MARKER = b"<!-- PQC portal-v4 -->\n"
_CRYPTO_JSON = "crypto_indexes.json"
_MAX_CRYPTO_JSON = evidence.MAX_BYTES
_CRYPTO_PAGES = ("algorithms.html", "libraries.html")
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


def _v5_producer(published, portal_v5):
    run_store.require(type(portal_v5) is bool and type(published) is run_store.PublishedRun,
                      'INVALID_PUBLICATION')
    return portal_v5 and run_store._is_producer_v2(published.manifest)


def _artifact_parts(published, item, *, portal_v5, producer_v2):
    parts, cap = run_store._slot(item['kind'], item['host_id'], item['slot'], producer_v2=producer_v2)
    path = '/'.join(parts)
    run_store.require(path == item['path'] and path in published.artifacts, 'INVALID_ARTIFACT_LINK')
    if portal_v5:
        if item['kind'] == 'detail':
            run_store.require(item['host_id'] in published.manifest['expected_host_ids'],
                              'INVALID_ARTIFACT_LINK')
        run_store.require(type(published.artifacts[path]) is bytes and
                          len(published.artifacts[path]) == item['size'] <= cap,
                          'INVALID_ARTIFACT_LINK')
    return parts, cap


def _artifact_label(kind, producer_v2):
    return 'Producer rules' if producer_v2 and kind == 'producer-rules' else _LABELS[kind]


def _view(published, *, portal_v5=False):
    """Project only a validated PublishedRun; callers cannot supply raw JSON."""
    producer_v2 = _v5_producer(published, portal_v5)
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
        parts, _ = _artifact_parts(published, item, portal_v5=portal_v5, producer_v2=producer_v2)
        path = '/'.join(parts)
        label = _artifact_label(item['kind'], producer_v2)
        links.append({'path': path, 'label': label, 'size': item['size'],
                      'version': item['format_version']})
    gaps = Counter((c['collection_state'], c['reason_code']) for c in doc['collections']
                   if c['collection_state'] != 'COLLECTED')
    algorithm_counts = Counter((row['algorithm']['family'], row['algorithm']['primitive'])
                               for row in doc['evidence'] if row['algorithm'] is not None)
    claims = [] if assessed is None else assessed['claims']
    claim_counts = Counter((c['level'], c['assessment_state']) for c in claims)
    result = {'run': {k: m[k] for k in ('run_id', 'run_kind', 'publication_state', 'run_state',
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
    if portal_v5:
        result['producer_v2'] = producer_v2
        if producer_v2:
            result['run'].update(producer_rules_sha256=m['producer_rules_sha256'],
                                 producer_rules_version=m['producer_rules_version'])
    return result


def _render(published):
    try:
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES)), autoescape=True,
                          undefined=StrictUndefined, keep_trailing_newline=True)
        out = bytearray()
        for chunk in env.get_template('run_index.html.j2').generate(v=_view(published)):
            raw = chunk.encode('utf-8')
            run_store.require(len(raw) <= _MAX_HTML - len(out), 'PORTAL_SIZE_LIMIT')
            out.extend(raw)
        return bytes(out), _render_css()
    except (OSError, TemplateError, UnicodeError):
        raise run_store.StoreError('PORTAL_RENDER_ERROR') from None


def _render_css(*, limit=None):
    # CSS is common to all three versions, so v3 verification does not need
    # to render an unrelated legacy index (or apply its HTML limits).
    try:
        cap = _MAX_CSS if limit is None else min(_MAX_CSS, limit)
        run_store.require(cap > 0, 'PORTAL_SIZE_LIMIT')
        with (_TEMPLATES / 'portal.css').open('rb') as f:
            css = f.read(cap + 1)
        run_store.require(0 < len(css) <= cap, 'PORTAL_SIZE_LIMIT')
        css.decode('utf-8')
        return css
    except (OSError, UnicodeError):
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
_LEGACY_PACKAGE_FIELDS = frozenset(('rpm-release', 'rpm-architecture', 'rpm-epoch'))


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
        field = data['field']
        if (collection['collector_id'] == 'legacy-import' and
                row['source']['source_kind'] == 'LEGACY_IMPORT' and
                (field in _LEGACY_FIELDS or
                 (field in _LEGACY_PACKAGE_FIELDS and collection['scope_key'] == 'packages'))):
            facts.append(('value', data['value']))
        else:
            facts.append(('value', 'Not displayed (unclassified legacy field)'))
    if kind in ('AUTHORIZED_NEGOTIATION', 'OBSERVED_USAGE'):
        fields = ('protocol', 'endpoint_ref', 'context_ref', 'authorization_ref') if kind == 'AUTHORIZED_NEGOTIATION' else (
            'method', 'business_source_ref', 'started_at', 'finished_at')
        facts.extend((key, data['conditions'][key]) for key in fields)
    return facts


def _host_views(published, overview, *, portal_v5=False):
    producer_v2 = _v5_producer(published, portal_v5)
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
        parts, _ = _artifact_parts(published, item, portal_v5=portal_v5, producer_v2=producer_v2)
        path = '/'.join(parts)
        link = {'path': '../' + path, 'label': _artifact_label(item['kind'], producer_v2), 'slot': item['slot']}
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
    return _render_pages(published, marker, css, history=False)


def _render_v3(published, marker, css):
    return _render_pages(published, marker, css, history=True)


def _render_v4(published, marker, css):
    return _render_pages(published, marker, css, history=True, crypto=True)


def _crypto_backlinks(projection):
    # Invert only the reviewed A membership sets. No host/group cross-product
    # and no new algorithm/library relation. Unresolved claims link to their
    # explicit unresolved section, never to a guessed group.
    from tools import portal_indexes as indexes
    links = defaultdict(set)
    count = 0

    def add(ref, prefix, href):
        nonlocal count
        indexes._id(ref, prefix)
        count += 1
        run_store.require(count <= indexes._MAX_MEMBERSHIPS, 'CRYPTO_INDEX_SIZE_LIMIT')
        links[ref].add(href)

    for name, prefix in (('algorithms', 'alg-'), ('libraries', 'lib-')):
        data = projection[name]
        for group in data['groups']:
            gid = indexes._id(group['id'], prefix)
            href = name + '.html#' + gid
            run_store.require(group['backlink'] == href, 'INVALID_CRYPTO_INDEX_PUBLICATION')
            for field, ref_prefix in (('host_ids', 'h-'), ('asset_ids', 'a-'),
                                      ('evidence_ids', 'e-'), ('claim_ids', 'cl-')):
                for ref in group[field]:
                    add(ref, ref_prefix, href)
        for cid in data['unresolved_claim_ids']:
            claim = projection['claims'][cid]
            href = name + '.html#unresolved-claims'
            add(cid, 'cl-', href)
            add(claim['subject']['host_id'], 'h-', href)
            if claim['subject'].get('asset_id') is not None:
                add(claim['subject']['asset_id'], 'a-', href)
            for eid in claim['evidence_ids']:
                add(eid, 'e-', href)
    return {ref: sorted(hrefs) for ref, hrefs in links.items()}


def _render_pages(published, marker, css, *, history, crypto=False):
    """Bounded buffers for one fixed generation, before any writes."""
    try:
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES)), autoescape=True,
                          undefined=StrictUndefined, keep_trailing_newline=True)
        v = _view(published)
        hosts, views = _host_views(published, v)
        remaining = _MAX_TOTAL_HTML
        pages = {}
        backlinks = {}
        if crypto:
            from tools import portal_indexes as indexes
            projection, index_pages = indexes.render_crypto_indexes(published)
            run_store.require(set(index_pages) == set(_CRYPTO_PAGES),
                              'INVALID_CRYPTO_INDEX_PUBLICATION')
            # Serialize exactly the same A projection that rendered both pages.
            # A owns the bounded canonical JSON encoding (no second inference).
            raw = indexes._bounded_bytes(projection)
            run_store.require(len(raw) <= _MAX_CRYPTO_JSON, 'CRYPTO_INDEX_SIZE_LIMIT')
            pages[_CRYPTO_JSON] = raw
            for name in _CRYPTO_PAGES:
                raw = index_pages[name]
                run_store.require(len(raw) <= min(_MAX_HTML, remaining), 'PORTAL_SIZE_LIMIT')
                pages[name] = raw
                remaining -= len(raw)
            backlinks = _crypto_backlinks(projection)
        def page(template, *, prefix=b'', **context):
            nonlocal remaining
            limit = min(_MAX_HTML, remaining)
            run_store.require(len(prefix) <= limit, 'PORTAL_SIZE_LIMIT')
            out = bytearray(prefix)
            for chunk in env.get_template(template).generate(
                    v=v, portal_v2=True, portal_v3=history, portal_v4=crypto,
                    crypto_backlinks=backlinks, **context):
                raw = chunk.encode('utf-8')
                run_store.require(len(raw) <= limit - len(out), 'PORTAL_SIZE_LIMIT')
                out.extend(raw)
            remaining -= len(out)
            return bytes(out)
        index = page('run_index.html.j2', prefix=_CRYPTO_MARKER if crypto else
                     _HISTORY_MARKER if history else b'')
        pages['hosts.html'] = page('hosts.html.j2', nested=True, hosts=hosts)
        for host in views:
            pages[host['host_id'] + '.html'] = page('host.html.j2', nested=True, host=host)
        receipt = run_store._json_bytes({'format': 4 if crypto else 3 if history else 2, 'run_id': v['run']['run_id'],
            'manifest_sha256': _digest(marker), 'index_sha256': _digest(index), 'css_sha256': _digest(css),
            'pages': [{'name': name, 'size': len(raw), 'sha256': _digest(raw)}
                      for name, raw in sorted(pages.items())]}, _MAX_RECEIPT)
        return index, pages, receipt
    except (OSError, TemplateError, UnicodeError):
        raise run_store.StoreError('PORTAL_RENDER_ERROR') from None


def _v5_download_context(downloads, rid, ids, raw):
    # Only fixed relative names are admitted to the templates. The assembler
    # has already bound every row to the corresponding actual buffer.
    batch, pairs = downloads
    names = ('algorithms.csv', 'asset_indexes.json', 'certificates.csv', 'scan_summary.json', 'summary.csv')

    def check(rows, expected, owner):
        run_store.require(type(rows) is tuple and len(rows) == len(expected), 'PORTAL_PAYLOAD_INVALID')
        for row, name in zip(rows, expected):
            run_store.require(type(row) is dict and set(row) == {'name', 'size', 'sha256', 'run_id', 'host_id'}
                and row['name'] == name and row['run_id'] == rid and row['host_id'] == owner
                and type(row['size']) is int and row['size'] > 0 and type(row['sha256']) is str
                and re.fullmatch(r'[0-9a-f]{64}', row['sha256']) is not None, 'PORTAL_PAYLOAD_INVALID')

    check(batch, names, None)
    run_store.require(type(pairs) is dict and set(pairs) == set(ids), 'PORTAL_PAYLOAD_INVALID')
    for hid in ids:
        check(pairs[hid], (hid + '.cbom.json', hid + '.cbom.provenance.json'), hid)
    batch = tuple(sorted((*batch, dict(name=_CRYPTO_JSON, size=len(raw), sha256=_digest(raw),
        run_id=rid, host_id=None)), key=lambda row: row['name']))
    return batch, pairs


def _render_v5_core(published, projection, *, page_limit, html_limit, bundle_limit, json_limit, downloads=None):
    """Fixed private root/nested buffers, no receipt, marker, or publication.

    Only the trusted assembler supplies the existing verified projection and
    remaining byte budgets. No path, additional Store.open or reassessment.
    """
    from tools import portal_indexes as indexes
    try:
        v = _view(published, portal_v5=True)
        hosts, views = _host_views(published, v, portal_v5=True)
        run_store.require(projection['run_id'] == v['run']['run_id'] and
                          set(projection['hosts']) <= set(published.manifest['expected_host_ids']),
                          'INVALID_CRYPTO_INDEX_PUBLICATION')
        expected_hosts = {h['host_id']: h for h in hosts}
        for hid, row in projection['hosts'].items():
            h = expected_hosts[hid]
            run_store.require(row['host_id'] == hid and row['href'] == indexes._href(hid) and
                              row['target_id'] == h['target_id'] and row['host_state'] == h['host_state'],
                              'INVALID_CRYPTO_INDEX_PUBLICATION')
        raw = indexes._bounded_bytes(projection, limit=min(json_limit, _MAX_CRYPTO_JSON, bundle_limit))
        remaining = bundle_limit - len(raw)
        css = _render_css(limit=remaining)
        remaining -= len(css)
        html = min(html_limit, _MAX_TOTAL_HTML)
        page_cap = min(page_limit, _MAX_HTML)
        pages = {_CRYPTO_JSON: raw}
        navigation = downloads is not None
        if navigation:
            # The trusted assembler supplied fixed metadata for the actual
            # B1/B2 buffers. Add the sixth export from this exact JSON buffer.
            batch_downloads, host_downloads = _v5_download_context(
                downloads, v['run']['run_id'], published.manifest['expected_host_ids'], raw)
        else:
            batch_downloads, host_downloads = (), {}
        crypto_pages = indexes._render_crypto_projection(projection, page_limit=page_cap,
                                                       total_limit=min(html, remaining))
        run_store.require(set(crypto_pages) == set(_CRYPTO_PAGES), 'INVALID_CRYPTO_INDEX_PUBLICATION')
        for name in _CRYPTO_PAGES:
            raw = crypto_pages[name]
            run_store.require(len(raw) <= min(page_cap, html, remaining), 'PORTAL_SIZE_LIMIT')
            pages[name] = raw
            html -= len(raw)
            remaining -= len(raw)
        backlinks = _crypto_backlinks(projection)
        env = Environment(loader=FileSystemLoader(str(_TEMPLATES)), autoescape=True,
                          undefined=StrictUndefined, keep_trailing_newline=True)

        def page(template, **context):
            nonlocal html, remaining
            limit = min(page_cap, html, remaining)
            out = bytearray()
            for chunk in env.get_template(template).generate(
                    v=v, portal_v2=True, portal_v3=True, portal_v4=True, portal_v5=True,
                    crypto_backlinks=backlinks, private_navigation=navigation, **context):
                raw = chunk.encode('utf-8')
                run_store.require(len(raw) <= limit - len(out), 'PORTAL_SIZE_LIMIT')
                out.extend(raw)
            html -= len(out)
            remaining -= len(out)
            return bytes(out)

        index = page('run_index.html.j2', batch_downloads=batch_downloads, host_downloads=host_downloads)
        pages['hosts.html'] = page('hosts.html.j2', nested=True, hosts=hosts)
        for host in views:
            pages[host['host_id'] + '.html'] = page('host.html.j2', nested=True, host=host,
                batch_downloads=batch_downloads,
                host_downloads=host_downloads[host['host_id']] if navigation else ())
        return index, css, pages
    except (OSError, TemplateError, UnicodeError):
        raise run_store.StoreError('PORTAL_RENDER_ERROR') from None


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _file_signature(fd, name, device):
    s = run_store._check_file_stat(os.stat(name, dir_fd=fd, follow_symlinks=False), device)
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)


def _index_stat(fd, device):
    return _file_signature(fd, 'index.html', device)


def _replace_v1_index(fd, device, old, new, signature, *, recheck=None):
    """Replace only the proven old stable index, never an arbitrary file."""
    def check():
        if recheck is not None:
            recheck()
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


def _page_cap(name):
    if name == _RECEIPT:
        return _MAX_RECEIPT
    if name == _CRYPTO_JSON:
        return _MAX_CRYPTO_JSON
    return _MAX_HTML


def _generation(fd, device, pages, receipt, *, complete, signatures=None):
    expected = set(pages) | {_RECEIPT}
    present = set(run_store._entries(fd, len(expected)))
    run_store.require(present <= expected, 'PORTAL_GENERATION_COLLISION')
    if complete or _RECEIPT in present:
        run_store.require(present == expected, 'PORTAL_GENERATION_INCOMPLETE')
    for name in sorted(present):
        raw = receipt if name == _RECEIPT else pages[name]
        if signatures is not None:
            signature = _file_signature(fd, name, device)
            run_store.require(signature == signatures.setdefault(name, signature), 'ARTIFACT_CHANGED')
        run_store.require(run_store._read(fd, name, device, _page_cap(name)) == raw,
                          'PORTAL_OUTPUT_COLLISION')
        if signatures is not None:
            run_store.require(_file_signature(fd, name, device) == signature, 'ARTIFACT_CHANGED')
    return present


def _publish_portal(fd, device, old, index, css, pages, receipt, refresh, *,
                    generation=_GENERATION, recheck=None, previous=None):
    run_store.require(generation in (_GENERATION, _HISTORY_GENERATION, _CRYPTO_GENERATION),
                      'PORTAL_OUTPUT_COLLISION')
    strict = generation == _CRYPTO_GENERATION
    signatures = {} if strict else None
    # Preflight the entire fixed output set before creating anything. Receipt
    # bytes are compared with our deterministic expected value, not parsed as
    # an authority for opening paths.
    css_exists = run_store._exists(fd, 'portal.css')
    index_exists = run_store._exists(fd, 'index.html')
    css_signature = _file_signature(fd, 'portal.css', device) if strict and css_exists else None
    def check_css():
        run_store.require(run_store._read(fd, 'portal.css', device, _MAX_CSS) == css,
                          'PORTAL_OUTPUT_COLLISION')
        if strict:
            run_store.require(_file_signature(fd, 'portal.css', device) == css_signature,
                              'ARTIFACT_CHANGED')
    if css_exists:
        check_css()
    signature = None
    current = None
    if index_exists:
        run_store.require(css_exists, 'PORTAL_OUTPUT_COLLISION')
        signature = _index_stat(fd, device)
        current = run_store._read(fd, 'index.html', device, _MAX_HTML)
        run_store.require(_index_stat(fd, device) == signature, 'ARTIFACT_CHANGED')
        run_store.require(current == index or (refresh and current == old), 'PORTAL_OUTPUT_COLLISION')
    complete = current == index
    if previous is not None:
        previous()
    if recheck is not None:
        recheck()
    gen = None
    try:
        present = set()
        if run_store._exists(fd, generation):
            gen = run_store._open_dir(fd, generation, device)
            present = _generation(gen, device, pages, receipt, complete=complete, signatures=signatures)
        else:
            run_store.require(not complete, 'PORTAL_GENERATION_INCOMPLETE')
        if complete:
            # Re-confirm directory durability on retry, without rewriting files.
            run_store._sync(gen)
            run_store._sync(fd)
            run_store.require(_entry_identity(fd, generation) == _identity(gen) and
                              _current_index(fd, device) == (current, signature) and
                              run_store._read(fd, 'portal.css', device, _MAX_CSS) == css,
                              'ARTIFACT_CHANGED')
            if recheck is not None:
                recheck()
            if strict:
                check_css()
                _generation(gen, device, pages, receipt, complete=True, signatures=signatures)
                run_store.require(_entry_identity(fd, generation) == _identity(gen) and
                                  _current_index(fd, device) == (current, signature), 'ARTIFACT_CHANGED')
            return
        if not css_exists:
            run_store._write(fd, 'portal.css', css, device)
            if strict:
                css_signature = _file_signature(fd, 'portal.css', device)
        if gen is None:
            gen = run_store._mkdir(fd, generation, device)
        for name, content in sorted(pages.items()):
            if name not in present:
                run_store._write(gen, name, content, device)
        # Verify exact page bytes and closed set before sealing the receipt.
        present = _generation(gen, device, pages, receipt, complete=False, signatures=signatures)
        run_store.require(set(pages) <= present, 'PORTAL_GENERATION_INCOMPLETE')
        if _RECEIPT not in present:
            run_store._write(gen, _RECEIPT, receipt, device)
        _generation(gen, device, pages, receipt, complete=True, signatures=signatures)
        run_store._sync(gen)
        # Ensure the generation is still the directory pinned above.
        check = run_store._open_dir(fd, generation, device)
        try:
            run_store.require(_identity(check) == _identity(gen), 'ARTIFACT_CHANGED')
        finally:
            os.close(check)
        check_css()
        def before_index():
            if previous is not None:
                previous()
            if recheck is not None:
                recheck()
            check_css()
            # Recheck the sealed generation's identity at the stable switch.
            check = run_store._open_dir(fd, generation, device)
            try:
                run_store.require(_identity(check) == _identity(gen), 'ARTIFACT_CHANGED')
                if strict:
                    _generation(check, device, pages, receipt, complete=True, signatures=signatures)
                    run_store.require(_entry_identity(fd, generation) == _identity(check),
                                      'ARTIFACT_CHANGED')
            finally:
                os.close(check)
        if index_exists:
            _replace_v1_index(fd, device, old, index, signature, recheck=before_index)
        else:
            before_index()
            run_store._write(fd, 'index.html', index, device)
    finally:
        if gen is not None:
            os.close(gen)


def _identity(fd):
    s = os.fstat(fd)
    return s.st_dev, s.st_ino


def _current_index(fd, device):
    if not run_store._exists(fd, 'index.html'):
        return None
    signature = _index_stat(fd, device)
    raw = run_store._read(fd, 'index.html', device, _MAX_HTML)
    run_store.require(_index_stat(fd, device) == signature, 'ARTIFACT_CHANGED')
    return raw, signature


def _entry_identity(fd, name):
    st = os.stat(name, dir_fd=fd, follow_symlinks=False)
    return st.st_dev, st.st_ino


def _core_signatures(fd, device, published, *, portal_v5=False):
    if type(portal_v5) is not bool:
        raise run_store.StoreError('INVALID_PUBLICATION')
    if portal_v5:
        try:
            return _slot_signatures(fd, device, published, portal_v5=True)
        except OSError:
            raise run_store.StoreError('ARTIFACT_CHANGED') from None
    return _slot_signatures(fd, device, published)


def _slot_signatures(fd, device, published, *, portal_v5=False):
    # Only validated fixed Store slots. Include each detail directory identity
    # as well as its file metadata; no recursive walk or arbitrary path read.
    producer_v2 = _v5_producer(published, portal_v5)
    result = {name: _file_signature(fd, name, device)
              for name in ('run_manifest.json', 'journal.json')}
    if portal_v5:
        run_store.require(run_store._read(fd, 'run_manifest.json', device, run_store.MAX_MANIFEST)
                          == run_store._json_bytes(published.manifest), 'ARTIFACT_CHANGED')
    for row in published.manifest['artifacts']:
        if not portal_v5:
            parts, _ = run_store._slot(row['kind'], row['host_id'], row['slot'])
            with run_store._directory(fd, parts[:-1], device) as parent:
                result['/'.join(parts)] = (_identity(parent), _file_signature(parent, parts[-1], device))
            continue
        parts, cap = _artifact_parts(published, row, portal_v5=True, producer_v2=producer_v2)
        path = '/'.join(parts)
        # Capture every pinned directory in the closed slot, not just the
        # immediate parent. No traversal outside the validated slot grammar.
        chain = [_identity(fd)]
        current = os.dup(fd)
        try:
            for part in parts[:-1]:
                nxt = run_store._open_dir(current, part, device)
                os.close(current)
                current = nxt
                chain.append(_identity(current))
            sig = _file_signature(current, parts[-1], device)
            raw = run_store._read(current, parts[-1], device, cap, row['size'])
            run_store.require(raw == published.artifacts[path] and
                              _digest(raw) == row['sha256'] and
                              _file_signature(current, parts[-1], device) == sig, 'ARTIFACT_CHANGED')
            result[path] = (tuple(chain), sig)
        finally:
            os.close(current)
    if portal_v5:
        for name in ('run_manifest.json', 'journal.json'):
            run_store.require(_file_signature(fd, name, device) == result[name], 'ARTIFACT_CHANGED')
    return result


def _render_in_store(report_root, store, run_id, refresh, history, *, crypto=False,
                     catalog_check=None):
    """One run-only attempt, or a fresh attempt under a pinned catalog lock.

    False requests the catalog-first path. It is returned only before any
    publication work and after the run lock is released by the context.
    """
    device = store._device
    with store._locked_run(run_id, shared=True) as (fd, lock):
        current = _current_index(fd, device)
        existing_v3 = current is not None and current[0].startswith(_HISTORY_MARKER)
        existing_v4 = current is not None and current[0].startswith(_CRYPTO_MARKER)
        strict = crypto or existing_v4
        if not existing_v4 and (crypto or (history and not existing_v3)) and catalog_check is None:
            return False
        identity, lock_identity = _identity(fd), _identity(lock)
        run_store.require(run_store._exists(fd, 'run_manifest.json'), 'INCOMPLETE_RUN')
        marker = run_store._read(fd, 'run_manifest.json', device, run_store.MAX_MANIFEST)
        journal_raw = run_store._read(fd, 'journal.json', device, run_store.MAX_MANIFEST)
        if strict:
            # A nested shared Store.open is still the actual authority. The
            # outer pinned run and lock remain held during the identity capture.
            published = store.open(run_id)
            core_signatures = _core_signatures(fd, device, published)
            run_store.require(run_store._read(fd, 'run_manifest.json', device, run_store.MAX_MANIFEST) == marker and
                              run_store._read(fd, 'journal.json', device, run_store.MAX_MANIFEST) == journal_raw,
                              'ARTIFACT_CHANGED')
    if not strict:
        published = store.open(run_id)
    run_store.require(marker == run_store._json_bytes(published.manifest), 'ARTIFACT_CHANGED')
    old = None
    previous_generation = None
    if existing_v4:
        css = _render_css()
        index, pages, receipt = _render_v4(published, marker, css)
        run_store.require(current[0] == index, 'PORTAL_OUTPUT_COLLISION')
        generation = _CRYPTO_GENERATION
    elif crypto:
        generation = _CRYPTO_GENERATION
        css = _render_css()
        if current is not None:
            run_store.require(refresh, 'PORTAL_OUTPUT_COLLISION')
            if existing_v3:
                old, old_pages, old_receipt = _render_v3(published, marker, css)
                previous_generation = _HISTORY_GENERATION, old_pages, old_receipt
            else:
                old, css = _render(published)
                if current[0] != old:
                    old, old_pages, old_receipt = _render_v2(published, marker, css)
                    previous_generation = _GENERATION, old_pages, old_receipt
            run_store.require(current[0] == old, 'PORTAL_OUTPUT_COLLISION')
        index, pages, receipt = _render_v4(published, marker, css)
    elif existing_v3:
        # No downgrade, and no dependency on current root catalog state.
        css = _render_css()
        index, pages, receipt = _render_v3(published, marker, css)
        run_store.require(current[0] == index, 'PORTAL_OUTPUT_COLLISION')
        generation = _HISTORY_GENERATION
    elif history:
        generation = _HISTORY_GENERATION
        css = _render_css()
        if current is not None:
            run_store.require(refresh, 'PORTAL_OUTPUT_COLLISION')
            old, css = _render(published)
            if current[0] != old:
                old, old_pages, old_receipt = _render_v2(published, marker, css)
                run_store.require(current[0] == old, 'PORTAL_OUTPUT_COLLISION')
                previous_generation = _GENERATION, old_pages, old_receipt
        index, pages, receipt = _render_v3(published, marker, css)
    else:
        generation = _GENERATION
        old, css = _render(published)
        index, pages, receipt = _render_v2(published, marker, css)
    with store._locked_run(run_id, shared=False) as (fd, lock):
        def recheck():
            store._check()
            root = run_store._root(report_root)
            try:
                run_store.require(_identity(root) == _identity(store._fd), 'ARTIFACT_CHANGED')
            finally:
                os.close(root)
            run_store._check_dir(fd, device)
            run_store._stat_file(lock, device)
            run_store.require(_identity(fd) == identity == _entry_identity(store._fd, run_id) and
                              _identity(lock) == lock_identity == _entry_identity(fd, '.writer.lock'),
                              'ARTIFACT_CHANGED')
            if catalog_check is not None:
                catalog_check()
        def recheck_core():
            if strict:
                run_store.require(_core_signatures(fd, device, published) == core_signatures,
                                  'ARTIFACT_CHANGED')
            run_store.require(run_store._read(fd, 'run_manifest.json', device, run_store.MAX_MANIFEST)
                              == marker, 'ARTIFACT_CHANGED')
            run_store.require(run_store._read(fd, 'journal.json', device, run_store.MAX_MANIFEST)
                              == journal_raw, 'ARTIFACT_CHANGED')
            journal = run_store._journal(run_store._unseal(journal_raw, run_store.MAX_MANIFEST), run_id)
            # Actual frozen-scope and complete core-byte verification, with no
            # new assessment. For v4 also repeat at the stable switch.
            run_store._read_publication(fd, device, published.manifest, run_id,
                                        frozen_scope=journal['scope'], verified=published)
            if strict:
                run_store.require(_core_signatures(fd, device, published) == core_signatures,
                                  'ARTIFACT_CHANGED')
        recheck()
        run_store.require(_current_index(fd, device) == current, 'ARTIFACT_CHANGED')
        recheck_core()
        previous = None
        if previous_generation is not None:
            old_name, old_pages, old_receipt = previous_generation
            old_identity = None
            old_signatures = {} if strict else None
            def previous():
                nonlocal old_identity
                with run_store._directory(fd, (old_name,), device) as gen:
                    actual = _identity(gen)
                    run_store.require(old_identity is None or actual == old_identity,
                                      'ARTIFACT_CHANGED')
                    _generation(gen, device, old_pages, old_receipt, complete=True,
                                signatures=old_signatures)
                    run_store.require(_entry_identity(fd, old_name) == actual,
                                      'ARTIFACT_CHANGED')
                    old_identity = actual
        def checked():
            recheck()
            if strict:
                recheck_core()
        _publish_portal(fd, device, old, index, css, pages, receipt, refresh,
                        generation=generation, recheck=checked, previous=previous)
    return True


@run_store._public
def render_run(report_root, run_id, *, refresh_portal=False, with_history=False,
               with_crypto_indexes=False):
    """Default v2; opt-in v3/v4 require a coherent, shared-locked catalog.

    Exact current v4 is never downgraded and needs no catalog for no-op proof.
    Exact current v3 retains its no-op unless explicitly upgraded to v4.
    Only an authorized refresh can replace a proven old stable index.
    """
    run_store.require(type(refresh_portal) is bool, 'INVALID_REFRESH_FLAG')
    run_store.require(type(with_history) is bool, 'INVALID_HISTORY_FLAG')
    run_store.require(type(with_crypto_indexes) is bool, 'INVALID_CRYPTO_INDEXES_FLAG')
    with run_store.RunStore(report_root) as store:
        root_identity = _identity(store._fd)
        done = _render_in_store(report_root, store, run_id, refresh_portal, with_history,
                                crypto=with_crypto_indexes)
    if not done:
        # Lazy fixed import: Catalog also imports this renderer for exact proof.
        # All run locks from the probe have been released, before taking the
        # shared catalog lock. Use its pinned Store for the entire publication.
        from tools import run_catalog
        with run_catalog._history_root(report_root) as (store, check):
            run_store.require(_identity(store._fd) == root_identity, 'ARTIFACT_CHANGED')
            run_store.require(_render_in_store(report_root, store, run_id, refresh_portal,
                                               with_history, crypto=with_crypto_indexes, catalog_check=check),
                              'CATALOG_RECOVERY_REQUIRED')
    return Path(report_root) / run_id / 'index.html'


def main(argv=None):
    parser = argparse.ArgumentParser(description='Render a private published Run dashboard offline',
                                     allow_abbrev=False)
    parser.add_argument('--report-root', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--refresh-portal', action='store_true')
    parser.add_argument('--with-history', action='store_true')
    parser.add_argument('--with-crypto-indexes', action='store_true')
    args = parser.parse_args(argv)
    try:
        render_run(args.report_root, args.run_id, refresh_portal=args.refresh_portal,
                   with_history=args.with_history, with_crypto_indexes=args.with_crypto_indexes)
    except run_store.StoreError as exc:
        print(exc.code, file=sys.stderr)
        return 1
    print('PORTAL_RENDERED')
    return 0


if __name__ == '__main__':
    sys.exit(main())
