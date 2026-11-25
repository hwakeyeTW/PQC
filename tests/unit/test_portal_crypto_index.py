"""Actual Store fixtures for the read-only #21 A projection and page contract."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit

import pytest

from test_portal_overview import (ROOT, RID, STAMP, END, LIMITS, RULES, Page, root,
                                  raw, options, publish, e, rs, assessment, portal)
from tools import portal_indexes as indexes

RULESET = assessment.load_rules(RULES)
MALICIOUS = '<img src=x onerror=alert(1)>'


def classified(name, context):
    return assessment.classify_algorithm(name, context, RULESET)


def producer_key(prefix, value):
    # Fixed #15 normalizer key contract, not the projection implementation.
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
    return prefix + '-' + hashlib.sha256(encoded.encode('ascii')).hexdigest()


def new_asset(doc, host, kind, literal):
    hid = host['host_id']
    aid = e.asset_id(hid, kind, literal, run_id=RID)
    doc['assets'].append(dict(asset_id=aid, host_id=hid, asset_kind=kind,
                              identity_scope='RUN_SCOPED', identity_key=literal, evidence_ids=[]))
    return doc['assets'][-1]


def add_scope(doc, host, collector, scope, records, state='COLLECTED'):
    """Construct typed records; Store and original validators own acceptance."""
    hid = host['host_id']
    source = dict(doc['run']['source'], producer_id=collector)
    cid = e.collection_id(RID, hid, collector, scope)
    refs = []
    for key, kind, data, alg, asset in records:
        eid = e.evidence_id(RID, hid, cid, key)
        refs.append(eid)
        doc['evidence'].append(dict(evidence_id=eid, host_id=hid, collection_id=cid,
            asset_id=None if asset is None else asset['asset_id'], observation_key=key,
            evidence_kind=kind, source=source, observed_at=STAMP, data=data, algorithm=alg))
        if asset is not None:
            asset['evidence_ids'].append(eid)
    reason = {'COLLECTED': 'COLLECTED', 'PARTIAL': 'INCOMPLETE_COLLECTION',
              'UNKNOWN': 'NO_EVIDENCE', 'ERROR': 'COMMAND_FAILED'}[state]
    doc['collections'].append(dict(collection_id=cid, host_id=hid, collector_id=collector,
        collector_version=source['producer_version'], scope_key=scope, collection_state=state,
        reason_code=reason, source=source, observed_at=STAMP, evidence_ids=refs))


def record(key, kind, data, alg=None, asset=None):
    return key, kind, data, alg, asset


def runtime(key, alg, supported, asset=None, capability=None):
    return record(key, 'RUNTIME_CAPABILITY', dict(capability=capability or key, supported=supported), alg, asset)


def package(key, name, version, present, asset=None, alg=None, **fields):
    return record(key, 'PACKAGE_INVENTORY', dict(name=name, version=version, present=present, **fields), alg, asset)


def metadata(key, name, version, asset=None):
    return record(key, 'ASSET_METADATA', dict(name=name, version=version), None, asset)


def populate(doc, host, second):
    hid = host['host_id']
    kem = classified('MLKEM768' if second else 'ML-KEM-768', 'KEM_CAPABILITY')
    ssh = classified('mlkem768x25519-sha256', 'SSH_KEX')
    sig = classified('ML-DSA-44', 'SIGNATURE')
    pubkey = classified('ML-DSA-44', 'CERT_PUBLIC_KEY')
    conflict = classified('ML-KEM-512', 'KEM_CAPABILITY')
    if second:
        conflict = dict(conflict, family='CLASSICAL', primitive='SIGNATURE')
    unknown = dict(algorithm_id=None, family='UNKNOWN', primitive='UNKNOWN', observed_name=MALICIOUS,
                   taxonomy_version=None)
    # Distinct host-scoped assets with the same literal identity key and name.
    lib = new_asset(doc, host, 'library', 'same-library-identity')
    pkg = new_asset(doc, host, 'package', 'same-package-identity')
    service = new_asset(doc, host, 'service', 'fixture-service')
    add_scope(doc, host, 'packages', 'package-inventory', [
        package('package-one', 'fixture-crypto-package', '3.5.0', True, pkg, release='1.fixture', architecture='x86_64'),
        package('package-repeat', 'fixture-crypto-package', '3.5.0', True, pkg, release='1.fixture', architecture='x86_64'),
        package('explicit-alg-package', 'fixture-kem-package', '1.0', True, alg=kem),
    ])
    # #15 persisted metadata/scopes, in the explicitly synthetic S1 short
    # collector seam (current Store rejects native #15 collector names).
    add_scope(doc, host, 'openssl', 'openssl-rpm-openssl', [
        package('rpm-one', 'openssl', '3.5.0', True, release='1.fixture', architecture='x86_64')])
    add_scope(doc, host, 'openssl', 'openssl-rpm-openssl-libs', [
        package('rpm-libs', 'openssl-libs', None if second else '3.5.0', not second)])
    add_scope(doc, host, 'openssl', 'openssl-version', [
        metadata('cli-version', 'openssl-cli', '3.5.0'),
        metadata('library-version', 'openssl-linked-library', None if second else '3.5.0')])
    provider = 'fixture-provider'
    pscope = producer_key('openssl-provider', provider)
    cap = producer_key('openssl-provider-loaded', provider)
    add_scope(doc, host, 'openssl', pscope, [metadata('metadata', provider, '3.5.0'),
        runtime(cap, None, None if second else True, capability=cap)])
    # Equal name/hash in a different scope is not a provider relationship.
    other = producer_key('openssl-kem', ['kem', provider, kem['algorithm_id']])
    add_scope(doc, host, 'openssl', 'openssl-kem', [
        runtime(other, kem, True, capability=other), runtime('kem-repeat', kem, True),
        runtime('conflicting-taxonomy', conflict, True),
        metadata('library-metadata', 'fixture-library', '3.5.0', lib),
        runtime('explicit-library', kem, True, lib),
        # These metadata spellings do not have the fixed #15 version/provider scope.
        metadata('cli-version', 'openssl-cli', '9.9.9'),
        metadata('metadata', provider, '9.9.9'),
        runtime(cap, kem, True, capability=cap)])
    add_scope(doc, host, 'openssl', 'signature-context', [runtime('sig', sig, True),
        runtime('public-key', pubkey, True), runtime('unknown-sig', unknown, None)])
    add_scope(doc, host, 'openssl', 'other-context', [runtime('unknown-kem', unknown, None)], 'UNKNOWN')
    add_scope(doc, host, 'openssl', 'legacy-unverified', [
        record('legacy-row', 'LEGACY_OBSERVATION', dict(field='tls-group', value='ML-KEM-768'), kem),
        metadata('context-metadata', 'fixture', '1.0')])
    # Explicit acquisition failure with a typed positive-looking value must
    # stay unknown, not a positive observation or PASS.
    if second:
        add_scope(doc, host, 'openssl', 'failed-runtime', [runtime('failed-capability', kem, True)], 'ERROR')
    neg = dict(host_id=hid, service_asset_id=service['asset_id'], endpoint_ref='fixture-endpoint',
               protocol='SSH', context_ref='fixture-context', authorization_ref='fixture-authorized')
    use = dict(host_id=hid, service_asset_id=service['asset_id'], business_source_ref='fixture-audit',
               method='SERVICE_AUDIT_RECORD', started_at=STAMP, finished_at=END)
    add_scope(doc, host, 'sshd', 'service-scope', [
        record('config', 'EFFECTIVE_CONFIGURATION', dict(setting='kex', effective_value='fixture', allowed=not second), ssh, service),
        record('negotiation', 'AUTHORIZED_NEGOTIATION', dict(conditions=neg, outcome='REJECTED' if second else 'NEGOTIATED'), ssh, service),
        record('usage', 'OBSERVED_USAGE', dict(conditions=use, outcome='CONTRADICTED' if second else 'OBSERVED'), ssh, service)])


def publish_crypto(root, assessed=True):
    # Actual S1 publication, not a mock or hand-made PublishedRun. The
    # production #15 normalizer is not yet wired into RunStore's collector API.
    args = options(('PARTIAL', 'PARTIAL'), negotiate=True)
    args['evidence_schema_version'] = '1.1.0'
    for flags in args['requested_flags'].values():
        flags['packages'] = True
    with rs.RunStore(root) as store, store.begin(**args) as writer:
        scope = writer.scope
        hosts = scope['hosts']
        for host in hosts:
            host.update(host_state='PARTIAL', reason_code='INCOMPLETE_COLLECTION')
        doc = rs._doc(scope, hosts, 'PARTIAL', finished_at=END, coverage_reason='INCOMPLETE_COLLECTION')
        for host in hosts:
            populate(doc, host, host['target_id'].startswith('fixture-1'))
        doc = json.loads(e.canonical_bytes(doc))
        terminals = []
        for host in doc['hosts']:
            hid = host['host_id']
            fragment = rs.host_fragment(doc, hid)
            terminal = dict(target_id=host['target_id'], host_state='PARTIAL', attempted=True,
                            reason_code='INCOMPLETE_COLLECTION', collectors=[])
            for collector, requested in sorted(scope['flags'][hid].items()):
                coll = [c for c in fragment['collections'] if c['collector_id'] == collector]
                state = 'NOT_SCANNED' if not requested else ('COLLECTED' if all(
                    c['collection_state'] == 'COLLECTED' for c in coll) else 'PARTIAL')
                terminal['collectors'].append(dict(collector_id=collector, requested=requested,
                    state=state, reason_code='DISABLED' if not requested else 'COLLECTED' if state == 'COLLECTED' else 'INCOMPLETE_COLLECTION',
                    rc=0 if requested else None, collection_ids=sorted(c['collection_id'] for c in coll)))
            writer.dispatch_intent(hid)
            writer.record_host(fragment, attempted=True, terminal=terminal)
            terminals.append(terminal)
        batch = raw(dict(batch_manifest_version=1, target_ids=sorted(h['target_id'] for h in hosts),
                         target_count=len(hosts), limits=LIMITS, profile='baseline', run_state='PARTIAL',
                         reason_code='INCOMPLETE_COLLECTION', hosts=sorted(terminals, key=lambda h: h['target_id'])))
        saved = assessment.evaluate_document(doc, RULESET) if assessed else None
        writer.finalize(doc, batch_raw=batch, batch_rc=5, assessed=saved, rules_raw=RULES if assessed else None)
    with rs.RunStore(root) as store:
        return store.open(RID)



@pytest.fixture
def published(root):
    return publish_crypto(root)


def project(published):
    return indexes.project_crypto_indexes(published)


def algorithm(p, aid):
    groups = [g for g in p['algorithms']['groups'] if g['algorithm_id'] == aid and g['classification'] == 'CANONICAL']
    assert len(groups) == 1
    return groups[0]


def libraries(p, kind, name=None):
    return [g for g in p['libraries']['groups'] if g['kind'] == kind and (name is None or g['name'] == name)]


def test_canonical_taxonomy_context_conflict_and_unique_counts(published):
    p = project(published)
    kem = algorithm(p, 'ml-kem-768')
    assert set(kem['observed_names']) == {'ML-KEM-768', 'MLKEM768'}
    assert kem['counts']['host_ids'] == 2 and kem['counts']['asset_ids'] == 2
    assert kem['family'] == 'PQC' and kem['primitive'] == 'KEM' and kem['taxonomy_version'] == '1.0.0'
    sig = algorithm(p, 'ml-dsa-44-signature'); pk = algorithm(p, 'ml-dsa-44-public-key')
    assert sig['id'] != pk['id'] and sig['observed_names'] == pk['observed_names'] == ['ML-DSA-44']
    assert sig['primitive'] == 'SIGNATURE' and pk['primitive'] == 'PUBLIC_KEY'
    conflicts = [g for g in p['algorithms']['groups'] if g['algorithm_id'] == 'ml-kem-512']
    assert len(conflicts) == 2 and {g['classification'] for g in conflicts} == {'CONFLICT'}
    assert {(g['primitive'], g['family']) for g in conflicts} == {('KEM', 'PQC'), ('SIGNATURE', 'CLASSICAL')}
    unknown = [g for g in p['algorithms']['groups'] if g['classification'] == 'UNKNOWN']
    assert len(unknown) == 4 and len({g['id'] for g in unknown}) == 4
    assert all(g['observed_names'] == [MALICIOUS] for g in unknown)
    assert len([g for g in p['algorithms']['groups'] if g['classification'] == 'LEGACY']) == 2
    assert all(g['classification'] == 'CANONICAL' for g in (kem, sig, pk))
    # Every indexed algorithm observation (including legacy/conflict) is
    # represented, but identical canonical IDs/contexts share one group.
    assert set(p['algorithms']['evidence_ids']) == {r['evidence_id'] for r in published.document['evidence']
                                                    if r['algorithm'] is not None}


def test_independent_levels_saved_claims_and_negative_observation(published):
    p = project(published)
    ssh = algorithm(p, 'ssh-mlkem768x25519-sha256')
    assert set(ssh['levels']) == set(e.LEVELS)
    for level, positive, negative in [('L3', 'ALLOWED', 'DISALLOWED'), ('L4', 'NEGOTIATED', 'REJECTED'),
                                       ('L5', 'OBSERVED', 'CONTRADICTED')]:
        data = ssh['levels'][level]
        assert data['observation_counts'] == {positive: 1, negative: 1}
        assert data['claim_counts'] == {'PASS': 1, 'FAIL': 1}
    assert ssh['levels']['L1']['claims'] == ssh['levels']['L2']['claims'] == {}
    kem = algorithm(p, 'ml-kem-768')
    assert kem['levels']['L1']['observation_counts'] == {'PRESENT': 2}
    failed = [r for r in p['evidence'].values() if r['scope_key'] == 'failed-runtime']
    assert len(failed) == 1 and failed[0]['facts']['supported'] is True
    assert failed[0]['collection_state'] == 'ERROR' and failed[0]['observation_state'] == 'UNKNOWN'
    assert failed[0]['evidence_id'] in kem['levels']['L2']['observations']['UNKNOWN']
    assert kem['levels']['L3']['observations'] == kem['levels']['L4']['observations'] == kem['levels']['L5']['observations'] == {}
    for cid, c in p['claims'].items():
        saved = next(x for x in published.assessed['claims'] if x['claim_id'] == cid)
        assert c['assessment_state'] == saved['assessment_state']
        assert c['evidence_ids'] == sorted(saved['evidence_ids'])
        assert c['conditions'] == saved['conditions']
        if c['assessment_state'] == 'PASS':
            assert any(e._supports_claim(saved, r, {x['collection_id']: x for x in published.document['collections']})
                       for r in published.document['evidence'] if r['evidence_id'] in saved['evidence_ids'])


def test_library_package_cli_provider_and_explicit_links(published):
    p = project(published)
    pkg = libraries(p, 'RPM_PACKAGE', 'fixture-crypto-package')
    assert len(pkg) == 1 and pkg[0]['counts'] == {'host_ids': 2, 'asset_ids': 2, 'evidence_ids': 4, 'claim_ids': 2}
    assert pkg[0]['presence'] == 'PRESENT' and pkg[0]['relations'] == []
    absent = libraries(p, 'RPM_PACKAGE', 'openssl-libs')
    assert len(absent) == 2 and {g['presence'] for g in absent} == {'PRESENT', 'ABSENT'}
    missing = next(g for g in absent if g['presence'] == 'ABSENT')
    assert missing['metadata_state'] == 'ABSENCE_RECORDED'
    assert missing['levels']['L1']['claim_counts'] == {'FAIL': 1}
    cli = libraries(p, 'OPENSSL_CLI'); linked = libraries(p, 'LINKED_LIBRARY_METADATA')
    providers = libraries(p, 'OPENSSL_PROVIDER'); explicit = libraries(p, 'LIBRARY_ASSET')
    assert len(cli) == 1 and cli[0]['version'] == '3.5.0' and cli[0]['counts']['host_ids'] == 2
    assert {g['version'] for g in linked} == {'3.5.0', None}
    assert {g['metadata_state'] for g in linked} == {'RECORDED_METADATA', 'MISSING_METADATA'}
    assert len(providers) == 1 and providers[0]['version'] == '3.5.0'
    assert providers[0]['levels']['L2']['observation_counts'] == {'SUPPORTED': 1, 'UNKNOWN': 1}
    assert all(not g['relations'] and g['presence'] == 'UNKNOWN' for g in cli + linked + providers)
    assert len(explicit) == 2 and all(g['counts']['asset_ids'] == 1 for g in explicit)
    assert all((g['name'], g['version']) == ('fixture-library', '3.5.0') for g in explicit)
    kem = algorithm(p, 'ml-kem-768')
    assert {r['group_id'] for r in kem['relations']} == {g['id'] for g in explicit + libraries(p, 'PACKAGE', 'fixture-kem-package')}
    assert len(p['relations']) == 3
    for rel in p['relations']:
        assert rel['algorithm_group_id'] == kem['id']
        assert all(p['evidence'][eid]['algorithm']['algorithm_id'] == 'ml-kem-768' for eid in rel['evidence_ids'])
    for g in p['libraries']['groups']:
        assert all(g['levels'][level]['observations'] == g['levels'][level]['claims'] == {} for level in ('L4', 'L5'))


def test_no_assessment_no_recompute_and_no_mutation(root, monkeypatch):
    pub = publish_crypto(root, assessed=False)
    before = deepcopy(pub)
    def forbidden(*args, **kwargs):
        raise AssertionError('projection must not classify or assess')
    monkeypatch.setattr(assessment, 'evaluate_document', forbidden)
    monkeypatch.setattr(assessment, 'classify_algorithm', forbidden)
    result, pages = indexes.render_crypto_indexes(pub)
    assert not result['assessed'] and not result['claims']
    assert all(not g['claim_ids'] for name in ('algorithms', 'libraries') for g in result[name]['groups'])
    assert all(b'Assessment not present. No verdict inferred.' in value for value in pages.values())
    assert pub == before
    # Result objects do not alias the saved algorithm, sources or subjects.
    first = next(r for r in result['evidence'].values() if r['algorithm'] is not None)
    first['algorithm']['family'] = 'changed'
    first['source']['producer_id'] = 'changed'
    assert pub == before


def test_exact_set_oracles_and_deterministic_json(published):
    p = project(published)
    assert p == project(published)
    encoded = json.dumps(p, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')
    assert indexes._bounded_bytes(p) == encoded and json.loads(encoded) == p
    all_refs = {k: set() for k in ('host_ids', 'asset_ids', 'evidence_ids', 'claim_ids')}
    for name in ('algorithms', 'libraries'):
        data = p[name]; totals = {k: set() for k in all_refs}
        for g in data['groups']:
            for key in totals:
                assert g[key] == sorted(set(g[key])) and g['counts'][key] == len(g[key])
                totals[key].update(g[key])
            for level, level_data in g['levels'].items():
                for key, registry in [('observations', 'evidence'), ('claims', 'claims')]:
                    assert level_data[key[:-1] + '_counts'] == {state: len(set(ids)) for state, ids in level_data[key].items()}
                    for state, ids in level_data[key].items():
                        assert set(ids) <= set(g['evidence_ids' if registry == 'evidence' else 'claim_ids'])
                        assert all(p[registry][i]['level'] == level for i in ids)
                        assert all(p[registry][i]['observation_state' if registry == 'evidence' else 'assessment_state'] == state for i in ids)
        for cid in data['unresolved_claim_ids']:
            c = p['claims'][cid]
            totals['claim_ids'].add(cid); totals['host_ids'].add(c['subject']['host_id'])
            if c['subject'].get('asset_id'):
                totals['asset_ids'].add(c['subject']['asset_id'])
            totals['evidence_ids'].update(c['evidence_ids'])
        for key in totals:
            assert data[key] == sorted(totals[key]) and data['counts'][key] == len(totals[key])
            all_refs[key].update(totals[key])
        assert data['counts']['groups'] == len(data['groups'])
    for key, registry in [('host_ids', 'hosts'), ('asset_ids', 'assets'), ('evidence_ids', 'evidence'), ('claim_ids', 'claims')]:
        assert all_refs[key] == set(p[registry])
    assert {gid for t in p['algorithms']['taxonomy'] for gid in t['group_ids']} == {g['id'] for g in p['algorithms']['groups']}
    assert all(t['count'] == len(t['group_ids']) for t in p['algorithms']['taxonomy'])
    assert all(p['assets'][aid]['host_id'] in p['hosts'] for aid in p['assets'])


def tree_state(root):
    return {str(path.relative_to(root)): (path.lstat().st_mode, path.lstat().st_ino, path.lstat().st_mtime_ns,
            path.read_bytes() if path.is_file() else None) for path in root.rglob('*')}


def test_page_escaping_actual_host_anchors_and_backlink_contract(root, published, tmp_path):
    # The actual unchanged renderer creates host pages. The A-slice only
    # renders memory buffers, then the test assembles a private preview tree
    # outside Report Root to verify the future same-generation targets.
    portal.render_run(root, RID)
    before = tree_state(root)
    p, pages = indexes.render_crypto_indexes(published)
    assert tree_state(root) == before
    assert set(pages) == {'algorithms.html', 'libraries.html'}
    for value in pages.values():
        assert MALICIOUS.encode() not in value
        assert b'<script' not in value and b'<img' not in value
    assert b'&lt;img src=x onerror=alert(1)&gt;' in pages['algorithms.html']
    preview = tmp_path / 'preview'; preview.mkdir()
    # Copy only known derived host pages for test parsing, never publish A.
    page_map = {}
    for hid in published.manifest['expected_host_ids']:
        path = root / RID / 'portal-v2' / (hid + '.html')
        page_map[path.name] = Page(path)
    for name, content in pages.items():
        path = preview / name; path.write_bytes(content); page_map[name] = Page(path)
    fixed = {'../portal.css', '../index.html', '../../index.html', 'hosts.html'}
    for name in ('algorithms', 'libraries'):
        page = page_map[name + '.html']
        for key, count in p[name]['counts'].items():
            assert int(page.text['count-' + key]) == count
        assert not any(tag in {'script', 'iframe', 'object', 'embed', 'base', 'form'} or
                       any(k.startswith('on') or k in ('src', 'srcset', 'action', 'style') for k in attrs)
                       for tag, attrs in page.tags)
        for href in page.links:
            u = urlsplit(href)
            assert not u.scheme and not u.netloc and not u.query and not u.path.startswith('/')
            assert '\\' not in href and '%' not in href
            if href in fixed:
                continue
            if u.path:
                assert u.path in page_map and (not u.fragment or u.fragment in page_map[u.path].ids)
            else:
                assert u.fragment in page.ids
        for g in p[name]['groups']:
            assert g['backlink'] == name + '.html#' + g['id'] and g['id'] in page.ids
            assert all(p['hosts'][hid]['href'] in page.links for hid in g['host_ids'])
            assert all(p['assets'][aid]['href'] in page.links for aid in g['asset_ids'])
            assert all(p['evidence'][eid]['href'] in page.links for eid in g['evidence_ids'])
            assert all(p['claims'][cid]['href'] in page.links for cid in g['claim_ids'])
    with rs.RunStore(root) as store:
        assert store.open(RID) == published
    assert tree_state(root) == before


def test_actual_i3_legacy_versions_distinct_and_no_guessed_usage(root):
    host = 'legacy-fixture.example.invalid'
    report = dict(host=host, collected_at=STAMP, openssl_version='OpenSSL 3.5.0', openssl_version_rc=0,
                  openssl_tls1_3_groups='X25519MLKEM768', openssl_tls1_3_groups_rc=0,
                  openssl_packages={'openssl-libs': [dict(name='openssl-libs', version='3.5.0', release='1.fixture', arch='x86_64', epoch=0),
                    dict(name='openssl-libs', version='3.5.0', release='2.fixture', arch='aarch64', epoch=1)]})
    old = dict(run_id='fixture-old', generated_at=STAMP, selected_hosts=[host], successful_hosts=[host],
               hosts_without_report=[], selected_count=1, completed_count=1, reports=[report])
    path = root.parent / 'legacy.json'; path.write_bytes(raw(old)); path.chmod(0o600)
    r = subprocess.run([sys.executable, '-B', '-m', 'tools.import_reports', '--input', str(path),
        '--format', 'legacy-ol-run-summary', '--run-id', RID, '--recorded-at', END,
        '--origin-ref', 'fixture-source', '--source-version', '0.9.1', '--report-root', str(root)],
        cwd=ROOT, capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr
    with rs.RunStore(root) as store:
        pub = store.open(RID)
    p = project(pub)
    groups = libraries(p, 'RPM_PACKAGE', 'openssl-libs')
    assert len(groups) == 2
    assert {(g['release'], g['architecture'], g['epoch']) for g in groups} == {('1.fixture', 'x86_64', 0), ('2.fixture', 'aarch64', 1)}
    assert all(g['counts']['asset_ids'] == 1 and g['counts']['evidence_ids'] == 4 for g in groups)
    assert len(libraries(p, 'LEGACY_RUNTIME_METADATA')) == 1
    assert all(g['classification'] == 'LEGACY' for g in p['algorithms']['groups'])
    assert p['relations'] == []


@pytest.mark.parametrize('value', [None, {}, 'evidence.json', Path('/tmp/invalid'), (None, None, None, None)])
def test_reject_non_publication(value):
    with pytest.raises(rs.StoreError, match='INVALID_CRYPTO_INDEX_PUBLICATION'):
        indexes.project_crypto_indexes(value)


@pytest.mark.parametrize('cap', ['_MAX_JSON', '_MAX_HTML', '_MAX_MEMBERSHIPS'])
def test_bounded_preview_rejects_without_writing(root, published, monkeypatch, cap):
    before = tree_state(root)
    monkeypatch.setattr(indexes, cap, 1)
    with pytest.raises(rs.StoreError, match='CRYPTO_INDEX_SIZE_LIMIT'):
        indexes.render_crypto_indexes(published)
    assert tree_state(root) == before


def test_empty_index_is_unknown(root):
    pub = publish(root, ('ERROR',))
    p, pages = indexes.render_crypto_indexes(pub)
    assert p['algorithms']['counts']['groups'] == p['libraries']['counts']['groups'] == 0
    assert not p['claims'] and not p['relations']
    assert all(b'No indexed records. This is not a negative verdict.' in value for value in pages.values())


def test_fixed_openssl_producer_scope_only(published):
    # The actual S1 fixture uses the synthetic short collector. Test the exact
    # reviewed #15 producer shape separately at the private scope predicate,
    # never claim a native #15 publication or pass raw rows to the public API.
    rows = published.document['evidence']
    coll = {c['collection_id']: c for c in published.document['collections']}
    version = next(r for r in rows if r['observation_key'] == 'cli-version' and
                   coll[r['collection_id']]['scope_key'] == 'openssl-version')
    source = dict(version['source'], producer_id='pqc-openssl-runtime', source_kind='NATIVE_COLLECTOR')
    c = dict(coll[version['collection_id']], collector_id='pqc-openssl-runtime', source=source)
    row = dict(version, source=source)
    assert indexes._metadata_kind(row, c) == 'OPENSSL_CLI'
    assert indexes._metadata_kind(row, dict(c, scope_key='openssl-kem')) is None
    assert indexes._metadata_kind(row, dict(c, collector_id='openssl', source=dict(source, producer_id='openssl'))) is None
    provider = next(r for r in rows if r['observation_key'] == 'metadata' and
                    coll[r['collection_id']]['scope_key'].startswith('openssl-provider-'))
    pc = dict(coll[provider['collection_id']], collector_id='pqc-openssl-runtime', source=source)
    assert indexes._metadata_kind(dict(provider, source=source), pc) == 'OPENSSL_PROVIDER'
    active = next(r for r in rows if r['collection_id'] == provider['collection_id'] and r['evidence_kind'] == 'RUNTIME_CAPABILITY')
    active = dict(active, source=source)
    assert indexes._provider_status(active, pc, provider['data']['name'])
    assert not indexes._provider_status(active, dict(pc, scope_key='openssl-kem'), provider['data']['name'])
    assert not indexes._provider_status(dict(active, algorithm=classified('ML-KEM-768', 'KEM_CAPABILITY')), pc, provider['data']['name'])


# B-slice: fixed N golden, captured with the unmodified renderer and real
# multi-host publish_crypto fixture before adding the v4 code.
N_PORTAL_GOLDEN = {'1': {'index.html': 'a9fa06ad0a902e06265e0d9b270d46ef43b9716da17c85574c75f9714f7b0823',
       'portal.css': 'f4d7737a3f86617d69542b477a2e4b3775ad113e75d34677a2dc01eb9e24089f',
       'run_manifest.json': '29ffcb3a7e42bc04398a74bc57bf696735c2e99a20d526c0df7ef0f2dccf8f93'},
 '2': {'index.html': '820fcafe82b88c16e29ec84d39e9f94b71b217fab402e3a83400caf43f6aa1e0',
       'portal-v2/h-6d2ff9a0eef70ae56bdc5a87219edc8e8fd64b0ab5daa25c7060278f2ff29ab5.html': 'f851e2588ac288779f08e43c67e5194b37b49ff7f4118b22531580b640d0429b',
       'portal-v2/h-d8e5f515397f29bc313a3fe0a24f704c474b33e1b2deca64e4e3586479957f7f.html': '1561eec2c5879163c0a3c688ef3cc708a98b0b814980586599658270ee80a823',
       'portal-v2/hosts.html': 'b8c8766db6a5c16c7ff3e5eb44e9a68d5218b2a4b9d96fc5d9e9b4d07e35bf5e',
       'portal-v2/portal_receipt.json': 'e582d61f8aaefdea37cdaeb94e651a5d8db3117239f0984721da4e36817bc1c7',
       'portal.css': 'f4d7737a3f86617d69542b477a2e4b3775ad113e75d34677a2dc01eb9e24089f',
       'run_manifest.json': '29ffcb3a7e42bc04398a74bc57bf696735c2e99a20d526c0df7ef0f2dccf8f93'},
 '3': {'index.html': '01de7f3558dfb4a306289f9fa0031ecc4cedea5bd879aacbf545ab12d73a3f5f',
       'portal-v3/h-6d2ff9a0eef70ae56bdc5a87219edc8e8fd64b0ab5daa25c7060278f2ff29ab5.html': '53a60f8ef45e0bcc4cfd44bffe4620d00c9cb75c8b7bc292b00fabcdfd431649',
       'portal-v3/h-d8e5f515397f29bc313a3fe0a24f704c474b33e1b2deca64e4e3586479957f7f.html': '9d62d3c15939c2c5d5f74f8be975acf5b5bb61658261d38ba68cc8ae46f96704',
       'portal-v3/hosts.html': '25a520f24075663e9363c52675c03b8272510c9d08a37d91fc6f8b7adb7cf578',
       'portal-v3/portal_receipt.json': '66e7a0bab73f6a2fc371f6d25c0154ec39b40f9af219754912f37bb56c6b1c9e',
       'portal.css': 'f4d7737a3f86617d69542b477a2e4b3775ad113e75d34677a2dc01eb9e24089f',
       'run_manifest.json': '29ffcb3a7e42bc04398a74bc57bf696735c2e99a20d526c0df7ef0f2dccf8f93'}}

# Publication tests reuse the actual Store fixtures and the original parsers.
import errno
import fcntl
import os
import shutil
import stat
import time
from collections import defaultdict
from contextlib import contextmanager
from itertools import product

import test_run_catalog as history_tests
from test_portal_navigation import NavigationPage
from tools import run_catalog as cat

V4 = 'portal-v4'
V4_JSON = 'crypto_indexes.json'
V4_RECEIPT = 'portal_receipt.json'


def assert_v4_publication(root, pub):
    rid = pub.manifest['run_id']; run = root / rid; gen = run / V4
    names = {'hosts.html', 'algorithms.html', 'libraries.html', V4_JSON,
             *(hid + '.html' for hid in pub.manifest['expected_host_ids'])}
    assert set(p.name for p in gen.iterdir()) == names | {V4_RECEIPT}
    assert stat.S_IMODE(gen.stat().st_mode) == 0o700
    index = run / 'index.html'; css = run / 'portal.css'
    assert index.read_bytes().startswith(b'<!-- PQC portal-v4 -->\n')
    def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
    assert json.loads((gen / V4_RECEIPT).read_bytes()) == {
        'format': 4, 'run_id': rid, 'manifest_sha256': digest(run / 'run_manifest.json'),
        'index_sha256': digest(index), 'css_sha256': digest(css),
        'pages': [{'name': n, 'size': (gen / n).stat().st_size, 'sha256': digest(gen / n)} for n in sorted(names)]}
    for path in [index, css, *gen.iterdir()]:
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
        assert info.st_uid == os.geteuid() and info.st_nlink == 1
    expected, original_pages = indexes.render_crypto_indexes(pub)
    data = (gen / V4_JSON).read_bytes()
    assert json.loads(data) == expected
    assert data == json.dumps(expected, ensure_ascii=True, sort_keys=True,
                              separators=(',', ':'), allow_nan=False).encode('ascii')
    assert all((gen / name).read_bytes() == content for name, content in original_pages.items())
    pages = {index: NavigationPage(index), **{gen / n: NavigationPage(gen / n) for n in names if n.endswith('.html')}}
    allowed = set(pages) | {root / 'index.html', css, gen / V4_JSON, *(run / p for p in pub.artifacts)}
    for path, page in pages.items():
        assert ('../index.html' if path == index else '../../index.html') in page.links
        assert not any(tag in {'script', 'iframe', 'object', 'embed', 'base', 'form'} or
                       any(k.startswith('on') or k in ('src', 'srcset', 'action', 'style') for k in attrs)
                       for tag, attrs in page.tags)
        for href in page.links:
            u = urlsplit(href)
            assert not u.scheme and not u.netloc and not u.query and not u.path.startswith('/')
            assert '\\' not in href and '%' not in u.path
            dest = (path.parent / u.path).resolve() if u.path else path
            assert dest in allowed and dest.is_file(), (path.name, href)
            if u.fragment:
                assert dest in pages and u.fragment in pages[dest].ids, (path.name, href)
    assert {V4 + '/' + name for name in names} <= set(pages[index].links)
    backwards = defaultdict(set)
    # Independent oracle: use actual emitted A group and reference sets,
    # not the new renderer's reverse map or its counts.
    for name in ('algorithms', 'libraries'):
        page = pages[gen / (name + '.html')]; data = expected[name]
        for key, count in data['counts'].items():
            assert int(page.text['count-' + key]) == count
        assert {ident for ident in page.ids if ident.startswith(('alg-', 'lib-'))} == {g['id'] for g in data['groups']}
        for group in data['groups']:
            href = group['backlink']
            for field, registry in (('host_ids', 'hosts'), ('asset_ids', 'assets'),
                                    ('evidence_ids', 'evidence'), ('claim_ids', 'claims')):
                for ref in group[field]:
                    assert expected[registry][ref]['href'] in page.references[group['id']]
                    backwards[ref].add(href)
            assert {x for x in page.references[group['id']] if x.startswith(('algorithms.html#', 'libraries.html#'))} == {
                r['href'] for r in group['relations']}
        for cid in data['unresolved_claim_ids']:
            claim = expected['claims'][cid]
            ref_ids = [cid, claim['subject']['host_id'], *claim['evidence_ids']]
            if claim['subject'].get('asset_id') is not None:
                ref_ids.append(claim['subject']['asset_id'])
            for ref in ref_ids:
                backwards[ref].add(name + '.html#unresolved-claims')
    for hid in pub.manifest['expected_host_ids']:
        page = pages[gen / (hid + '.html')]
        assert {'algorithms.html', 'libraries.html', V4_JSON, '../index.html#' + hid,
                'hosts.html#' + hid} <= set(page.links)
        all_anchors = [hid] + [r[e.REGISTRIES[k]] for k in ('assets', 'evidence')
                               for r in pub.document[k] if r['host_id'] == hid] + [
            r['claim_id'] for r in (pub.assessed or {}).get('claims', []) if r['subject']['host_id'] == hid]
        for ref in all_anchors:
            assert ref in page.ids
            actual = {x for x in page.references[ref] if x.startswith(('algorithms.html#', 'libraries.html#'))}
            assert actual == backwards[ref], ref
    with rs.RunStore(root) as store:
        assert store.open(rid) == pub
    return expected


def assert_old_unchanged(run, before):
    assert {k: v for k, v in history_tests.tree_bytes(run).items()
            if k != 'index.html' and not k.startswith(V4 + '/')} == {
        k: v for k, v in before.items() if k != 'index.html'}


@pytest.mark.parametrize('version', [1, 2, 3])
def test_v4_fixed_n_golden_and_explicit_upgrade(root, version):
    pub = publish_crypto(root); run = root / RID
    history_tests.v1(root, RID, pub)
    if version >= 2:
        portal.render_run(root, RID, refresh_portal=True)
    if version == 3:
        cat.build_catalog(root)
        portal.render_run(root, RID, refresh_portal=True, with_history=True)
    assert {name: hashlib.sha256((run / name).read_bytes()).hexdigest()
            for name in N_PORTAL_GOLDEN[str(version)]} == N_PORTAL_GOLDEN[str(version)]
    cat.build_catalog(root)
    old_catalog = history_tests.catalog_state(root)
    old_generation = cat.check_catalog(root)
    before = history_tests.tree_bytes(run)
    rc = history_tests.render_cli(root, RID, '--with-crypto-indexes')
    assert (rc.returncode, rc.stdout, rc.stderr) == (1, b'', b'PORTAL_OUTPUT_COLLISION\n')
    assert history_tests.tree_bytes(run) == before and not (run / V4).exists()
    flags = ['--with-crypto-indexes', '--refresh-portal']
    if version == 3:
        flags += ['--with-history']
    rc = history_tests.render_cli(root, RID, *flags)
    assert (rc.returncode, rc.stdout, rc.stderr) == (0, b'PORTAL_RENDERED\n', b'')
    assert (run / 'index.html').stat().st_ino != before['index.html'][1]
    assert_old_unchanged(run, before)
    assert history_tests.catalog_state(root) == old_catalog
    assert cat.check_catalog(root) == old_generation
    assert history_tests.data(root)['rows'][0]['portal_generation'] == f'portal-v{version}'
    assert_v4_publication(root, pub)
    cat.build_catalog(root)
    result = history_tests.assert_html_snapshot(root)
    assert result['rows'][0]['portal_generation'] == V4 and result['rows'][0]['href'] == RID + '/index.html'
    assert history_tests.tree_bytes(root / cat.GENERATIONS / old_generation) == {
        k.split('/', 1)[1]: v for k, v in old_catalog[2].items() if k.startswith(old_generation + '/')}


def test_v4_fresh_single_projection_and_unresolved_backlinks(root, monkeypatch):
    actual = populate
    def with_ambiguous_claim(doc, host, second):
        actual(doc, host, second)
        alg = classified('ML-KEM-512', 'KEM_CAPABILITY')
        # Same exact saved claim context, two conflicting stored taxonomies.
        # A must leave the resulting saved claim unresolved.
        add_scope(doc, host, 'openssl', 'fixture-ambiguous-claim', [
            runtime('one', alg, True, capability='same-fact'),
            runtime('two', dict(alg, primitive='SIGNATURE', family='CLASSICAL'), True, capability='same-fact')])
    monkeypatch.setattr(sys.modules[__name__], 'populate', with_ambiguous_claim)
    cat.build_catalog(root)  # a coherent empty snapshot, no current run row
    before_cat = history_tests.catalog_state(root)
    pub = publish_crypto(root); run = root / RID
    before = history_tests.tree_bytes(run); calls = []
    original = indexes.render_crypto_indexes
    def render(published):
        assert published == pub
        out = original(published); calls.append(out)
        return out
    with monkeypatch.context() as m:
        m.setattr(indexes, 'render_crypto_indexes', render)
        portal.render_run(root, RID, with_crypto_indexes=True, with_history=True)
    assert len(calls) == 1
    assert not (run / 'portal-v2').exists() and not (run / 'portal-v3').exists()
    assert json.loads((run / V4 / V4_JSON).read_bytes()) == calls[0][0]
    assert all((run / V4 / n).read_bytes() == b for n, b in calls[0][1].items())
    assert calls[0][0]['algorithms']['unresolved_claim_ids']
    assert history_tests.catalog_state(root) == before_cat
    assert all(history_tests.tree_bytes(run)[k] == v for k, v in before.items())
    assert_v4_publication(root, pub)


@pytest.mark.parametrize('fault', ['missing', 'one-slot', 'corrupt'])
def test_v4_catalog_precondition_eight_flag_noop(root, monkeypatch, fault):
    pub = history_tests.publish(root, monkeypatch, 'first'); run = root / 'first'
    original = history_tests.tree_bytes(run)
    assert history_tests.render_cli(root, 'first', '--with-crypto-indexes').returncode == 1
    assert not (root / cat.LOCK).exists() and history_tests.tree_bytes(run) == original
    cat.build_catalog(root)
    second = history_tests.publish(root, monkeypatch, 'new'); target = root / 'new'
    rc = history_tests.render_cli(root, 'new', '--with-crypto-indexes')
    assert (rc.returncode, rc.stdout, rc.stderr) == (0, b'PORTAL_RENDERED\n', b'')
    assert_v4_publication(root, second)
    if fault == 'missing':
        for name in (cat.HTML, cat.JSON, cat.LOCK): (root / name).unlink()
        shutil.rmtree(root / cat.GENERATIONS)
    elif fault == 'one-slot': (root / cat.HTML).unlink()
    else: history_tests.put(root / cat.JSON, b'foreign')
    before = tree_state(root)
    for refresh, history, crypto in product((False, True), repeat=3):
        assert portal.render_run(root, 'new', refresh_portal=refresh, with_history=history,
                                 with_crypto_indexes=crypto) == target / 'index.html'
        assert tree_state(root) == before
    assert history_tests.render_cli(root, 'first', '--with-crypto-indexes').returncode == 1
    assert tree_state(root) == before
    with pytest.raises(rs.StoreError, match='INVALID_CRYPTO_INDEXES_FLAG'):
        portal.render_run(root, 'first', with_crypto_indexes=1)
    assert history_tests.render_cli(root, 'first', '--with-crypto-index').returncode == 2
    portal.render_run(root, 'first')
    assert (run / 'portal-v2' / V4_RECEIPT).is_file() and not (run / V4).exists()


def test_v4_legacy_recovered_error_relative_relocation(root, monkeypatch):
    pubs = {'legacy': history_tests.legacy(root, 'legacy'),
            'recovered': history_tests.recover(root, monkeypatch, 'recovered'),
            'error': history_tests.publish(root, monkeypatch, 'error', ('ERROR',))}
    cat.build_catalog(root)
    before = {rid: history_tests.tree_bytes(root / rid) for rid in pubs}
    for rid in pubs:
        portal.render_run(root, rid, with_crypto_indexes=True)
    cat.build_catalog(root)
    for rid, pub in pubs.items():
        assert all(history_tests.tree_bytes(root / rid)[k] == v for k, v in before[rid].items())
        data = assert_v4_publication(root, pub)
        assert data['relations'] == []
    moved = root.parent / 'reports moved \u6e2c\u8a66'; root.rename(moved)
    for rid, pub in pubs.items():
        assert_v4_publication(moved, pub)
    assert all(r['portal_generation'] == V4 for r in history_tests.assert_html_snapshot(moved)['rows'])


@pytest.mark.parametrize('fault', ['json', 'receipt', 'missing', 'extra', 'symlink', 'hardlink', 'mode', 'marker'])
def test_v4_invalid_reference_mixed_valid_run(root, monkeypatch, fault):
    cat.build_catalog(root)
    pub = history_tests.publish(root, monkeypatch, 'bad')
    good = history_tests.publish(root, monkeypatch, 'good')
    portal.render_run(root, 'good', with_crypto_indexes=True)
    run = root / 'bad'; gen = run / V4
    portal.render_run(root, 'bad', with_crypto_indexes=True)
    path = gen / V4_JSON
    if fault == 'json': history_tests.put(path, b'{}')
    elif fault == 'receipt': history_tests.put(gen / V4_RECEIPT, b'{}')
    elif fault == 'missing': path.unlink()
    elif fault == 'extra': history_tests.put(gen / 'foreign.html', b'foreign')
    elif fault == 'symlink':
        path.unlink(); path.symlink_to(root / 'good' / V4 / V4_JSON)
    elif fault == 'hardlink':
        other = root.parent / 'external'; os.link(path, other)
    elif fault == 'mode': path.chmod(0o644)
    else: history_tests.put(run / 'index.html', portal._CRYPTO_MARKER)
    old_index = (run / 'index.html').read_bytes()
    for flags in ({}, {'with_crypto_indexes': True, 'refresh_portal': True}):
        with pytest.raises(rs.StoreError): portal.render_run(root, 'bad', **flags)
        assert (run / 'index.html').read_bytes() == old_index
    rc = history_tests.cli(root)
    assert rc.returncode == 0, rc.stderr
    rows = {r['run_id']: r for r in history_tests.assert_html_snapshot(root)['rows']}
    assert rows['good']['portal_status'] == 'AVAILABLE' and rows['good']['portal_generation'] == V4
    assert rows['bad']['publication_status'] == 'PUBLISHED' and rows['bad']['portal_status'] == 'INVALID'
    assert rows['bad']['href'] is None and rows['bad']['portal_generation'] is None
    assert_v4_publication(root, good)


def test_v4_unreferenced_generations_not_opened(root, monkeypatch):
    cat.build_catalog(root)
    for version in (1, 2, 3, 4):
        rid = f'v{version}'; pub = history_tests.publish(root, monkeypatch, rid); run = root / rid
        if version == 1: history_tests.v1(root, rid, pub)
        else: portal.render_run(root, rid, with_history=version == 3, with_crypto_indexes=version == 4)
        if version != 4:
            (run / V4).mkdir(mode=0o700)
            path = history_tests.put(run / V4 / V4_JSON, b'')
            history_tests.sparse(path, portal._MAX_CRYPTO_JSON + 1)
        else:
            for name in ('portal-v2', 'portal-v3'): (run / name).symlink_to(root.parent / 'missing')
    original = rs._open_dir
    def safe_open(fd, name, device, **kwargs):
        parent = Path(os.readlink(f'/proc/self/fd/{fd}')).name
        assert (parent, name) not in {('v1', V4), ('v2', V4), ('v3', V4), ('v4', 'portal-v2'), ('v4', 'portal-v3')}
        return original(fd, name, device, **kwargs)
    monkeypatch.setattr(rs, '_open_dir', safe_open)
    cat.build_catalog(root)
    assert {r['run_id']: r['portal_generation'] for r in history_tests.data(root)['rows']} == {f'v{n}': f'portal-v{n}' for n in (1,2,3,4)}
    for rid in ('v2', 'v3', 'v4'): portal.render_run(root, rid)


def test_v4_json_separate_cap_and_exact_admission(root, monkeypatch):
    pub = publish_crypto(root); run = root / RID
    cat.build_catalog(root); portal.render_run(root, RID, with_crypto_indexes=True)
    gen = run / V4
    html = [run / 'index.html', *gen.glob('*.html')]
    # Real fixture JSON exceeds every individual HTML page. Lower only the
    # test HTML cap; this must not cap JSON or add JSON to total HTML.
    max_page = max(p.stat().st_size for p in html)
    json_size = (gen / V4_JSON).stat().st_size
    assert json_size > max_page
    monkeypatch.setattr(portal, '_MAX_HTML', max_page)
    monkeypatch.setattr(portal, '_MAX_TOTAL_HTML', sum(p.stat().st_size for p in html))
    admitted = (sum(a['size'] for a in pub.manifest['artifacts']) +
                sum((run / n).stat().st_size for n in ('run_manifest.json', 'journal.json', 'portal.css', 'index.html')) +
                sum(p.stat().st_size for p in gen.iterdir()))
    monkeypatch.setattr(cat, 'MAX_ADMITTED', admitted)
    cat.build_catalog(root)
    assert history_tests.data(root)['rows'][0]['portal_generation'] == V4
    portal.render_run(root, RID)
    before = history_tests.catalog_state(root)
    monkeypatch.setattr(cat, 'MAX_ADMITTED', admitted - 1)
    with pytest.raises(cat.CapacityError, match='CATALOG_CAPACITY'): cat.build_catalog(root)
    assert history_tests.catalog_state(root) == before


@pytest.mark.parametrize('fault', ['json', 'html', 'total', 'generated-json', 'generated-page'])
def test_v4_capacity_refuses_whole_catalog(root, monkeypatch, fault):
    cat.build_catalog(root)
    history_tests.publish(root, monkeypatch, 'run'); run = root / 'run'; gen = run / V4
    portal.render_run(root, 'run', with_crypto_indexes=True); cat.build_catalog(root)
    old = history_tests.catalog_state(root); old_gen = cat.check_catalog(root)
    path = gen / (V4_JSON if fault == 'json' else 'algorithms.html')
    if fault == 'json': history_tests.sparse(path, portal._MAX_CRYPTO_JSON + 1)
    elif fault == 'html': history_tests.sparse(path, portal._MAX_HTML + 1)
    elif fault == 'total':
        monkeypatch.setattr(portal, '_MAX_TOTAL_HTML', (run / 'index.html').stat().st_size + sum(
            p.stat().st_size for p in gen.glob('*.html')) - 1)
    elif fault == 'generated-json': monkeypatch.setattr(indexes, '_MAX_JSON', 1)
    else: monkeypatch.setattr(indexes, '_MAX_HTML', 1)
    actual = rs._read
    def read(fd, name, device, limit, *args, **kwargs):
        if fault in ('json', 'html'):
            assert not (Path(os.readlink(f'/proc/self/fd/{fd}')).name == V4 and name == path.name)
        return actual(fd, name, device, limit, *args, **kwargs)
    def unrelated(*args, **kwargs): raise AssertionError('unreferenced renderer')
    monkeypatch.setattr(rs, '_read', read)
    for name in ('_render', '_render_v2', '_render_v3'): monkeypatch.setattr(portal, name, unrelated)
    for recover in (False, True):
        with pytest.raises(cat.CapacityError, match='CATALOG_CAPACITY'): cat.build_catalog(root, recover=recover)
        assert history_tests.catalog_state(root) == old
    assert cat.check_catalog(root) == old_gen


@pytest.mark.parametrize('kind', ['json', 'total', 'page', 'receipt'])
def test_v4_generated_cap_before_write(root, monkeypatch, kind):
    cat.build_catalog(root); history_tests.publish(root, monkeypatch, 'run')
    before = tree_state(root)
    owner, field = {'json': (portal, '_MAX_CRYPTO_JSON'), 'total': (portal, '_MAX_TOTAL_HTML'),
                    'page': (portal, '_MAX_HTML'), 'receipt': (portal, '_MAX_RECEIPT')}[kind]
    monkeypatch.setattr(owner, field, 1)
    with pytest.raises(rs.StoreError, match='SIZE_LIMIT'):
        portal.render_run(root, 'run', with_crypto_indexes=True)
    assert tree_state(root) == before


def test_v4_lock_order_shared_through_switch(root, monkeypatch):
    history_tests.publish(root, monkeypatch, 'run'); run = root / 'run'
    cat.build_catalog(root); portal.render_run(root, 'run', with_history=True)
    before = history_tests.catalog_state(root); seen = []
    real_context, real_render, real_replace = cat._history_root, portal._render_v4, os.replace
    def probe(path, held):
        fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            if held:
                with pytest.raises(BlockingIOError): fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally: os.close(fd)
    @contextmanager
    def context(report_root):
        probe(run / '.writer.lock', False); seen.append('run-released')
        with real_context(report_root) as value: yield value
    def render(*args):
        probe(root / cat.LOCK, True); seen.append('render-held')
        return real_render(*args)
    def replace(src, dst, **kwargs):
        if dst == 'index.html':
            probe(root / cat.LOCK, True); probe(run / '.writer.lock', True); seen.append('switch-held')
        return real_replace(src, dst, **kwargs)
    monkeypatch.setattr(cat, '_history_root', context); monkeypatch.setattr(portal, '_render_v4', render)
    monkeypatch.setattr(os, 'replace', replace)
    portal.render_run(root, 'run', refresh_portal=True, with_crypto_indexes=True)
    assert seen == ['run-released', 'render-held', 'switch-held']
    probe(root / cat.LOCK, False); probe(run / '.writer.lock', False)
    assert history_tests.catalog_state(root) == before


def test_v4_actual_lock_contention_and_independent_noop(root, monkeypatch):
    cat.build_catalog(root)
    for rid in ('old', 'new', 'default'): history_tests.publish(root, monkeypatch, rid)
    portal.render_run(root, 'old', with_crypto_indexes=True)
    before = history_tests.tree_bytes(root / 'new'); old = history_tests.tree_bytes(root / 'old')
    fd = os.open(root / cat.LOCK, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB); start = time.monotonic()
        p = history_tests.render_cli(root, 'new', '--with-crypto-indexes')
        assert (p.returncode, p.stdout, p.stderr) == (1, b'', b'RUN_BUSY\n')
        assert 4.5 <= time.monotonic() - start < 20
        portal.render_run(root, 'old', with_crypto_indexes=True, refresh_portal=True)
        portal.render_run(root, 'default')
        assert history_tests.tree_bytes(root / 'old') == old
    finally: os.close(fd)
    with rs.RunStore(root) as store, store._locked_run('new', shared=False):
        with pytest.raises(rs.StoreError, match='RUN_BUSY'):
            portal.render_run(root, 'new', with_crypto_indexes=True)
    assert history_tests.tree_bytes(root / 'new') == before


@pytest.mark.parametrize('fault', ['root', 'catalog-lock', 'stable-slot', 'run-lock', 'core'])
def test_v4_identity_drift_refuses_before_output(root, monkeypatch, fault):
    pub = history_tests.publish(root, monkeypatch, 'run'); run = root / 'run'
    cat.build_catalog(root); portal.render_run(root, 'run', with_history=True)
    before = history_tests.tree_bytes(run); actual = portal._render_v4
    moved = root.parent / 'old-root'
    def render(*args):
        out = actual(*args)
        if fault == 'root': root.rename(moved); root.mkdir(mode=0o700)
        else:
            path = {'catalog-lock': root / cat.LOCK, 'stable-slot': root / cat.JSON,
                    'run-lock': run / '.writer.lock', 'core': run / 'evidence.json'}[fault]
            raw_bytes = path.read_bytes(); path.rename(root.parent / 'old-inode'); history_tests.put(path, raw_bytes)
        return out
    monkeypatch.setattr(portal, '_render_v4', render)
    with pytest.raises(rs.StoreError):
        portal.render_run(root, 'run', refresh_portal=True, with_crypto_indexes=True)
    target = moved / 'run' if fault == 'root' else run
    assert not (target / V4).exists()
    assert (target / 'index.html').read_bytes() == before['index.html'][0]


@pytest.mark.parametrize('boundary', ['page', 'receipt', 'replace', 'durability', 'old-page', 'sealed-json', 'core'])
def test_v4_upgrade_faults_and_exact_resume(root, monkeypatch, boundary):
    pub = history_tests.publish(root, monkeypatch, 'run', ('COMPLETE', 'PARTIAL')); run = root / 'run'
    cat.build_catalog(root); portal.render_run(root, 'run', with_history=True)
    original = history_tests.tree_bytes(run); old_index = original['index.html'][0]
    old_catalog = history_tests.catalog_state(root); gen = run / V4
    real_write, real_replace, real_sync = rs._write, os.replace, rs._sync
    switched = False
    def write(fd, name, content, device, **kwargs):
        if boundary == 'page' and name == V4_JSON: raise rs.StoreError('FIXTURE_INTERRUPTION')
        if boundary == 'receipt' and name == V4_RECEIPT: raise rs.StoreError('FIXTURE_INTERRUPTION')
        result = real_write(fd, name, content, device, **kwargs)
        if name == V4_RECEIPT:
            if boundary == 'old-page':
                path = run / 'portal-v3' / 'hosts.html'; raw_bytes = path.read_bytes()
                path.rename(root.parent / 'old-page'); history_tests.put(path, raw_bytes)
            if boundary == 'sealed-json': history_tests.put(gen / V4_JSON, b'{}')
            if boundary == 'core':
                path = run / 'evidence.json'; raw_bytes = path.read_bytes()
                path.rename(root.parent / 'old-core'); history_tests.put(path, raw_bytes)
        assert (run / 'index.html').read_bytes() == old_index
        return result
    def replace(src, dst, **kwargs):
        nonlocal switched
        if dst == 'index.html':
            assert (gen / V4_RECEIPT).is_file() and (gen / V4_JSON).is_file()
            if boundary == 'replace': raise OSError(errno.EIO, 'fixture interruption')
            real_replace(src, dst, **kwargs); switched = True
        else: return real_replace(src, dst, **kwargs)
    def sync(fd):
        if boundary == 'durability' and switched: raise rs.StoreError('DURABILITY_UNCONFIRMED')
        return real_sync(fd)
    with monkeypatch.context() as m:
        m.setattr(rs, '_write', write); m.setattr(os, 'replace', replace); m.setattr(rs, '_sync', sync)
        with pytest.raises(rs.StoreError):
            portal.render_run(root, 'run', refresh_portal=True, with_crypto_indexes=True)
    assert switched == (boundary == 'durability')
    assert ((run / 'index.html').read_bytes() != old_index) == switched
    assert history_tests.catalog_state(root) == old_catalog and not list(run.glob('.portal-index-*'))
    staged = history_tests.tree_bytes(gen)
    if boundary == 'sealed-json':
        with pytest.raises(rs.StoreError): portal.render_run(root, 'run', refresh_portal=True, with_crypto_indexes=True)
        assert history_tests.tree_bytes(gen) == staged
    elif boundary in ('old-page', 'core'):
        # The interrupted invocation refused even a same-byte inode change.
        # The new invocation has its own independent exact preflight.
        assert not switched
    else:
        portal.render_run(root, 'run', refresh_portal=True, with_crypto_indexes=True)
        assert_v4_publication(root, pub)
        assert all(history_tests.tree_bytes(gen)[k] == v for k, v in staged.items())
        assert_old_unchanged(run, original)


def test_v4_incomplete_sealed_staging_refuses_upgrade(root, monkeypatch):
    history_tests.publish(root, monkeypatch, 'run'); run = root / 'run'
    cat.build_catalog(root); portal.render_run(root, 'run')
    original = os.replace
    def interrupt(src, dst, **kwargs):
        if dst == 'index.html': raise OSError(errno.EIO, 'fixture interruption')
        return original(src, dst, **kwargs)
    with monkeypatch.context() as m:
        m.setattr(os, 'replace', interrupt)
        with pytest.raises(rs.StoreError): portal.render_run(root, 'run', refresh_portal=True, with_crypto_indexes=True)
    gen = run / V4; assert (gen / V4_RECEIPT).exists()
    (gen / V4_JSON).unlink(); before = tree_state(root)
    with pytest.raises(rs.StoreError): portal.render_run(root, 'run', refresh_portal=True, with_crypto_indexes=True)
    assert tree_state(root) == before


def test_v4_fresh_index_last_interruption_resume(root, monkeypatch):
    cat.build_catalog(root); pub = history_tests.publish(root, monkeypatch, 'run')
    run = root / 'run'; gen = run / V4; original = history_tests.tree_bytes(run)
    cat_before = history_tests.catalog_state(root); actual = rs._write
    def write(fd, name, content, device, **kwargs):
        if name == 'index.html':
            assert (gen / V4_RECEIPT).is_file() and (gen / V4_JSON).is_file()
            assert not (run / 'index.html').exists()
            raise rs.StoreError('FIXTURE_INTERRUPTION')
        return actual(fd, name, content, device, **kwargs)
    with monkeypatch.context() as m:
        m.setattr(rs, '_write', write)
        with pytest.raises(rs.StoreError, match='FIXTURE_INTERRUPTION'):
            portal.render_run(root, 'run', with_crypto_indexes=True)
    staged = history_tests.tree_bytes(gen)
    assert not (run / 'index.html').exists() and history_tests.catalog_state(root) == cat_before
    portal.render_run(root, 'run', with_crypto_indexes=True)
    assert_v4_publication(root, pub)
    assert history_tests.tree_bytes(gen) == staged
    assert all(history_tests.tree_bytes(run)[k] == v for k, v in original.items())


@pytest.mark.parametrize('version', [2, 3])
def test_v4_refuses_corrupt_referenced_old_generation(root, monkeypatch, version):
    cat.build_catalog(root); history_tests.publish(root, monkeypatch, 'run'); run = root / 'run'
    portal.render_run(root, 'run', with_history=version == 3)
    history_tests.put(run / f'portal-v{version}' / V4_RECEIPT, b'{}')
    before = tree_state(root)
    with pytest.raises(rs.StoreError, match='PORTAL_OUTPUT_COLLISION'):
        portal.render_run(root, 'run', refresh_portal=True, with_crypto_indexes=True)
    assert tree_state(root) == before and not (run / V4).exists()
