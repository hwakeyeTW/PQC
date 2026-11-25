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
