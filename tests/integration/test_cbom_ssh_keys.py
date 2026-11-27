"""SK-A: actual private synthetic V3 Store replay, never an SSH transport."""
from copy import deepcopy
import builtins
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest
import test_c3a_capacity_profile as f
import test_run_store_v3_native as native
from tools import cbom_ssh_keys as sk, evidence, run_store as store, run_store_v3 as v3
from tools import scan_collectors as bridge, batch_execution as batch, ssh_posture as ssh


SLOT = v3.PRODUCER_SLOTS[bridge.SSH]
FP = '1' * 64
FP2 = '2' * 64
FP_UNKNOWN = '3' * 64


def key(n, fp=FP, kind='ssh-ed25519', bits=256, grammar='KNOWN'):
    return dict(source_ref='key-' + f'{n:064x}', key_type=kind, bits=bits,
                fingerprint_sha256=fp, grammar=grammar)


def key_flags(config=False):
    return {flag: flag == bridge.KEYS or (config and flag == bridge.SSHD) for flag in bridge.FLAGS}


def item(i=0, rows=None, *, partial=False, config=False, unavailable=False, policy=False):
    flags = key_flags(config)
    flags[bridge.POLICY_FLAG] = policy
    rows = [key(1)] if rows is None else sorted(rows, key=lambda r: r['source_ref'])
    keys = (f.sshacq.result('UNKNOWN', 'SOURCE_MISSING') if unavailable else
            f.sshacq.result('PARTIAL' if partial else 'COLLECTED', 'KEY_GAP' if partial else 'OK', rows=rows,
                           gaps=['KEY_TYPE_UNKNOWN'] if partial else []))
    config_slot = None
    if config:
        src = ssh.digest('src', ['ssh-config-v1', ['etc', 'ssh'], 'sshd_config'])
        config_slot = f.sshacq.result('COLLECTED', 'OK', rows=[
            dict(kind='SOURCE', order=0, source_ref=src, line=0, context_ref='global-default',
                 source_kind='MAIN', parent_ref=None, include_line=None, depth=0),
            dict(kind='KEY_REFERENCE', order=1, source_ref=src, line=1, context_ref='global-default',
                 key_source_ref=rows[0]['source_ref'])])
    snapshot = f._ssh_typed(flags, config=config_slot, keys=keys)
    snapshots = {bridge.PLATFORM: f._platform_snapshot(), bridge.SSH: snapshot}
    if policy:
        snapshots[bridge.POLICY] = f._policy_snapshot()
    return native.replay((i, snapshots, flags))


def hid(i):
    return i[2]['hosts'][0]['host_id']


def publish(root, items, monkeypatch):
    return native.actual(root, items, monkeypatch)


def detail(pub, host):
    return json.loads(pub.artifacts[f'details/{host}/{SLOT}.json'])


def key_record(pub, host):
    return next(r for r in detail(pub, host)['records'] if r['slot'] == 'keys')


def tree(root):
    return {str(p.relative_to(root)): (p.stat().st_mode, p.stat().st_mtime_ns, p.read_bytes() if p.is_file() else None)
            for p in sorted(root.rglob('*'))}


@pytest.fixture
def root(tmp_path):
    p = tmp_path / 'reports'
    p.mkdir(mode=0o700)
    return p


def test_sk_a_dedup_host_isolation_metadata_and_no_io(root, monkeypatch):
    rows = [key(2), key(1), key(3, FP2, 'ssh-rsa', 3072),
            key(4, FP_UNKNOWN, 'ssh-fixture-unknown', None, 'UNKNOWN_TYPE')]
    first, second = item(0, rows, partial=True, config=True), item(1, [key(1)])
    pub = publish(root, [second, first], monkeypatch)
    original, files = deepcopy(pub), tree(root)
    h1, h2 = hid(first), hid(second)
    kr = key_record(pub, h1)
    assert kr['state'] == 'PARTIAL' and len(kr['observations']) == 4
    assert any(o['config_evidence_ids'] for o in kr['observations'])

    def deny(*args, **kwargs):
        pytest.fail('projection attempted I/O or transport')

    with monkeypatch.context() as trap:
        for mod, name in [(builtins, 'open'), (os, 'open'), (Path, 'open'), (socket, 'socket'),
                          (subprocess, 'Popen'), (os, 'unlink'), (os, 'rename')]:
            trap.setattr(mod, name, deny)
        a = sk._project_verified_v3_keys(pub, h1)
        b = sk._project_verified_v3_keys(pub, h2)
        assert a == sk._project_verified_v3_keys(pub, h1)
    assert pub == original and tree(root) == files
    assert a.host_state == 'PARTIAL' and a.collection_state == 'PARTIAL' and not a.recovery
    assert len(a.keys) == 2 and len(b.keys) == 1
    assert [k.asset_id for k in a.keys] == sorted(k.asset_id for k in a.keys)
    by_fp = {k.fingerprint_sha256: k for k in a.keys}
    assert set(by_fp) == {FP, FP2}
    for fp, typ, bits, count in [(FP, 'ssh-ed25519', 256, 2), (FP2, 'ssh-rsa', 3072, 1)]:
        k = by_fp[fp]
        assert (k.run_id, k.host_id, k.key_type, k.bits, k.identity_basis) == (native.RID, h1, typ, bits, sk._BASIS)
        assert k.asset_id == evidence.asset_id(h1, 'public_key', 'sha256-' + fp, run_id=native.RID)
        assert k.collection_ids == (kr['collection_id'],)
        asset = next(x for x in pub.document['assets'] if x['asset_id'] == k.asset_id)
        assert k.evidence_ids == tuple(sorted(asset['evidence_ids']))
        assert len(k.evidence_ids) == count and set(k.evidence_ids) == {
            o['evidence_id'] for o in kr['observations'] if o['asset_id'] == k.asset_id}
        assert all(x not in k.evidence_ids for o in kr['observations'] for x in o['config_evidence_ids'])
    assert by_fp[FP].asset_id != b.keys[0].asset_id and b.keys[0].fingerprint_sha256 == FP
    assert set(by_fp[FP].evidence_ids).isdisjoint(b.keys[0].evidence_ids)
    unknown = next(o for o in kr['observations'] if o['row']['grammar'] == 'UNKNOWN_TYPE')
    assert a.omissions == (sk._Omission('KEY_COLLECTION_PARTIAL', collection_ids=(kr['collection_id'],)),
                           sk._Omission('UNKNOWN_KEY_TYPE', (unknown['evidence_id'],), (kr['collection_id'],)))
    wire = repr(a)
    assert FP_UNKNOWN not in wire and 'ssh-fixture-unknown' not in wire and 'fixture-' not in wire
    assert all(o['row']['source_ref'] not in wire for o in kr['observations'])
    assert 'config_evidence_ids' not in wire and 'source_ref' not in wire and 'private_key' not in wire


def test_sk_a_32_keys_and_empty(root, monkeypatch):
    first = item(0, [key(i, f'{i:064x}') for i in range(32)])
    empty = item(1, [])
    pub = publish(root, [first, empty], monkeypatch)
    a = sk._project_verified_v3_keys(pub, hid(first))
    b = sk._project_verified_v3_keys(pub, hid(empty))
    assert len(a.keys) == 32 and len({k.asset_id for k in a.keys}) == 32 and not a.omissions
    assert all(len(k.evidence_ids) == 1 for k in a.keys)
    assert not b.keys and b.omissions[0].reason == 'NO_KEYS_OBSERVED'
    assert v3.SLOTS[SLOT] == 2 * 1024 * 1024 and len(pub.manifest['artifacts']) <= 66


def test_sk_a_recovery_committed_unknown_never(root, monkeypatch):
    items = [item(i) for i in range(3)]
    with store.RunStore(root) as s:
        with native.start(s, items, monkeypatch) as w:
            for x in items[:2]:
                w.dispatch_intent(hid(x))
            monkeypatch.setattr(v3, '_clock', lambda: f.FIN)
            _, r, d, ds, _ = items[0]
            w.record_host(d, attempted=True, terminal=r, details=ds)
        cp = next((root / native.RID / 'checkpoints').glob('*.json'))
        old = cp.read_bytes()
        monkeypatch.setattr(v3, '_clock', lambda: native.RECOVER)
        recovered = s._recover_v3(native.RID)
        pub = s._open_v3(native.RID)
        assert recovered == pub and cp.read_bytes() == old and pub.assessed is None
    a, b, c = [sk._project_verified_v3_keys(pub, hid(x)) for x in items]
    assert a.recovery and a.attempt_status == 'ATTEMPTED' and len(a.keys) == 1
    assert a.keys[0].fingerprint_sha256 == FP and a.keys[0].asset_id == items[0][2]['assets'][-1]['asset_id']
    assert b.recovery and b.attempt_status == 'UNKNOWN' and not b.keys and b.omissions[0].reason == 'OUTCOME_UNKNOWN'
    assert c.recovery and c.attempt_status == 'NOT_ATTEMPTED' and not c.keys and c.omissions[0].reason == 'NOT_ATTEMPTED'


def _blank_keys(i, mode):
    flags = key_flags()
    target = 'fixture-%02d.example.invalid' % i
    if mode == 'connection':
        row = batch._host(target, True, [batch._outcome(x, True, 'UNREACHABLE', 'CONNECTION_FAILED')
                         if flags[x] else batch._outcome(x, False, 'NOT_SCANNED', 'DISABLED')
                         for x in batch._COLLECTORS], 'CONNECTION_FAILED')
        row['platform'] = batch._outcome(bridge.PLATFORM, True, 'UNREACHABLE', 'CONNECTION_FAILED')
    else:
        row = batch._blank(target, flags, 'CONTROLLER_WORKER_FAILED', True)
        row['platform'] = batch._outcome(bridge.PLATFORM, True, 'ERROR', 'OUTCOME_UNKNOWN')
    return flags, row, native.fragment(row), {}, None


def test_sk_a_disabled_no_handoff_unavailable_and_cleanup(root, monkeypatch):
    good = item(0)
    flags, row, doc, details, p = deepcopy(good)
    row.update(host_state='ERROR', reason_code='CONTROLLER_CLEANUP_UNCONFIRMED')
    downgraded = (flags, row, native.fragment(row, p.document), details, p)
    items = [downgraded, native.blank(1, 'disabled'), _blank_keys(2, 'connection'),
             _blank_keys(3, 'worker'), item(4, unavailable=True), item(5, unavailable=True, policy=True)]
    pub = publish(root, items, monkeypatch)
    results = [sk._project_verified_v3_keys(pub, hid(x)) for x in items]
    assert all(not r.keys for r in results)
    assert results[0].host_state == 'ERROR' and results[0].collection_state == 'COLLECTED'
    assert results[0].omissions[0].reason == 'HOST_NOT_USABLE' and results[0].omissions[0].asset_ids
    assert results[1].omissions[0].reason == 'KEYS_DISABLED'
    assert all(r.omissions[0].reason == 'HOST_NOT_USABLE' for r in results[2:5])
    assert all(r.omissions[1].reason == 'PROOF_NOT_RETAINED' for r in results[2:4])
    assert results[-1].host_state == 'PARTIAL' and results[-1].collection_state == 'UNKNOWN'
    assert results[-1].omissions[0].reason == 'KEY_COLLECTION_UNAVAILABLE'


def _set_artifact(pub, path, raw):
    pub.artifacts[path] = raw
    entry = next(e for e in pub.manifest['artifacts'] if e['path'] == path)
    entry.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    return entry


@pytest.mark.parametrize('defect', ['version', 'contract', 'capacity', 'foreign-source', 'foreign-host',
                                    'entry-version', 'entry-path', 'hash', 'noncanonical', 'membership',
                                    'handoff-source', 'observed-time', 'coherent-detail', 'raw-backref',
                                    'foreign-companion', 'oversize', 'missing-entry', 'foreign-raw', 'handoff-outcome',
                                    'extra-missing', 'host-limit', 'entry-limit'])
def test_sk_a_reject_inconsistent_actual_snapshot(root, monkeypatch, defect):
    a, b = item(0), item(1)
    pub = deepcopy(publish(root, [a, b], monkeypatch))
    h, other = hid(a), hid(b)
    path = f'details/{h}/{SLOT}.json'
    handoff = f'details/{h}/{v3.HANDOFF}.json'
    entry = next(e for e in pub.manifest['artifacts'] if e['path'] == path)
    if defect == 'version': pub.manifest['manifest_version'] = '1.0.0'
    elif defect == 'contract': pub.manifest['batch_contract'] = 'B04_PRODUCER_V2'
    elif defect == 'capacity': pub.manifest['capacity_profile'] = 'OTHER'
    elif defect == 'foreign-source': pub.manifest['source']['origin_ref'] = 'fixture-other'
    elif defect == 'foreign-host': h = 'h-' + '0' * 64
    elif defect == 'entry-version': entry['format_version'] = '1.1.0'
    elif defect == 'entry-path': entry['path'] = 'details/foreign/ssh-posture.json'
    elif defect == 'hash': entry['sha256'] = '0' * 64
    elif defect == 'noncanonical': _set_artifact(pub, path, pub.artifacts[path] + b' ')
    elif defect == 'membership': entry['evidence_ids'] = []
    elif defect in ('handoff-source', 'handoff-outcome'):
        wire = json.loads(pub.artifacts[handoff])
        if defect == 'handoff-source': wire['target_id'] = 'foreign.example.invalid'
        else: next(r for r in wire['records'] if r['producer_id'] == bridge.SSH)['reason_code'] = 'COMMAND_FAILED'
        _set_artifact(pub, handoff, bridge.wire_bytes(wire))
    elif defect in ('observed-time', 'coherent-detail'):
        value = detail(pub, h)
        if defect == 'observed-time': value['observed_at'] = '2026-01-01T00:00:01Z'
        else: next(r for r in value['records'] if r['slot'] == 'keys')['observations'][0]['row']['bits'] = 384
        value.pop('detail_sha256'); value['detail_sha256'] = hashlib.sha256(ssh.canonical(value)).hexdigest()
        _set_artifact(pub, path, ssh.canonical(value))
    elif defect == 'raw-backref':
        asset = next(r for r in pub.document['assets'] if r['host_id'] == h and r['asset_kind'] == 'public_key')
        asset['evidence_ids'] = []
    elif defect == 'foreign-companion': _set_artifact(pub, path, pub.artifacts[f'details/{other}/{SLOT}.json'])
    elif defect == 'oversize': _set_artifact(pub, path, b'x' * (v3.SLOTS[SLOT] + 1))
    elif defect == 'missing-entry': pub.manifest['artifacts'].remove(entry)
    elif defect == 'extra-missing': pub.manifest['missing_artifacts'].append(dict(path='unknown', reason_code='REQUIRED_DETAIL_MISSING'))
    elif defect == 'host-limit': pub.manifest['hosts'] *= 6
    elif defect == 'entry-limit': pub.manifest['artifacts'] *= 7
    elif defect == 'foreign-raw':
        e = next(r for r in pub.document['evidence'] if r['host_id'] == h and r['asset_id'] is not None
                 and r['source']['producer_id'] == bridge.SSH)
        e['source']['origin_ref'] = 'fixture-other'
    with pytest.raises(sk._ProjectionError) as err:
        sk._project_verified_v3_keys(pub, h)
    assert str(err.value) in ('UNVERIFIED_V3_SNAPSHOT', 'UNKNOWN_EXPECTED_HOST', 'INVALID_V3_KEY_PROOF')


@pytest.mark.parametrize('defect', ['fingerprint-type', 'fingerprint-bits', 'bad-grammar', '33-keys', 'slot-limit'])
def test_sk_a_actual_store_rejects_bad_typed_checkpoint(root, monkeypatch, defect):
    good = item(0)
    _, r, d, ds, _ = deepcopy(good)
    with store.RunStore(root) as s:
        with native.start(s, [good], monkeypatch) as w:
            w.dispatch_intent(hid(good)); monkeypatch.setattr(v3, '_clock', lambda: f.FIN)
            if defect == 'slot-limit':
                ds[SLOT] = b'x' * (v3.SLOTS[SLOT] + 1)
            else:
                env = bridge.read_wire(ds[v3.HANDOFF]); rows = next(x for x in env['records']
                    if x['producer_id'] == bridge.SSH)['snapshot']['slots']['keys']['rows']
                if defect == 'fingerprint-type': rows.append(key(2, FP, 'ssh-rsa', 2048))
                elif defect == 'fingerprint-bits':
                    rows[0].update(key_type='ssh-rsa', bits=2048); rows.append(key(2, FP, 'ssh-rsa', 3072))
                elif defect == 'bad-grammar': rows[0]['grammar'] = 'UNKNOWN_TYPE'
                elif defect == '33-keys': rows[:] = [key(i, f'{i:064x}') for i in range(33)]
                ds[v3.HANDOFF] = bridge.wire_bytes(env)
            with pytest.raises(store.StoreError):
                w.record_host(d, attempted=True, terminal=r, details=ds)
            assert not list((root / native.RID / 'checkpoints').glob('*.json'))
            assert not (root / native.RID / 'run_manifest.json').exists()


def test_sk_a_actual_tamper_rejected_before_projection(root, monkeypatch):
    a = item()
    pub = publish(root, [a], monkeypatch)
    path = f'details/{hid(a)}/{SLOT}.json'
    assert sk._project_verified_v3_keys(pub, hid(a)).keys
    raw = pub.artifacts[path]
    (root / native.RID / path).write_bytes(raw + b' ')
    with store.RunStore(root) as s, pytest.raises(store.StoreError):
        # The reader must reject; there is no fallback to a raw caller dict.
        sk._project_verified_v3_keys(s._open_v3(native.RID), hid(a))


def test_sk_a_actual_old_store_not_admitted(root, monkeypatch):
    import test_run_store_v2_certificate as c1
    pub = c1._c2_open(root, ('complete',), assessed=True)
    with pytest.raises(sk._ProjectionError, match='^UNVERIFIED_V3_SNAPSHOT$'):
        sk._project_verified_v3_keys(pub, pub.manifest['expected_host_ids'][0])
    with pytest.raises(sk._ProjectionError, match='^UNVERIFIED_V3_SNAPSHOT$'):
        sk._project_verified_v3_keys(pub._asdict(), pub.manifest['expected_host_ids'][0])


def test_sk_a_cross_run_isolation(root, monkeypatch):
    first = item()
    pub = publish(root, [first], monkeypatch)
    a = sk._project_verified_v3_keys(pub, hid(first)).keys[0]
    monkeypatch.setattr(native, 'RID', 'sk-a-other-synthetic-run')
    second = item()
    pub2 = publish(root, [second], monkeypatch)
    b = sk._project_verified_v3_keys(pub2, hid(second)).keys[0]
    assert a.fingerprint_sha256 == b.fingerprint_sha256 == FP
    assert a.run_id != b.run_id and a.host_id != b.host_id and a.asset_id != b.asset_id
    assert set(a.evidence_ids).isdisjoint(b.evidence_ids) and set(a.collection_ids).isdisjoint(b.collection_ids)
