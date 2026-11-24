"""S01/S03 focused evidence; S02 requires a separate actual safe native proof."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import time

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import assessment, evidence as ev, ssh_posture as ssh

ROLE = ROOT / 'roles/pqc_platform_crypto/tasks/ssh_posture.yml'
MIRROR = ROOT / 'ansible_collections/security/compliance_pqc_readiness/roles/pqc_platform_crypto/tasks/ssh_posture.yml'
TASKS = yaml.safe_load(ROLE.read_text())
HELPER = next(t['ansible.builtin.command']['argv'][-2] for t in TASKS if 'ansible.builtin.command' in t)
H = {'__name__': 'test_helper'}
exec(compile(HELPER, '<fixed-ssh-helper>', 'exec'), H)
RULES = assessment.load_rules((ROOT / 'config/assessment_rules.yml').read_bytes())
TIME = '2026-01-01T00:00:00Z'
HOST = ev.host_id('fixture-authority', 'host-a.example.invalid')
SOURCE = dict(source_kind='SYNTHETIC', producer_id=ssh.PRODUCER, producer_version=ssh.VERSION,
              origin_ref='fixture-ssh', input_sha256=None)
CTX = ssh.digest('ctx', ['fixture-context'])


def document(run_scoped=False, second=False):
    h = dict(host_id=HOST, target_id='host-a.example.invalid', identity_scope='STABLE', host_state='COMPLETE',
             reason_code='FIXTURE', inventory_authority_id='fixture-authority', identity_key=None)
    if run_scoped:
        h.update(host_id=ev.host_id(None, None, run_id='fixture-run', identity_key='anonymous-host'),
                 identity_scope='RUN_SCOPED', inventory_authority_id=None, target_id=None, identity_key='anonymous-host')
    hosts = [h]
    if second:
        hosts.append(dict(h, host_id=ev.host_id('fixture-authority', 'host-b.example.invalid'),
                          target_id='host-b.example.invalid'))
    return dict(schema_version='1.1.0', run=dict(run_id='fixture-run', run_state='COMPLETE', recorded_at=TIME,
                started_at=None, finished_at=None, source=SOURCE.copy(), expected_host_ids=[x['host_id'] for x in hosts]),
                hosts=hosts, collections=[], assets=[], evidence=[], claims=[], findings=[])


def snapshot(sshd_on=True, keys_on=True, status='UNVERIFIED', contexts=None, **overrides):
    flags = dict(zip(ssh.FLAGS, (sshd_on, keys_on)))
    data = dict(flags=flags, platform_status=status, context_refs=['global-default'] if contexts is None else contexts, slots={})
    for slot in ssh.slots(data):
        flag = keys_on if slot == 'keys' else sshd_on
        state, reason = (('NOT_SCANNED', 'DISABLED_BY_USER') if not flag else
                         ('NOT_APPLICABLE', 'PLATFORM_OUT_OF_SCOPE') if status == 'OUT_OF_SCOPE' else
                         ('UNKNOWN', 'PLATFORM_UNRESOLVED') if status == 'UNKNOWN' else
                         ('UNKNOWN', 'KEY_FLAG_REQUIRED') if slot.startswith('native-') and not keys_on else
                         ('UNKNOWN', 'TOOL_UNAVAILABLE'))
        data['slots'][slot] = H['result'](state, reason)
    data['slots'].update(overrides)
    return data


def norm(s, doc=None, host=None):
    if doc is None:
        doc = document()
    return ssh.normalize_ssh(doc, doc['hosts'][0]['host_id'] if host is None else host, s, SOURCE, TIME, RULES)


def parse(text, rc=0, err=b''):
    return H['parse_client'](rc, text.encode('ascii') if isinstance(text, str) else text, err)


def field(raw):
    if isinstance(raw, str):
        raw = raw.encode('ascii')
    return struct.pack('>I', len(raw)) + raw


def public(name='ssh-ed25519', payload=None, comment=b'DUMMY-COMMENT'):
    if payload is None:
        payload = field(bytes(range(32)))
    wire = field(name) + payload
    return name.encode('ascii') + b' ' + base64.b64encode(wire) + b' ' + comment + b'\n', wire


def put(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data if isinstance(data, bytes) else data.encode('utf-8'))
    path.chmod(0o600)
    return path


def read_fixture(root, slot):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return H['collect_config' if slot == 'config' else 'collect_keys'](fd)
    finally:
        os.close(fd)


def make_fixture(root):
    put(root / 'etc/ssh/sshd_config', '''# KexAlgorithms ignored-comment
KexAlgorithms curve25519-sha256
Include /etc/ssh/sshd_config.d/*.conf
HostKey /etc/ssh/ssh_host_ed25519_key
Match User DUMMY-USER-SENTINEL
 Ciphers +aes256-ctr
 AuthorizedKeysCommand /dummy/external-command
Match all
 MACs hmac-sha2-256
''')
    put(root / 'etc/ssh/sshd_config.d/20-second.conf', 'Ciphers aes128-ctr\n')
    put(root / 'etc/ssh/sshd_config.d/10-first.conf', 'Include /etc/crypto-policies/back-ends/opensshserver.config\nHostKeyAlgorithms ssh-ed25519\n')
    put(root / 'etc/crypto-policies/back-ends/opensshserver.config', 'KexAlgorithms -diffie-hellman-*\n')
    raw, wire = public()
    put(root / 'etc/ssh/ssh_host_ed25519_key.pub', raw)
    put(root / 'etc/ssh/ssh_host_duplicate_key.pub', public(comment=b'OTHER-DUMMY-COMMENT')[0])
    return hashlib.sha256(wire).hexdigest()


@pytest.mark.parametrize('text,rc,err,state,reason', [
    ('curve25519-sha256\nmlkem768x25519-sha256\n', 0, b'', 'COLLECTED', 'OK'),
    ('ssh-ed25519\nssh-ed25519\n', 0, b'', 'PARTIAL', 'FORMAT_GAP'),
    ('ssh-ed25519\nDUMMY invalid line\n', 0, b'', 'PARTIAL', 'FORMAT_GAP'),
    ('bad /path\n', 0, b'', 'UNKNOWN', 'UNRECOGNIZED_OUTPUT'),
    ('ssh-ed25519', 0, b'', 'ERROR', 'INCOMPLETE_OUTPUT'),
    ('', 0, b'', 'UNKNOWN', 'NO_OUTPUT'),
    (b'\xff\n', 0, b'', 'ERROR', 'INVALID_ENCODING'),
    ('x\n' * 257, 0, b'', 'ERROR', 'ROW_LIMIT'),
    ('x' * 16384 + '\n', 0, b'', 'ERROR', 'OUTPUT_LIMIT'),
    ('x\n', 1, b'Unsupported query "sig"\n', 'UNKNOWN', 'UNSUPPORTED_QUERY'),
    ('x\n', 1, b'Permission denied\n', 'PERMISSION_DENIED', 'PERMISSION_DENIED'),
    ('x\n', 0, b'error\n', 'ERROR', 'COMMAND_FAILED'),
    ('x\n', 7, b'', 'ERROR', 'COMMAND_FAILED'),
])
def test_client_parser(text, rc, err, state, reason):
    r = parse(text, rc, err)
    assert (r['state'], r['reason']) == (state, reason)
    assert bool(r['rows']) == (state in ('COLLECTED', 'PARTIAL'))
    ssh.validate_snapshot(snapshot(**{'client-kex': r}))


def test_client_context_separation():
    s = snapshot(keys_on=False, **{'client-kex': parse('mlkem768x25519-sha256\ncurve25519-sha256\nML-DSA-44\n'),
        'client-cipher': parse('aes256-ctr\nML-KEM-768\n'), 'client-key': parse('ssh-ed25519\nML-DSA-44\n'),
        'client-sig': parse('rsa-sha2-512\nML-DSA-44\n'), 'client-mac': parse('hmac-sha2-256\nML-DSA-44\n')})
    d, detail = norm(s)
    rows = [r for r in d['evidence'] if r['evidence_kind'] == 'RUNTIME_CAPABILITY']
    assert any(r['algorithm']['family'] == 'HYBRID' and r['algorithm']['primitive'] == 'KEX' for r in rows)
    assert any(r['algorithm']['family'] == 'PQC' and r['algorithm']['primitive'] == 'SIGNATURE' for r in rows)
    assert all(r['algorithm']['family'] == 'UNKNOWN' for r in rows if r['data']['capability'] in ('ssh-client-key', 'ssh-client-mac'))
    assert all(r['data']['supported'] is True for r in rows)
    reread = ev.parse_evidence_bytes(ev.canonical_bytes(d))
    ssh.validate_details(reread, json.loads(ssh.canonical(detail)), RULES)
    assessed = assessment.evaluate_document(reread, RULES)
    assert {c['level'] for c in assessed['claims']} == {'L2'}
    assert not any(c['assessment_state'] == 'FAIL' for c in assessed['claims'])
    ssh.validate_details(assessed, detail, RULES)


@pytest.mark.parametrize('sshd,keys,status', [(False, False, 'UNVERIFIED'), (True, True, 'OUT_OF_SCOPE'),
    (True, True, 'UNKNOWN'), (False, True, 'UNVERIFIED'), (True, False, 'UNVERIFIED')])
def test_flag_platform_and_native_hold(sshd, keys, status):
    s = snapshot(sshd, keys, status, contexts=['global-default', CTX])
    d, detail = norm(s)
    assert not d['assets'] and not [r for r in d['evidence'] if r['evidence_kind'] != 'COLLECTION_SUMMARY']
    assert len(detail['records']) == 9
    assert not assessment.evaluate_document(d, RULES)['claims']
    if sshd and not keys and status == 'UNVERIFIED':
        assert all(r['reason'] == 'KEY_FLAG_REQUIRED' for r in detail['records'] if r['slot'].startswith('native-'))


def test_static_config_lineage_not_effective(tmp_path):
    fp = make_fixture(tmp_path)
    config, keys = read_fixture(tmp_path, 'config'), read_fixture(tmp_path, 'keys')
    assert config['state'] == 'PARTIAL' and set(config['gaps']) == {'MATCH_UNRESOLVED', 'NATIVE_DEPENDENCY'}
    assert keys['state'] == 'COLLECTED' and len(keys['rows']) == 2
    sources = [r for r in config['rows'] if r['kind'] == 'SOURCE']
    assert [r['source_kind'] for r in sources] == ['MAIN', 'DROPIN', 'POLICY_BACKEND', 'DROPIN']
    assert [r['depth'] for r in sources] == [0, 1, 2, 1]
    assert sources[2]['parent_ref'] == sources[1]['source_ref'] and sources[3]['parent_ref'] == sources[0]['source_ref']
    directives = [r for r in config['rows'] if r['kind'] == 'DIRECTIVE']
    assert any(r['operator'] == '-' and r['values'] == ['diffie-hellman-*'] for r in directives)
    assert any(r['operator'] == '+' and r['context_ref'] != 'global-default' for r in directives)
    assert 'ignored-comment' not in json.dumps(config) and 'DUMMY-USER-SENTINEL' not in json.dumps(config)
    before = document(); saved = copy.deepcopy(before)
    s = snapshot(config=config, keys=keys); saved_s = copy.deepcopy(s)
    d, detail = norm(s, before)
    assert before == saved and s == saved_s
    assert len(d['assets']) == 1 and len(d['assets'][0]['evidence_ids']) == 2
    assert d['assets'][0]['identity_key'] == 'sha256-' + fp and d['assets'][0]['asset_kind'] == 'public_key'
    assert all(r['evidence_kind'] in ('ASSET_METADATA', 'COLLECTION_SUMMARY') for r in d['evidence'])
    key_detail = next(x for x in detail['records'] if x['slot'] == 'keys')
    assert sorted(len(x['config_evidence_ids']) for x in key_detail['observations']) == [0, 1]
    wire = ev.canonical_bytes(d); reread = ev.parse_evidence_bytes(wire)
    ssh.validate_details(reread, detail, RULES)
    assessed = assessment.evaluate_document(reread, RULES)
    assert not assessed['claims'] and all(f['assessment_state'] not in ('PASS', 'FAIL') for f in assessed['findings'])
    assert ssh.canonical(norm(s)[1]) == ssh.canonical(detail)
    assert ev.canonical_bytes(norm(s)[0]) == wire
    assert all(x not in ssh.canonical(detail) for x in [b'DUMMY-COMMENT', b'OTHER-DUMMY-COMMENT', b'/etc/ssh', b'/dummy/external-command'])


def test_actual_no_private_or_escape_reads(tmp_path):
    root = tmp_path / 'root'; outside = tmp_path / 'outside'
    secret = put(outside / 'private-sentinel', b'DUMMY-PRIVATE-SENTINEL\n')
    control = put(outside / 'positive-control', b'DUMMY-READ-CONTROL\n')
    old = 1000000000
    for p in (secret, control):
        os.utime(p, ns=(old, old))
    assert control.read_bytes() == b'DUMMY-READ-CONTROL\n'
    # A real atime positive control on this filesystem; no secret content read by test.
    if control.stat().st_atime_ns == old:
        pytest.fail('Filesystem did not expose the required read witness')
    put(root / 'etc/ssh/sshd_config', 'Include /outside/private-sentinel\nInclude /etc/ssh/sshd_config.d/*.conf\n'
        'HostKey /outside/private-sentinel\nMatch exec DUMMY_EXTERNAL_SENTINEL\nAuthorizedKeysCommand /outside/no-run\n')
    drop = root / 'etc/ssh/sshd_config.d'; drop.mkdir(mode=0o700)
    (drop / '10-link.conf').symlink_to(secret)
    os.link(secret, drop / '20-hard.conf')
    os.mkfifo(drop / '30-fifo.conf', mode=0o600)
    keydir = root / 'etc/ssh'
    (keydir / 'ssh_host_link_key.pub').symlink_to(secret)
    os.link(secret, keydir / 'ssh_host_hard_key.pub')
    os.mkfifo(keydir / 'ssh_host_fifo_key.pub', mode=0o600)
    put(keydir / 'ssh_host_real_key.pub', public()[0])
    put(keydir / 'ssh_host_rsa_key', b'DUMMY-PRIVATE-NAME-SENTINEL')
    os.utime(keydir / 'ssh_host_rsa_key', ns=(old, old))
    a, b = read_fixture(root, 'config'), read_fixture(root, 'keys')
    assert a['state'] == b['state'] == 'PARTIAL'
    assert {'INCLUDE_REJECTED', 'SOURCE_UNSAFE', 'HOSTKEY_PATH_REJECTED', 'NATIVE_DEPENDENCY'} <= set(a['gaps'])
    assert b['gaps'] == ['SOURCE_UNSAFE'] and len(b['rows']) == 1
    assert secret.stat().st_atime_ns == old and (keydir / 'ssh_host_rsa_key').stat().st_atime_ns == old
    assert 'DUMMY-' not in json.dumps([a, b]) and str(outside) not in json.dumps([a, b])
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with H['Reader'](fd, 65536, 'config') as reader:
            with pytest.raises(H['ReadFailure'], match='SOURCE_UNSAFE'):
                reader.read(('etc', 'ssh'), 'ssh_host_rsa_key')
            with pytest.raises(H['ReadFailure'], match='SOURCE_UNSAFE'):
                reader.read(('etc', 'ssh'), 'ssh_host_real_key.pub')
        with H['Reader'](fd, 524288, 'keys') as reader:
            with pytest.raises(H['ReadFailure'], match='SOURCE_UNSAFE'):
                reader.read(('etc', 'ssh'), 'sshd_config')
    finally:
        os.close(fd)


def test_directory_symlink_and_source_drift(tmp_path):
    outside = tmp_path / 'outside'
    put(outside / 'sshd_config', 'KexAlgorithms curve25519-sha256\n')
    root = tmp_path / 'root'; (root / 'etc').mkdir(parents=True, mode=0o700)
    (root / 'etc/ssh').symlink_to(outside, target_is_directory=True)
    assert read_fixture(root, 'config')['state'] == 'UNKNOWN'
    assert read_fixture(root, 'keys')['state'] == 'UNKNOWN'
    (root / 'etc/ssh').unlink()
    p = put(root / 'etc/ssh/sshd_config', 'Ciphers aes256-ctr\n')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with H['Reader'](fd, 65536, 'config') as reader:
            assert reader.read(('etc', 'ssh'), 'sshd_config') == b'Ciphers aes256-ctr\n'
            p.write_bytes(b'Ciphers aes128-ctr\n')
            with pytest.raises(H['LimitFailure'], match='SOURCE_DRIFT'):
                reader.verify()
    finally:
        os.close(fd)


@pytest.mark.parametrize('kind,reason', [('file', 'INPUT_LIMIT'), ('aggregate', 'INPUT_LIMIT'),
    ('entries', 'DIRECTORY_LIMIT'), ('sources', 'SOURCE_LIMIT'), ('records', 'ROW_LIMIT')])
def test_config_limits_discard_all(tmp_path, kind, reason):
    p = tmp_path / 'etc/ssh/sshd_config'
    put(p, 'Include /etc/ssh/sshd_config.d/*.conf\n')
    if kind == 'file':
        put(p, b'#' * 16385)
    elif kind == 'records':
        put(p, 'Ciphers a\n' * 513)
    else:
        count = {'aggregate': 5, 'entries': 257, 'sources': 32}[kind]
        for i in range(count):
            put(p.parent / 'sshd_config.d' / ('f%03d.conf' % i), b'#' * 16384 if kind == 'aggregate' else b'#x\n')
    assert read_fixture(tmp_path, 'config') == H['result']('ERROR', reason)


def test_repeated_include_and_control_characters(tmp_path):
    p = tmp_path / 'etc/ssh/sshd_config'
    put(p, 'Include /etc/crypto-policies/back-ends/opensshserver.config\n')
    put(tmp_path / 'etc/crypto-policies/back-ends/opensshserver.config',
        'Include /etc/crypto-policies/back-ends/opensshserver.config\n')
    r = read_fixture(tmp_path, 'config')
    assert r['state'] == 'PARTIAL' and r['gaps'] == ['INCLUDE_REPEATED']
    ssh.validate_snapshot(snapshot(config=r))
    put(p, b'Ciphers a\x0bMatch all\n')
    assert read_fixture(tmp_path, 'config')['state'] == 'UNKNOWN'


@pytest.mark.parametrize('name,payload,bits', [
    ('ssh-ed25519', field(b'x'*32), 256),
    ('ssh-rsa', field(b'\x01\x00\x01') + field(b'\x00\x80' + b'x'*255), 2048),
    ('ssh-dss', field(b'\x00\x80' + b'x'*127) + field(b'\x01')*3, 1024),
    ('ecdsa-sha2-nistp256', field('nistp256') + field(b'\x04'+b'x'*64), 256),
    ('ecdsa-sha2-nistp384', field('nistp384') + field(b'\x04'+b'x'*96), 384),
    ('ecdsa-sha2-nistp521', field('nistp521') + field(b'\x04'+b'x'*132), 521),
    ('ssh-unknown-fixture', field(b'opaque'), None),
])
def test_public_key_wire_fingerprint(name, payload, bits):
    raw, wire = public(name, payload)
    row = H['parse_public'](raw)
    assert row == dict(key_type=name, bits=bits, fingerprint_sha256=hashlib.sha256(wire).hexdigest(),
                       grammar='UNKNOWN_TYPE' if bits is None else 'KNOWN')
    assert H['parse_public'](public(name, payload, b'other-comment')[0]) == row
    assert H['parse_public'](raw.rstrip(b'\n')) == row


@pytest.mark.parametrize('raw', [b'', b'-----BEGIN OPENSSH PRIVATE KEY-----\nDUMMY\n',
    b'ssh-ed25519 !!!\n', b'ssh-ed25519 ' + base64.b64encode(field('ssh-rsa') + field(b'x'*32)) + b'\n',
    public(payload=field(b'x'*31))[0], public(payload=field(b'x'*32)+b'x')[0],
    public('ssh-rsa', field(b'\x80')+field(b'\x01'))[0], public('ecdsa-sha2-nistp256', field('nistp384')+field(b'x'*65))[0],
    public('ssh-unknown-fixture', b'')[0], public()[0]+b'other\n', public()[0].replace(b' ', b'\x0b', 1)])
def test_reject_invalid_public(raw):
    with pytest.raises(H['ReadFailure'], match='KEY_INVALID'):
        H['parse_public'](raw)


def test_keys_unknown_empty_and_limits(tmp_path):
    p = tmp_path / 'etc/ssh'; p.mkdir(parents=True, mode=0o700)
    r = read_fixture(tmp_path, 'keys')
    assert r == H['result']('COLLECTED', 'OK')
    d, _ = norm(snapshot(sshd_on=False, keys=r))
    assert [x['data']['observation_count'] for x in d['evidence']] == [0]
    put(p / 'ssh_host_unknown_key.pub', public('ssh-unknown-fixture', field(b'opaque'))[0])
    r = read_fixture(tmp_path, 'keys')
    assert r['state'] == 'PARTIAL' and r['gaps'] == ['KEY_TYPE_UNKNOWN']
    d, detail = norm(snapshot(sshd_on=False, keys=r))
    assert not d['assets'] and not assessment.evaluate_document(d, RULES)['claims']
    assert next(x for x in d['evidence'] if x['evidence_kind'] == 'COLLECTION_SUMMARY')['data']['observation_count'] == 0
    for i in range(32):
        put(p / ('ssh_host_key%d_key.pub' % i), public()[0])
    assert read_fixture(tmp_path, 'keys') == H['result']('ERROR', 'SOURCE_LIMIT')


def test_key_identity_run_scope(tmp_path):
    make_fixture(tmp_path)
    r = read_fixture(tmp_path, 'keys')
    d, detail = norm(snapshot(sshd_on=False, keys=r), document(run_scoped=True))
    a = d['assets'][0]
    assert a['identity_scope'] == 'RUN_SCOPED'
    assert a['asset_id'] == ev.asset_id(a['host_id'], 'public_key', a['identity_key'], run_id='fixture-run')
    ssh.validate_details(ev.parse_evidence_bytes(ev.canonical_bytes(d)), detail, RULES)


@pytest.mark.parametrize('mutation', [
    lambda s: s.update(raw='DUMMY-SECRET'), lambda s: s['flags'].update(pqc_collect_sshd=1),
    lambda s: s['context_refs'].append('raw-user'), lambda s: s['slots']['client-kex'].update(rc=True),
    lambda s: s['slots']['client-kex'].update(state='COLLECTED', reason='OK', rc=0, rows=['ssh-ed25519']*2),
    lambda s: s['slots']['native-0'].update(state='COLLECTED', reason='OK', rc=0, rows=['ssh-ed25519']),
    lambda s: s['slots']['keys']['rows'][0].update(bits=True),
    lambda s: s['slots']['keys']['rows'][0].update(source_ref='raw/path'),
    lambda s: s['slots']['keys']['rows'][0].update(key_type='ssh-rsa'),
    lambda s: s['slots']['config']['rows'][1].update(context_ref='ctx-'+'0'*64),
    lambda s: s['slots']['config']['rows'][0].update(parent_ref='src-'+'0'*64),
    lambda s: s['slots']['config'].update(state='COLLECTED', reason='OK', gaps=[]),
])
def test_snapshot_reject_untrusted_and_forged_native(tmp_path, mutation):
    make_fixture(tmp_path)
    s = snapshot(config=read_fixture(tmp_path, 'config'), keys=read_fixture(tmp_path, 'keys'))
    mutation(s)
    with pytest.raises(ev.EvidenceError) as exc:
        ssh.validate_snapshot(s)
    assert 'DUMMY-SECRET' not in str(exc.value)


def rehash(d):
    d.pop('detail_sha256', None)
    d['detail_sha256'] = hashlib.sha256(ssh.canonical(d)).hexdigest()


@pytest.mark.parametrize('change', ['hash', 'extra', 'duplicate', 'cross-host', 'wrong-asset', 'wrong-evidence',
    'wrong-origin', 'wrong-config-link', 'row-conflict', 'context', 'collection', 'missing'])
def test_companion_reject_rehashed_mismatch(tmp_path, change):
    make_fixture(tmp_path)
    s = snapshot(config=read_fixture(tmp_path, 'config'), keys=read_fixture(tmp_path, 'keys'))
    d, detail = norm(s, document(second=True))
    d, other = norm(snapshot(sshd_on=False, keys=read_fixture(tmp_path, 'keys')), d, d['hosts'][1]['host_id'])
    bad = copy.deepcopy(detail)
    key = next(x for x in bad['records'] if x['slot'] == 'keys')
    other_key = next(x for x in other['records'] if x['slot'] == 'keys')
    obs = key['observations'][0]
    if change == 'hash':
        bad['detail_sha256'] = '0'*64
    else:
        if change == 'extra': bad['raw'] = 'DUMMY-SECRET'
        if change == 'duplicate': key['observations'].append(copy.deepcopy(obs))
        if change == 'cross-host': key['host_id'] = other['host_id']
        if change == 'wrong-asset': obs['asset_id'] = other_key['observations'][0]['asset_id']
        if change == 'wrong-evidence': obs['evidence_id'] = other_key['observations'][0]['evidence_id']
        if change == 'wrong-origin': bad['source']['origin_ref'] = 'wrong-origin'
        if change == 'wrong-config-link': obs['config_evidence_ids'] = [other_key['observations'][0]['evidence_id']]
        if change == 'row-conflict': obs['row']['fingerprint_sha256'] = '0'*64
        if change == 'context': bad['context_refs'] = [CTX]
        if change == 'collection': key['collection_id'] = other_key['collection_id']
        if change == 'missing': bad['records'].pop()
        rehash(bad)
    with pytest.raises(ev.EvidenceError) as exc:
        ssh.validate_details(d, bad, RULES)
    assert 'DUMMY-SECRET' not in str(exc.value)
    ssh.validate_details(d, detail, RULES)
    ssh.validate_details(d, other, RULES)


@pytest.mark.parametrize('code,seconds,expected', [('print("ok")', 2, None), ('raise SystemExit(7)', 2, None),
    ('import time; time.sleep(5)', .2, 'TIMEOUT'), ('import sys; sys.stdout.write("x"*20000)', 2, 'OUTPUT_LIMIT'),
    ('import sys; sys.stdout.write("x"*8193); sys.stderr.write("y"*8192)', 2, 'OUTPUT_LIMIT')])
def test_actual_bounded_child(code, seconds, expected):
    start = time.monotonic()
    reason, rc, out, err = H['capture']([sys.executable, '-I', '-B', '-c', code], seconds)
    assert reason == expected and time.monotonic()-start < 3 and len(out)+len(err) <= 16384 and rc is not None
    if code == 'print("ok")': assert out == b'ok\n' and rc == 0
    if 'SystemExit' in code: assert rc == 7
    if expected == 'TIMEOUT': assert rc < 0


def test_child_reap_no_agent_env_and_closed_stdin(monkeypatch):
    monkeypatch.setenv('SSH_AUTH_SOCK', '/DUMMY-AGENT-SENTINEL')
    monkeypatch.setenv('SSH_ASKPASS', '/DUMMY-ASKPASS-SENTINEL')
    reason, rc, out, err = H['capture']([sys.executable, '-I', '-B', '-c',
        'import os,sys; print(sorted(os.environ)); print(len(sys.stdin.read()))'], 2)
    assert (reason, rc, err) == (None, 0, b'') and out == b"['HOME', 'LC_ALL', 'PATH']\n0\n"
    reason, rc, out, err = H['capture']([sys.executable, '-I', '-B', '-c',
        'import os,time; print(os.getpid(),flush=True); time.sleep(8)'], 2)
    assert reason == 'TIMEOUT' and rc < 0 and not err
    with pytest.raises(ProcessLookupError):
        os.kill(int(out), 0)


def test_fixed_entry_native_never_dispatched_and_mirror():
    assert ROLE.read_bytes() == MIRROR.read_bytes()
    assert ROLE.stat().st_mode & 0o777 == MIRROR.stat().st_mode & 0o777 == 0o644
    assert H['CLIENTS'] == {f'client-{q}': ['/usr/bin/ssh', '-Q', q] for q in ('kex', 'cipher', 'key', 'sig', 'mac')}
    for bad in ('-T', '-G', 's_client', '/etc/ssh/sshd_config'):
        p = subprocess.run([sys.executable, '-I', '-B', '-c', HELPER, bad], capture_output=True, timeout=3)
        assert p.returncode == 2 and not p.stdout
    p = subprocess.run([sys.executable, '-I', '-B', '-c', HELPER, 'native-0'], capture_output=True, timeout=3)
    assert p.returncode == 0
    result = json.loads(p.stdout)
    assert result['state'] in ('UNKNOWN', 'PERMISSION_DENIED', 'ERROR') and not result['rows'] and result['rc'] is None


def test_actual_client_query_smoke_required():
    if H['tool_error']('/usr/bin/ssh'):
        pytest.skip('Required real ssh -Q smoke: fixed client executable unavailable')
    actual = []
    for slot in ssh.CLIENTS:
        r = H['run_slot'](slot)
        ssh.validate_snapshot(snapshot(**{slot: r}))
        actual.append(r)
    assert any(r['state'] in ('COLLECTED', 'PARTIAL') for r in actual)


def test_required_safe_native_effective_control():
    # No unproven sshd -T invocation even on a host with sshd installed.
    assert H['NATIVE_T_QUALIFIED'] is ssh.NATIVE_T_QUALIFIED is False
    pytest.skip('S02 HOLD: actual production -T/-C, public-only equivalence and native safety not qualified')


def native_play(role, root, tmp_path, requests, expected):
    play = tmp_path / 'play.yml'; output = tmp_path / 'snapshot'
    tasks = []
    for i, (req, count) in enumerate(zip(requests, expected)):
        tasks += [dict(name='Internal synthetic call', **{'ansible.builtin.include_role':
                   dict(name=role, tasks_from='ssh_posture')}, vars={'pqc_ssh_request': req}),
                  dict(name='Verify actual helper invocation count', **{'ansible.builtin.assert': dict(that=[
                      'pqc_ssh_queries.results | selectattr("rc", "defined") | list | length == ' + str(count)])}),
                  dict(name='Save synthetic closed projection', **{'ansible.builtin.copy':
                       dict(content='{{ pqc_ssh_snapshot | to_json }}', dest=str(output)+str(i), mode='0600')}, no_log=True)]
    put(play, yaml.safe_dump([dict(hosts='localhost', connection='local', gather_facts=False,
        vars={'ansible_python_interpreter': sys.executable}, tasks=tasks)]))
    cfg = put(tmp_path / 'ansible.cfg', '[defaults]\nretry_files_enabled=False\ninterpreter_python=auto_silent\n')
    env = dict(os.environ, ANSIBLE_CONFIG=str(cfg), ANSIBLE_ROLES_PATH=str(root/'roles'), ANSIBLE_COLLECTIONS_PATH=str(root),
        ANSIBLE_COLLECTIONS_SCAN_SYS_PATH='false', ANSIBLE_LOCAL_TEMP=str(tmp_path/'ansible-local'),
        ANSIBLE_REMOTE_TEMP=str(tmp_path/'ansible-remote'))
    cmd = [str(Path(sys.executable).parent/'ansible-playbook'), '-i', 'localhost,', str(play)]
    for opts in (['--syntax-check'], []):
        p = subprocess.run(cmd+opts, env=env, cwd=tmp_path, capture_output=True, timeout=120)
        assert p.returncode == 0, (p.stdout[-3000:], p.stderr[-1000:])
    rows = [json.loads(Path(str(output)+str(i)).read_text()) for i in range(len(requests))]
    for s in rows:
        d, detail = norm(s)
        ssh.validate_details(assessment.evaluate_document(ev.parse_evidence_bytes(ev.canonical_bytes(d)), RULES), detail, RULES)
    return rows


@pytest.mark.parametrize('role', ['pqc_platform_crypto', 'security.compliance_pqc_readiness.pqc_platform_crypto'])
def test_native_synthetic_role(role, tmp_path):
    def request(a, b, status, contexts=None):
        r = dict(flags=dict(zip(ssh.FLAGS, (a, b))), platform_status=status)
        return r if contexts is None else dict(r, context_refs=contexts)
    # Actual unchanged candidate loaded for zero-query cases. No actual /etc/ssh access.
    r = native_play(role, ROOT, tmp_path/'zero', [request(False, False, 'UNVERIFIED'),
        request(True, True, 'OUT_OF_SCOPE'), request(True, True, 'UNKNOWN')], [0, 0, 0])
    assert all(x['state'] == 'NOT_SCANNED' for x in r[0]['slots'].values())
    assert all(x['state'] == 'NOT_APPLICABLE' for x in r[1]['slots'].values())
    assert all(x['state'] == 'UNKNOWN' for x in r[2]['slots'].values())
    # Private test-only role copy changes exactly one constant: root of synthetic
    # config/key filesystem. No production caller path override or fake CLI.
    fixture = tmp_path/'fixture'; make_fixture(fixture)
    role_root = tmp_path/'role-root'
    original = ROLE.read_text()
    old = "ROOT_PATH = '/'"; assert original.count(old) == 1
    text = original.replace(old, 'ROOT_PATH = '+repr(str(fixture)))
    for path in (ROLE, MIRROR):
        put(role_root/path.relative_to(ROOT), text)
    r = native_play(role, role_root, tmp_path/'eligible', [request(True, False, 'UNVERIFIED'),
        request(False, True, 'UNVERIFIED'), request(True, True, 'UNVERIFIED', ['global-default', CTX])], [6, 1, 9])
    assert r[0]['slots']['keys']['state'] == 'NOT_SCANNED' and r[0]['slots']['native-0']['reason'] == 'KEY_FLAG_REQUIRED'
    assert r[1]['slots']['config']['state'] == 'NOT_SCANNED' and len(r[1]['slots']['keys']['rows']) == 2
    assert r[2]['slots']['config']['state'] == 'PARTIAL' and len(r[2]['slots']['keys']['rows']) == 2
    assert all(not r[2]['slots'][x]['rows'] for x in ('native-0', 'native-1'))


def test_real_source_permissions_and_missing(tmp_path):
    assert os.geteuid() != 0, 'Required non-root source permission witness'
    root = tmp_path / 'root'; (root / 'etc/ssh').mkdir(parents=True, mode=0o700)
    assert read_fixture(root, 'config')['reason'] == 'SOURCE_MISSING'
    cfg = put(root / 'etc/ssh/sshd_config', 'Ciphers aes256-ctr\n')
    key = put(root / 'etc/ssh/ssh_host_ed25519_key.pub', public()[0])
    cfg.chmod(0); key.chmod(0)
    try:
        for slot in ('config', 'keys'):
            r = read_fixture(root, slot)
            assert r == H['result']('PERMISSION_DENIED', 'SOURCE_PERMISSION')
            ssh.validate_snapshot(snapshot(**{slot: r}))
    finally:
        cfg.chmod(0o600); key.chmod(0o600)


# Synthetic effective output; never presented as native OpenSSH output.
EFFECTIVE_FIXTURE = (b'KexAlgorithms curve25519-sha256,mlkem768x25519-sha256,future-kex\n'
                     b'ciphers aes128-ctr,aes256-ctr\n'
                     b'macs hmac-sha2-256\n'
                     b'hostkeyalgorithms ssh-ed25519\n'
                     b'PubkeyAcceptedKeyTypes ssh-ed25519\n'
                     b'hostbasedacceptedalgorithms ssh-ed25519\n'
                     b'casignaturealgorithms RSA-SHA256\n'
                     b'passwordauthentication yes\n'
                     b'allowusers DUMMY-USER-SENTINEL\n')
NATIVE_SPEC = dict(user='fixture_user', host='fixture.example.invalid', addr='192.0.2.2',
                   laddr='198.51.100.2', lport=22)
NATIVE_CTX = H['digest']('ctx', ['ssh-native-context-v1', NATIVE_SPEC['user'], NATIVE_SPEC['host'],
                               NATIVE_SPEC['addr'], NATIVE_SPEC['laddr'], NATIVE_SPEC['lport']])


def effective(mode='T', out=EFFECTIVE_FIXTURE, rc=0, err=b''):
    return H['parse_effective'](mode, rc, out, err)


@pytest.mark.parametrize('mode', ['G', 'T'])
def test_r2_shared_effective_roundtrip(mode):
    one = effective(mode)
    two = effective(mode, EFFECTIVE_FIXTURE.replace(b'PubkeyAcceptedKeyTypes ssh-ed25519',
                                                    b'pubkeyacceptedalgorithms rsa-sha2-256'))
    assert one['state'] == two['state'] == 'COLLECTED'
    assert {r['mode'] for r in one['rows']} == {mode}
    assert any(r['token'] == 'RSA-SHA256' for r in one['rows'])
    assert not any(r['setting'] in ('passwordauthentication', 'allowusers') for r in one['rows'])
    assert all(r['setting'] != 'pubkeyacceptedkeytypes' for r in one['rows'])
    d, detail = norm(snapshot(contexts=['global-default', NATIVE_CTX], **{'native-0': one, 'native-1': two}))
    assert detail['source']['source_kind'] == 'SYNTHETIC'
    assert b'DUMMY-USER-SENTINEL' not in ssh.canonical(detail)
    rows = [e for e in d['evidence'] if e['evidence_kind'] == 'EFFECTIVE_CONFIGURATION']
    assert len(rows) == len(one['rows']) + len(two['rows'])
    assert {e['collection_id'] for e in rows} == {r['collection_id'] for r in detail['records'] if r['slot'].startswith('native-')}
    assert all(e['data']['allowed'] is True and e['asset_id'] is None for e in rows)
    for e in rows:
        if e['data']['setting'] in ('macs', 'hostkeyalgorithms', 'pubkeyacceptedalgorithms', 'hostbasedacceptedalgorithms') or e['data']['effective_value'] == 'future-kex':
            assert e['algorithm']['family'] == 'UNKNOWN'
    a = assessment.evaluate_document(ev.parse_evidence_bytes(ev.canonical_bytes(d)), RULES)
    assert all(c['level'] == 'L3' for c in a['claims'])
    assert {c['assessment_state'] for c in a['claims']} == {'PASS', 'UNKNOWN'}
    assert not any(c['assessment_state'] == 'FAIL' for c in a['claims'])
    ssh.validate_details(a, detail, RULES)
    forged = copy.deepcopy(detail)
    rec = next(r for r in forged['records'] if r['slot'] == 'native-0')
    rec['observations'][0]['row']['mode'] = 'T' if mode == 'G' else 'G'
    rehash(forged)
    with pytest.raises(ev.EvidenceError):
        ssh.validate_details(a, forged, RULES)


@pytest.mark.parametrize('mode', ['G', 'T'])
def test_r2_native_source_must_not_accept_unqualified_positive(mode):
    s = snapshot(**{'native-0': effective(mode)})
    doc = document()
    native = dict(SOURCE, source_kind='NATIVE_COLLECTOR')
    doc['run']['source'] = native
    with pytest.raises(ev.EvidenceError, match='SSH_NATIVE_SOURCE_UNQUALIFIED'):
        ssh.normalize_ssh(doc, HOST, s, native, TIME, RULES)
    # A synthetic producer cannot be mixed into a native run by relabeling.
    with pytest.raises(ev.EvidenceError, match='SYNTHETIC_MIX'):
        ssh.normalize_ssh(doc, HOST, s, SOURCE, TIME, RULES)
    with pytest.raises(ev.EvidenceError):
        ssh.validate_snapshot(snapshot(keys_on=False, **{'native-0': effective(mode)}))


def test_r2_no_mixed_native_modes_or_forged_rows():
    with pytest.raises(ev.EvidenceError, match='SSH_NATIVE_MODE_MISMATCH'):
        ssh.validate_snapshot(snapshot(contexts=['global-default', NATIVE_CTX],
                                       **{'native-0': effective('G'), 'native-1': effective('T')}))
    for modify in (lambda r: r['rows'].append(copy.deepcopy(r['rows'][-1])),
                   lambda r: r['rows'].pop(0), lambda r: r['rows'][0].update(token='-bad'),
                   lambda r: r['rows'][0].update(mode='G'), lambda r: r.update(rc=1),
                   lambda r: r['rows'][0].update(extra='DUMMY-SECRET')):
        r = effective()
        modify(r)
        with pytest.raises(ev.EvidenceError):
            ssh.validate_snapshot(snapshot(**{'native-0': r}))


@pytest.mark.parametrize('out,rc,err,reason', [
    (EFFECTIVE_FIXTURE, 7, b'', 'COMMAND_FAILED'),
    (EFFECTIVE_FIXTURE, 0, b'diagnostic', 'COMMAND_FAILED'),
    (EFFECTIVE_FIXTURE, 1, b'Permission denied', 'PERMISSION_DENIED'),
    (b'', 0, b'', 'NO_OUTPUT'),
    (EFFECTIVE_FIXTURE[:-1], 0, b'', 'INCOMPLETE_OUTPUT'),
    (EFFECTIVE_FIXTURE + b'\xff\n', 0, b'', 'INVALID_ENCODING'),
    (EFFECTIVE_FIXTURE + b'ciphers aes128-ctr\n', 0, b'', 'UNRECOGNIZED_OUTPUT'),
    (EFFECTIVE_FIXTURE + b'pubkeyacceptedalgorithms ssh-ed25519\n', 0, b'', 'UNRECOGNIZED_OUTPUT'),
    (EFFECTIVE_FIXTURE.replace(b'ciphers aes128-ctr,aes256-ctr\n', b''), 0, b'', 'UNRECOGNIZED_OUTPUT'),
    (EFFECTIVE_FIXTURE.replace(b'ciphers aes128-ctr,aes256-ctr', b'ciphers'), 0, b'', 'UNRECOGNIZED_OUTPUT'),
    (EFFECTIVE_FIXTURE.replace(b'aes128-ctr,aes256-ctr', b'aes128-ctr,aes128-ctr'), 0, b'', 'UNRECOGNIZED_OUTPUT'),
    (EFFECTIVE_FIXTURE.replace(b'aes128-ctr,aes256-ctr', b'+aes128-ctr'), 0, b'', 'UNRECOGNIZED_OUTPUT'),
    (EFFECTIVE_FIXTURE.replace(b'aes128-ctr,aes256-ctr', b'none'), 0, b'', 'UNRECOGNIZED_OUTPUT'),
    (EFFECTIVE_FIXTURE + b'KexAlgorithms=x\n', 0, b'', 'UNRECOGNIZED_OUTPUT'),
    (EFFECTIVE_FIXTURE + b'gssapikexalgorithms ' + b','.join(b'x'+str(i).encode() for i in range(257)) + b'\n', 0, b'', 'ROW_LIMIT'),
    (EFFECTIVE_FIXTURE + b'x'*16384, 0, b'', 'OUTPUT_LIMIT'),
])
def test_r2_effective_parser_rejects_whole_result(out, rc, err, reason):
    for mode in ('G', 'T'):
        r = effective(mode, out, rc, err)
        assert r['reason'] == reason and not r['rows'] and not r['gaps']
        ssh.validate_snapshot(snapshot(**{'native-0': r}))


def test_r2_fixed_t_argv_and_context_rejection():
    path = '/tmp/pqc-fixture/config-0'
    base = ['/usr/sbin/sshd', '-T', '-f', path]
    assert H['native_argv'](path, 'global-default', None) == base
    assert H['native_argv'](path, NATIVE_CTX, NATIVE_SPEC) == base + [
        '-C', 'user=fixture_user,host=fixture.example.invalid,addr=192.0.2.2,laddr=198.51.100.2,lport=22']
    for spec in (dict(NATIVE_SPEC, user='-G'), dict(NATIVE_SPEC, host='a,b'),
                 dict(NATIVE_SPEC, addr='192.0.2.2,user=root'), dict(NATIVE_SPEC, laddr='fe80::1%eth0'),
                 dict(NATIVE_SPEC, lport=True), dict(NATIVE_SPEC, lport=0), dict(NATIVE_SPEC, extra='-G'),
                 None, NATIVE_SPEC):
        with pytest.raises(H['ReadFailure'], match='NATIVE_CONTEXT_REJECTED'):
            H['native_argv'](path, 'ctx-'+'0'*64, spec)
    with pytest.raises(H['ReadFailure']):
        H['native_argv'](path, 'global-default', NATIVE_SPEC)


def native_fixture(root):
    put(root/'etc/ssh/sshd_config', 'HostKey /etc/ssh/ssh_host_ed25519_key\n'
        'PasswordAuthentication yes\nInclude /etc/ssh/sshd_config.d/*.conf\n'
        'Match Address 192.0.2.0/24\n PasswordAuthentication no\n')
    put(root/'etc/ssh/sshd_config.d/20-last.conf', 'Ciphers aes256-ctr\n')
    put(root/'etc/ssh/sshd_config.d/10-first.conf', 'Include /etc/crypto-policies/back-ends/opensshserver.config\n')
    put(root/'etc/crypto-policies/back-ends/opensshserver.config', 'KexAlgorithms curve25519-sha256\n')
    put(root/'etc/ssh/ssh_host_ed25519_key.pub', public()[0])
    marker = put(root/'etc/ssh/ssh_host_ed25519_key', b'DUMMY-PRIVATE-KEY-SENTINEL')
    os.utime(marker, ns=(1000000000, 1000000000))
    return marker


def prepare_fixture(root, stage):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return Path(H['prepare_native'](fd, str(stage), time.monotonic()+2))
    finally:
        os.close(fd)


def test_r2_public_only_native_closure_actual_fs(tmp_path):
    root, stage = tmp_path/'fixture', tmp_path/'stage'
    stage.mkdir(mode=0o700)
    marker = native_fixture(root)
    before = marker.stat().st_atime_ns
    main = prepare_fixture(root, stage)
    text = main.read_text()
    assert 'HostKey '+str(stage/'public-0.pub') in text
    assert 'Include '+str(stage/'config-1')+' '+str(stage/'config-3') in text
    assert 'Include '+str(stage/'config-2') in (stage/'config-1').read_text()
    assert (stage/'config-2').read_bytes() == b'KexAlgorithms curve25519-sha256\n'
    assert (stage/'config-3').read_bytes() == b'Ciphers aes256-ctr\n'
    assert 'Match Address 192.0.2.0/24\nPasswordAuthentication no' in text
    assert marker.stat().st_atime_ns == before
    for path in stage.iterdir():
        assert path.stat().st_mode & 0o777 == 0o600
        assert b'DUMMY-PRIVATE-KEY-SENTINEL' not in path.read_bytes()
    assert b'DUMMY-COMMENT' not in (stage/'public-0.pub').read_bytes()
    assert H['parse_public']((stage/'public-0.pub').read_bytes()) == H['parse_public'](public()[0])


@pytest.mark.parametrize('problem', ['include', 'user-match', 'agent', 'command', 'unknown', 'no-global-key',
                                      'late-key', 'key-symlink', 'include-symlink', 'cycle', 'key-invalid'])
def test_r2_unsafe_closure_rejected_before_capture(tmp_path, monkeypatch, problem):
    root = tmp_path/'fixture'
    native_fixture(root)
    config = root/'etc/ssh/sshd_config'
    raw = config.read_text()
    if problem == 'include': put(config, raw.replace('/etc/ssh/sshd_config.d/*.conf', '/outside.conf'))
    if problem == 'user-match': put(config, raw.replace('Match Address 192.0.2.0/24', 'Match User fixture_user'))
    if problem == 'agent': put(config, raw+'HostKeyAgent /tmp/agent.sock\n')
    if problem == 'command': put(config, raw+'AuthorizedKeysCommand /usr/bin/true\n')
    if problem == 'unknown': put(config, raw+'UnknownDirective yes\n')
    if problem == 'no-global-key': put(config, raw.split('\n',1)[1])
    if problem == 'late-key': put(config, raw.split('\n',1)[1]+raw.split('\n',1)[0]+'\n')
    if problem == 'key-symlink':
        key = root/'etc/ssh/ssh_host_ed25519_key.pub'; key.unlink(); key.symlink_to(root/'etc/ssh/ssh_host_ed25519_key')
    if problem == 'include-symlink':
        inc = root/'etc/ssh/sshd_config.d/20-last.conf'; inc.unlink(); inc.symlink_to(config)
    if problem == 'cycle': put(root/'etc/ssh/sshd_config.d/20-last.conf', 'Include /etc/ssh/sshd_config.d/*.conf\n')
    if problem == 'key-invalid': put(root/'etc/ssh/ssh_host_ed25519_key.pub', b'DUMMY INVALID PUBLIC\n')
    # The qualification gate is changed in this isolated unit-test namespace
    # only, to exercise the future path. No real sshd process is allowed.
    monkeypatch.setitem(H, 'NATIVE_T_QUALIFIED', True)
    monkeypatch.setitem(H, 'capture', lambda *a, **kw: pytest.fail('unsafe closure reached child'))
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        r = H['evaluate_native_t'](fd, {'context_ref': 'global-default', 'context_spec': None})
    finally:
        os.close(fd)
    assert r['state'] in ('UNKNOWN', 'ERROR', 'PERMISSION_DENIED') and not r['rows']
    assert r['reason'] in ('NATIVE_SOURCE_REJECTED', 'SOURCE_PERMISSION', 'SOURCE_DRIFT', 'SOURCE_LIMIT')
    ssh.validate_snapshot(snapshot(**{'native-0': r}))


def test_r2_native_unqualified_zero_child_or_source_reads(monkeypatch):
    assert H['NATIVE_T_QUALIFIED'] is ssh.NATIVE_T_QUALIFIED is False
    monkeypatch.setitem(H, 'tool_error', lambda path: None)
    monkeypatch.setitem(H, 'prepare_native', lambda *a: pytest.fail('unqualified source read'))
    monkeypatch.setitem(H, 'capture', lambda *a, **kw: pytest.fail('unqualified child'))
    assert H['run_slot']('native-0', dict(context_ref=NATIVE_CTX, context_spec=NATIVE_SPEC)) == H['result']('UNKNOWN', 'NATIVE_SAFETY_UNPROVEN')
    assert H['evaluate_native_t'](-1, {}) == H['result']('UNKNOWN', 'NATIVE_SAFETY_UNPROVEN')


@pytest.mark.parametrize('reason', [None, 'TIMEOUT', 'OUTPUT_LIMIT', 'CLEANUP_FAILED'])
def test_r2_native_t_candidate_fixed_capture_and_cleanup(tmp_path, monkeypatch, reason):
    root = tmp_path/'fixture'; native_fixture(root)
    stages = []
    monkeypatch.setitem(H, 'NATIVE_T_QUALIFIED', True)
    def fake_capture(argv, seconds):
        # Unit test boundary only: this output is synthetic, no sshd executed.
        assert 0 < seconds <= 23
        assert argv[:3] == ['/usr/sbin/sshd', '-T', '-f'] and argv[4] == '-C' and len(argv) == 6
        assert argv[-1].startswith('user=fixture_user,host=fixture.example.invalid,')
        stage = Path(argv[3]).parent
        assert stage.stat().st_mode & 0o777 == 0o700
        assert all(p.stat().st_mode & 0o777 == 0o600 for p in stage.iterdir())
        stages.append(stage)
        return reason, 0 if reason is None else -9, EFFECTIVE_FIXTURE, b''
    monkeypatch.setitem(H, 'capture', fake_capture)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        r = H['evaluate_native_t'](fd, {'context_ref': NATIVE_CTX, 'context_spec': NATIVE_SPEC})
    finally:
        os.close(fd)
    assert len(stages) == 1 and not stages[0].exists()
    if reason is None:
        assert r == effective('T')
    else:
        assert r['state'] == 'ERROR' and r['reason'] == reason and not r['rows']
    ssh.validate_snapshot(snapshot(**{'native-0': r}))


def development_g_argv(path, ref, spec):
    # Test-only G path. No runtime switch or fallback in the product helper.
    argv = H['native_argv'](str(path), ref, spec)
    return [argv[0], '-G', *argv[2:]]


def test_r2_development_g_argv_separate():
    assert development_g_argv('/tmp/fixture/config-0', 'global-default', None) == [
        '/usr/sbin/sshd', '-G', '-f', '/tmp/fixture/config-0']
    assert development_g_argv('/tmp/fixture/config-0', NATIVE_CTX, NATIVE_SPEC)[4] == '-C'
    assert H['native_argv']('/tmp/fixture/config-0', NATIVE_CTX, NATIVE_SPEC)[1] == '-T'


def test_r2_actual_development_g_control(tmp_path):
    # Requires an actual qualified G execution environment. Do not make mere
    # executable presence, non-root or the network guard a safety proof.
    if H['tool_error']('/usr/sbin/sshd'):
        pytest.skip('Development -G/-G -C: fixed sshd unavailable')
    # Current QA evidence explicitly fails outside-file/exec negative controls.
    # An independently qualified exact G environment is required before this
    # test-only constant is changed. Never change the production T gate for G.
    development_g_qualified = False
    if not development_g_qualified:
        pytest.skip('Development -G/-G -C: native safety qualification unavailable')
    root, stage = tmp_path/'fixture', tmp_path/'stage'
    stage.mkdir(mode=0o700)
    native_fixture(root)
    main = prepare_fixture(root, stage)
    for ref, spec, password in [('global-default', None, b'passwordauthentication yes'),
                                (NATIVE_CTX, NATIVE_SPEC, b'passwordauthentication no')]:
        reason, rc, out, err = H['capture'](development_g_argv(main, ref, spec))
        assert reason is None and rc == 0 and not err
        assert password in out.lower().splitlines()
        r = effective('G', out, rc, err)
        assert r['state'] == 'COLLECTED'
        d, detail = norm(snapshot(contexts=[ref], **{'native-0': r}))
        ssh.validate_details(assessment.evaluate_document(d, RULES), detail, RULES)



def test_r2_context_rejected_before_source_or_child(monkeypatch):
    monkeypatch.setitem(H, 'NATIVE_T_QUALIFIED', True)
    monkeypatch.setitem(H, 'prepare_native', lambda *a: pytest.fail('invalid context source read'))
    monkeypatch.setitem(H, 'capture', lambda *a, **kw: pytest.fail('invalid context child'))
    assert H['evaluate_native_t'](-1, {'context_ref': NATIVE_CTX, 'context_spec': dict(NATIVE_SPEC, user='-G')}) == H['result']('UNKNOWN', 'NATIVE_CONTEXT_REJECTED')


def test_r2_stage_cleanup_failure_discards_native_result(tmp_path, monkeypatch):
    root = tmp_path/'fixture'; native_fixture(root)
    monkeypatch.setitem(H, 'NATIVE_T_QUALIFIED', True)
    real = H['tempfile'].TemporaryDirectory
    stages = []
    class FailingCleanup:
        def __init__(self, **options):
            self.inner = real(**options)
            self.name = self.inner.name
            stages.append(Path(self.name))
        def cleanup(self):
            self.inner.cleanup()
            raise OSError('synthetic cleanup failure')
    monkeypatch.setattr(H['tempfile'], 'TemporaryDirectory', FailingCleanup)
    monkeypatch.setitem(H, 'capture', lambda *a, **kw: (None, 0, EFFECTIVE_FIXTURE, b''))
    monkeypatch.setitem(H, 'parse_effective', lambda *a: pytest.fail('cleanup failure reached parser'))
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        r = H['evaluate_native_t'](fd, {'context_ref': 'global-default', 'context_spec': None})
    finally:
        os.close(fd)
    assert r == H['result']('ERROR', 'CLEANUP_FAILED', 0) and len(stages) == 1 and not stages[0].exists()
    ssh.validate_snapshot(snapshot(**{'native-0': r}))
