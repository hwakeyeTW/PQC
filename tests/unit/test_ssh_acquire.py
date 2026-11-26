"""SSH S1 fixed file acquisition, native packaging and bounded local cleanup.

All filesystem inputs are anonymous fixtures; never execute a valid stage
against the product's fixed real root in these tests.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import ssh_posture as original

COLL = ROOT / 'ansible_collections/security/compliance_pqc_readiness'
MODULE = COLL / 'plugins/modules/pqc_ssh_acquire.py'
MIRROR = ROOT / 'plugins/modules/pqc_ssh_acquire.py'
HELPER = ROOT / 'plugins/module_utils/pqc_bounded_execution.py'
FQCN = 'security.compliance_pqc_readiness.pqc_ssh_acquire'
BASE_PYTHON = os.path.abspath(sys._base_executable)


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


acq = _load('ssh_acquisition_test', MODULE)
helper = _load('ssh_bounded_test', HELPER)
legacy = _load('ssh_posture_fixture', ROOT / 'tests/unit/test_ssh_posture.py')
PACKAGE = '''import sys,json
from pathlib import Path
from ansible.plugins.loader import init_plugin_loader, module_loader
from ansible.executor.module_common import modify_module
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar
init_plugin_loader()
name,source,dest,args=sys.argv[1:]
ctx=module_loader.find_plugin_with_context(name)
assert ctx.resolved and Path(ctx.plugin_resolved_path).resolve()==Path(source).resolve()
v={'ansible_python_interpreter':sys._base_executable,'ansible_playbook_python':sys.executable}
b=modify_module(module_name=ctx.resolved_fqcn,module_path=ctx.plugin_resolved_path,
    module_args=json.loads(args),templar=Templar(loader=DataLoader(),variables=v),task_vars=v,remote_is_local=False)
assert b.module_style=='new'
Path(dest).write_bytes(b.b_module_data)
'''


def _private(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def _root(tmp, *, populated=True):
    root = _private(tmp / 'fixture-root')
    _private(root / 'etc/ssh')
    if populated:
        legacy.make_fixture(root)
    for path in root.rglob('*'):
        if path.is_dir():
            path.chmod(0o700)
    return root


def _replace(source, old, new):
    assert source.count(old) == 1
    return source.replace(old, new)


def _fixture(tmp, root, *, fqcn=False, inner=23, outer=28, patch=None, exact=False):
    assert 0.5 <= inner <= 23 and 0.5 <= outer <= 28
    source = MODULE.read_text()
    if not exact:
        for a, b in (("ROOT_DIRECTORY = '/'", 'ROOT_DIRECTORY = ' + repr(str(root))),
                     ('_TRUSTED_UID = 0', '_TRUSTED_UID = ' + str(os.geteuid())),
                     ('INNER_SECONDS = 23', 'INNER_SECONDS = ' + repr(inner)),
                     ('STAGE_SECONDS = 28', 'STAGE_SECONDS = ' + repr(outer))):
            source = _replace(source, a, b)
        if patch:
            source = patch(source)
    collection_root = _private(tmp / 'collections')
    if fqcn:
        parent = _private(collection_root / 'ansible_collections/security/compliance_pqc_readiness/plugins/modules')
        h = parent.parent / 'module_utils' / HELPER.name
        _private(h.parent)
        shutil.copyfile(HELPER, h)
    else:
        parent = _private(tmp / 'library')
    candidate = parent / MODULE.name
    candidate.write_text(source)
    candidate.chmod(0o600)
    return candidate, collection_root, FQCN if fqcn else MODULE.stem


def _package(tmp, stage, fixture, **extra):
    candidate, collection_root, name = fixture
    _private(tmp)
    cfg = tmp / 'ansible.cfg'
    cfg.write_text('[defaults]\nhost_key_checking=True\nretry_files_enabled=False\nfact_caching=memory\n')
    env = dict(PATH=str(Path(sys.executable).parent) + ':/usr/bin:/bin', HOME=str(_private(tmp / 'home')),
               TMPDIR=str(_private(tmp / 'tmp')), LC_ALL='C.UTF-8', ANSIBLE_CONFIG=str(cfg),
               ANSIBLE_LIBRARY=str(candidate.parent), ANSIBLE_MODULE_UTILS=str(HELPER.parent),
               ANSIBLE_COLLECTIONS_PATH=str(collection_root), ANSIBLE_COLLECTIONS_SCAN_SYS_PATH='false',
               ANSIBLE_LOCAL_TEMP=str(_private(tmp / 'local')), ANSIBLE_REMOTE_TEMP=str(_private(tmp / 'remote')),
               ANSIBLE_NOCOLOR='1')
    dest = tmp / 'AnsiballZ_ssh.py'
    args = dict(stage=stage, _ansible_no_log=True, _ansible_check_mode=True) | extra
    p = subprocess.run([sys.executable, '-I', '-B', '-c', PACKAGE, name, str(candidate), str(dest), json.dumps(args)],
                       cwd=tmp, env=env, capture_output=True, timeout=20)
    assert p.returncode == 0, p.stderr.decode(errors='replace')
    dest.chmod(0o600)
    return dest, env


def _argv(pack):
    return [BASE_PYTHON, '-I', '-B', str(pack[0])]


def _invoke(pack, stage, *, fail=False):
    start = time.monotonic()
    p = subprocess.run(_argv(pack), cwd=pack[0].parent, env=pack[1], capture_output=True, timeout=32)
    assert len(p.stdout) + len(p.stderr) <= acq.WRAPPER_BYTES
    if fail:
        assert p.returncode != 0 and b'"receipt"' not in p.stdout
        return None
    assert p.returncode == 0 and not p.stderr, (p.returncode, p.stdout[:300], p.stderr[:300])
    outer = json.loads(p.stdout)
    assert set(outer) == {'changed', 'receipt', 'invocation'} and outer['changed'] is False
    assert outer['invocation'] == {'module_args': {'stage': stage}}
    receipt = acq.validate_receipt(outer['receipt'], stage)
    assert len(p.stdout) == acq._wrapper_size(receipt)
    print('NATIVE_FRAME', stage, len(acq.canonical(receipt)), len(p.stdout), flush=True)
    return receipt, time.monotonic() - start


def _slot(receipt):
    assert (receipt['reason_code'], receipt['rc'], receipt['cleanup_confirmed']) == ('COMMAND_OK', 0, True)
    return receipt['payload']


def _valid_original(stage, slot):
    data = legacy.snapshot(**{stage: slot})
    if stage == 'config' and slot['reason'] in original.HALT_REASONS:
        for name in ('keys', 'native-0'):
            data['slots'][name] = acq.result('UNKNOWN', 'ACQUISITION_STOPPED')
    elif stage == 'keys' and slot['reason'] in original.HALT_REASONS:
        data['slots']['native-0'] = acq.result('UNKNOWN', 'ACQUISITION_STOPPED')
    original.validate_snapshot(data)


def test_mirror_and_fixed_contract():
    assert MODULE.read_bytes() == MIRROR.read_bytes()
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o644 for p in (MODULE, MIRROR))
    assert HELPER.read_bytes() == (COLL / 'plugins/module_utils' / HELPER.name).read_bytes()
    assert acq.STAGES == ('config', 'keys') and acq.ROOT_DIRECTORY == '/' and acq._TRUSTED_UID == 0
    assert not acq.NATIVE_Q_QUALIFIED and not acq.NATIVE_T_QUALIFIED
    assert acq.INNER_SECONDS == 23 and acq.STAGE_SECONDS == 28
    assert acq.SLOT_BYTES == 262144 and acq.CHILD_BYTES == 262145 and acq.WIRE_BYTES == 1048576
    assert acq.RECEIPT_BYTES < acq.WRAPPER_BYTES < acq.WIRE_BYTES
    assert helper.OUTPUT_BYTES == 16384 and helper._POLICY_OUTPUT_BYTES == 65537
    for bad in ('client-kex', 'native-0', 'native-1', '-T', '-G', '-Q', '/', None, True):
        with pytest.raises(ValueError):
            acq._stage(bad)


@pytest.mark.parametrize('fqcn', [False, True], ids=['short', 'fqcn'])
def test_native_fixed_config_and_keys(tmp_path, fqcn):
    assert os.geteuid() != 0
    root = _root(tmp_path)
    secret = legacy.put(root / 'etc/ssh/ssh_host_ed25519_key', b'PRIVATE-NAME-SENTINEL')
    outside = legacy.put(tmp_path / 'outside', b'ESCAPE-SENTINEL')
    with (root / 'etc/ssh/sshd_config').open('a') as f:
        f.write('Include ' + str(outside) + '\nHostKey ' + str(outside) + '\n')
    for p in (secret, outside):
        os.utime(p, ns=(1000000000, 1000000000))
    fixture = _fixture(tmp_path / 'candidate', root, fqcn=fqcn)
    result = {}
    for stage in acq.STAGES:
        row = _slot(_invoke(_package(tmp_path / stage, stage, fixture), stage)[0])
        assert row == legacy.read_fixture(root, stage)
        _valid_original(stage, row)
        result[stage] = row
    assert {'INCLUDE_REJECTED', 'HOSTKEY_PATH_REJECTED'} <= set(result['config']['gaps'])
    data, detail = legacy.norm(legacy.snapshot(**result))
    assert len(data['assets']) == 1 and len(data['assets'][0]['evidence_ids']) == 2
    assert not data['claims']
    assert b'DUMMY-' not in acq.canonical(detail) and b'SENTINEL' not in acq.canonical(result)
    assert secret.stat().st_atime_ns == outside.stat().st_atime_ns == 1000000000
    # Package exact product bytes too, but invoke only a rejected request.
    exact = _fixture(tmp_path / 'exact', root, fqcn=fqcn, exact=True)
    assert exact[0].read_bytes() == MODULE.read_bytes()
    _invoke(_package(tmp_path / 'bad-stage', 'native-0', exact), 'native-0', fail=True)
    _invoke(_package(tmp_path / 'bad-root', 'config', exact, root=str(root), path=str(outside),
                     argv=['/fixture'], context='fixture'), 'config', fail=True)


@pytest.mark.parametrize('stage', acq.STAGES)
def test_native_missing_permission_and_unsafe(tmp_path, stage):
    root = _root(tmp_path, populated=False)
    directory = root / 'etc/ssh'
    path = directory / ('sshd_config' if stage == 'config' else 'ssh_host_ed25519_key.pub')
    data = b'Ciphers aes256-ctr\n' if stage == 'config' else legacy.public()[0]
    fixture = _fixture(tmp_path / 'candidate', root)
    pack = _package(tmp_path / 'native', stage, fixture)
    def check(state, reason):
        row = _slot(_invoke(pack, stage)[0])
        assert row == acq.result(state, reason)
        _valid_original(stage, row)
    directory.rmdir()
    check('UNKNOWN', 'SOURCE_MISSING')
    _private(directory)
    if stage == 'keys':
        check('COLLECTED', 'OK')
    else:
        check('UNKNOWN', 'SOURCE_MISSING')
    legacy.put(path, data).chmod(0)
    try:
        check('PERMISSION_DENIED', 'SOURCE_PERMISSION')
    finally:
        path.chmod(0o600)
    path.chmod(0o622)
    check('UNKNOWN', 'SOURCE_UNSAFE')
    path.unlink()
    secret = legacy.put(tmp_path / 'secret', b'PRIVATE-ESCAPE-SENTINEL')
    os.utime(secret, ns=(1000000000, 1000000000))
    path.symlink_to(secret)
    check('UNKNOWN', 'SOURCE_UNSAFE')
    path.unlink()
    os.link(secret, path)
    check('UNKNOWN', 'SOURCE_UNSAFE')
    path.unlink()
    os.mkfifo(path, 0o600)
    check('UNKNOWN', 'SOURCE_UNSAFE')
    path.unlink()
    assert secret.stat().st_atime_ns == 1000000000
    legacy.put(path, b'-----BEGIN OPENSSH PRIVATE KEY-----\nDUMMY\n')
    check('UNKNOWN', 'SOURCE_UNSAFE' if stage == 'config' else 'KEY_INVALID')
    legacy.put(path, b'x' * (acq.LIMIT + 1))
    check('ERROR', 'INPUT_LIMIT')
    legacy.put(path, data)
    directory.chmod(0o722)
    try:
        check('UNKNOWN', 'SOURCE_UNSAFE')
    finally:
        directory.chmod(0o700)


def test_fixed_reader_trust_drift_and_limits(tmp_path, monkeypatch):
    root = _root(tmp_path)
    monkeypatch.setattr(acq, '_TRUSTED_UID', os.geteuid())
    monkeypatch.setattr(acq, 'ROOT_DIRECTORY', str(root))
    main = root / 'etc/ssh/sshd_config'
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with acq.Reader(fd, 65536, 'config') as reader:
            for name in ('ssh_host_ed25519_key', 'ssh_host_ed25519_key.pub', '../shadow'):
                with pytest.raises(acq.ReadFailure, match='SOURCE_UNSAFE'):
                    reader.read(('etc', 'ssh'), name)
            reader.read(('etc', 'ssh'), 'sshd_config')
            legacy.put(main, 'Ciphers changed\n')
            with pytest.raises(acq.LimitFailure, match='SOURCE_DRIFT'):
                reader.verify()
        with acq.Reader(fd, 524288, 'keys') as reader:
            with pytest.raises(acq.ReadFailure, match='SOURCE_UNSAFE'):
                reader.read(('etc', 'ssh'), 'sshd_config')
        monkeypatch.setattr(acq, '_TRUSTED_UID', 0)
        with pytest.raises(acq.ReadFailure, match='SOURCE_UNSAFE'):
            acq.Reader(fd, 65536, 'config')
        monkeypatch.setattr(acq, '_TRUSTED_UID', os.geteuid())
    finally:
        os.close(fd)
    legacy.put(main, 'Include /etc/ssh/sshd_config.d/*.conf\n')
    drop = main.parent / 'sshd_config.d'
    for p in drop.iterdir():
        p.unlink()
    for i in range(32):
        legacy.put(drop / ('f%02d.conf' % i), '# fixture\n')
    assert acq._acquire('config') == acq.result('ERROR', 'SOURCE_LIMIT')
    for p in drop.iterdir():
        p.unlink()
    for i in range(257):
        legacy.put(drop / ('f%03d.conf' % i), '# fixture\n')
    assert acq._acquire('config') == acq.result('ERROR', 'DIRECTORY_LIMIT')
    for p in drop.iterdir():
        p.unlink()
    for i in range(4):
        legacy.put(drop / ('f%02d.conf' % i), 'Include sshd_config.d/*.conf\n')
    assert acq._acquire('config') == acq.result('ERROR', 'SOURCE_LIMIT')
    for i in range(4):
        legacy.put(drop / ('f%02d.conf' % i), b'#' * 16384)
    assert acq._acquire('config') == acq.result('ERROR', 'INPUT_LIMIT')
    legacy.put(main, 'Ciphers ' + ','.join('a%d' % i for i in range(257)) + '\n')
    assert acq._acquire('config') == acq.result('ERROR', 'ROW_LIMIT')
    legacy.put(main, 'Ciphers a\n' * 513)
    assert acq._acquire('config') == acq.result('ERROR', 'ROW_LIMIT')
    for i in range(31):
        legacy.put(main.parent / ('ssh_host_extra%d_key.pub' % i), legacy.public()[0])
    assert acq._acquire('keys') == acq.result('ERROR', 'SOURCE_LIMIT')
    monkeypatch.setattr(acq, 'INNER_SECONDS', 0)
    assert acq._acquire('config') == acq.result('ERROR', 'TIMEOUT')


def test_public_layout_and_unknown_gap(tmp_path, monkeypatch):
    root = _root(tmp_path, populated=False)
    monkeypatch.setattr(acq, '_TRUSTED_UID', os.geteuid())
    monkeypatch.setattr(acq, 'ROOT_DIRECTORY', str(root))
    field = legacy.field
    cases = [('ssh-rsa', field(b'\x01\x00\x01') + field(b'\x00\x80' + b'x' * 255)),
             ('ssh-dss', field(b'\x01') * 4), ('ecdsa-sha2-nistp256', field('nistp256') + field(b'\x04' + b'x' * 64)),
             ('ssh-unknown-fixture', field(b'opaque'))]
    for i, (name, body) in enumerate(cases):
        raw, _ = legacy.public(name, body)
        assert acq.parse_public(raw) == legacy.H['parse_public'](raw)
        legacy.put(root / ('etc/ssh/ssh_host_fixture%d_key.pub' % i), raw)
    result = acq._acquire('keys')
    assert result == legacy.read_fixture(root, 'keys')
    assert result['state'] == 'PARTIAL' and result['gaps'] == ['KEY_TYPE_UNKNOWN']
    _valid_original('keys', result)


def test_native_large_actual_config(tmp_path):
    root = _root(tmp_path, populated=False)
    main = legacy.put(root / 'etc/ssh/sshd_config', 'Ciphers aes256-ctr\n' * 511)
    assert main.stat().st_size < acq.LIMIT
    receipt, _ = _invoke(_package(tmp_path / 'native', 'config', _fixture(tmp_path, root, fqcn=True)), 'config')
    row = _slot(receipt)
    assert row == legacy.read_fixture(root, 'config') and len(row['rows']) == 512
    assert 65536 < len(acq.canonical(row)) <= acq.SLOT_BYTES
    _valid_original('config', row)


def _sized_slot(size):
    src = acq.digest('src', ['ssh-config-v1', ['etc', 'ssh'], 'sshd_config'])
    main = dict(kind='SOURCE', order=0, source_ref=src, line=0, context_ref='global-default',
                source_kind='MAIN', parent_ref=None, include_line=None, depth=0)
    rows = [main] + [dict(kind='DIRECTIVE', order=i, source_ref=src, line=i, context_ref='global-default',
                          setting='ciphers', operator='EXACT', values=['a']) for i in range(1, 10)]
    slot = acq.result('COLLECTED', 'OK', rows=rows)
    remaining = size - len(acq.canonical(slot))
    for row in rows[1:]:
        for j in range(255):
            if remaining < 4:
                rows[1]['values'][0] += 'z' * remaining
                remaining = 0
                break
            token = ('b%03d' % j) + 'x' * 124
            token = token[:min(128, remaining - 3)]
            row['values'].append(token)
            remaining -= len(token) + 3
        if remaining == 0:
            break
    assert remaining == 0 and len(acq.canonical(slot)) == size
    return slot


@pytest.mark.parametrize('delta', [0, 1])
def test_native_complete_slot_capacity(tmp_path, delta):
    # This is a serializer stress fixture, not a claim that the raw-file limits
    # can generate every validator-legal shape. The actual large read is separate.
    row = _sized_slot(acq.SLOT_BYTES + delta)
    if not delta:
        _valid_original('config', row)
    else:
        with pytest.raises(original.ev.EvidenceError, match='SSH_PROJECTION_LIMIT'):
            _valid_original('config', row)
    root = _root(tmp_path, populated=False)
    def patch(source):
        return _replace(source, 'def _acquire(stage):\n', 'def _acquire(stage):\n    return ' + repr(row) + '\n')
    fixture = _fixture(tmp_path / 'candidate', root, patch=patch)
    actual = _slot(_invoke(_package(tmp_path / 'native', 'config', fixture), 'config')[0])
    assert actual == (acq.result('ERROR', 'OUTPUT_LIMIT') if delta else row)
    _valid_original('config', actual)


def test_closed_receipt_and_cleanup_fail_closed():
    row = acq.result('COLLECTED', 'OK')
    good = acq._receipt('keys', 'COMMAND_OK', 0, True, row)
    assert acq.validate_receipt(good, 'keys') == good
    for bad in (good | {'format': True}, good | {'rc': True}, good | {'cleanup_confirmed': False},
                good | {'stage': 'config'}, good | {'extra': 1}, good | {'payload': row | {'rc': 0}},
                good | {'payload': row | {'rows': [{'private': 'DUMMY'}]}}, good | {'reason_code': 'COMMAND_TIMEOUT'}):
        with pytest.raises(ValueError):
            acq.validate_receipt(bad, 'keys')
    for raw in (b'{"x":1,"x":2}\n', b'{"x":NaN}\n', b'{"x":1.0}\n', b'{}', b'{}\n\n', b'x' * (acq.CHILD_BYTES + 1)):
        with pytest.raises(ValueError):
            acq._decode(raw)
    for reason in ('PROCESS_CONTROL_UNAVAILABLE', 'REMOTE_CLEANUP_UNCONFIRMED'):
        r = acq._from_result('keys', helper.CommandResult(reason, None, b'', b'', False))
        assert r['payload'] is None and r['cleanup_confirmed'] is False
        with pytest.raises(ValueError):
            acq._from_result('keys', helper.CommandResult(reason, None, acq.canonical(row)+b'\n', b'', False))
    with pytest.raises(ValueError):
        acq._from_result('keys', helper.CommandResult('COMMAND_OK', 0, acq.canonical(row)+b'\n', b'', False))
    with pytest.raises(ValueError):
        acq._from_result('keys', helper.CommandResult('COMMAND_OK', 0, acq.canonical(row)+b'\n', b'bad', True))


def test_native_child_output_limit(tmp_path):
    root = _root(tmp_path)
    def patch(source):
        return _replace(source, 'def _child(stage):\n',
                        'def _child(stage):\n    sys.stdout.buffer.write(b"x" * (CHILD_BYTES + 1))\n    return\n')
    fixture = _fixture(tmp_path, root, outer=3, patch=patch)
    receipt, elapsed = _invoke(_package(tmp_path / 'native', 'config', fixture), 'config')
    assert receipt['reason_code'] == 'COMMAND_OUTPUT_LIMIT' and receipt['payload'] is None
    assert receipt['cleanup_confirmed'] is True and elapsed < 4


def test_native_inner_timeout(tmp_path):
    root = _root(tmp_path)
    def patch(source):
        return _replace(source, 'def collect_config(root):\n', 'def collect_config(root):\n    time.sleep(60)\n')
    fixture = _fixture(tmp_path, root, inner=0.6, outer=3, patch=patch)
    receipt, elapsed = _invoke(_package(tmp_path / 'native', 'config', fixture), 'config')
    assert _slot(receipt) == acq.result('ERROR', 'TIMEOUT') and elapsed < 4
    _valid_original('config', receipt['payload'])


@pytest.mark.parametrize('kind', ['timeout', 'interrupt'])
def test_native_outer_process_group_cleanup(tmp_path, kind):
    root = _root(tmp_path)
    witness = tmp_path / 'witness.json'
    def patch(source):
        injection = ('def _child(stage):\n    signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
                     '    child = os.fork()\n    if child == 0:\n        time.sleep(60)\n        os._exit(0)\n'
                     '    with open(' + repr(str(witness)) + ', "w") as f:\n'
                     '        json.dump(dict(pids=[os.getpid(),child],pgid=os.getpgrp(),uid=os.geteuid()),f)\n'
                     '    time.sleep(60)\n')
        return _replace(source, 'def _child(stage):\n', injection)
    fixture = _fixture(tmp_path, root, outer=2.5, patch=patch)
    pack = _package(tmp_path / 'native', 'config', fixture)
    if kind == 'timeout':
        receipt, elapsed = _invoke(pack, 'config')
        assert receipt['reason_code'] == 'COMMAND_TIMEOUT' and elapsed < 4
    else:
        start = time.monotonic()
        with subprocess.Popen(_argv(pack), cwd=pack[0].parent, env=pack[1], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as p:
            while not witness.exists() and time.monotonic() - start < 1.5:
                time.sleep(.01)
            assert witness.exists()
            p.send_signal(signal.SIGTERM)
            out, err = p.communicate(timeout=5)
            assert p.returncode == 0 and not err
            receipt = acq.validate_receipt(json.loads(out)['receipt'], 'config')
            assert receipt['reason_code'] == 'INTERRUPTED'
        assert time.monotonic() - start < 5
    assert receipt['cleanup_confirmed'] and receipt['payload'] is None
    row = json.loads(witness.read_bytes())
    assert row['uid'] == os.geteuid() != 0
    for pid in row['pids']:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
    with pytest.raises(ProcessLookupError):
        os.killpg(row['pgid'], 0)
