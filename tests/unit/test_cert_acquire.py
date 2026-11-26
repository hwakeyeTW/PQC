"""Cert S1 native wrapper, fixed reader, and local owned-process controls.

All valid module acquisitions use a private, code-only synthetic root seam.
Exact product bytes are also packaged, but only rejected requests are invoked.
Never acquire the actual system certificate roots in these engineering tests.
"""
import copy
import hashlib
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
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
COLL = ROOT / 'ansible_collections/security/compliance_pqc_readiness'
MODULE = COLL / 'plugins/modules/pqc_cert_acquire.py'
MIRROR = ROOT / 'plugins/modules/pqc_cert_acquire.py'
HELPER = ROOT / 'plugins/module_utils/pqc_bounded_execution.py'
ROLE = ROOT / 'roles/pqc_platform_crypto/tasks/cert_assets.yml'
FQCN = 'security.compliance_pqc_readiness.pqc_cert_acquire'
BASE_PYTHON = '/usr/bin/python3'


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


acq = _load('cert_acquisition_test', MODULE)
helper = _load('cert_bounded_test', HELPER)
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
v={'ansible_python_interpreter':'/usr/bin/python3','ansible_playbook_python':sys.executable}
b=modify_module(module_name=ctx.resolved_fqcn,module_path=ctx.plugin_resolved_path,
    module_args=json.loads(args),templar=Templar(loader=DataLoader(),variables=v),task_vars=v,remote_is_local=False)
assert b.module_style=='new'
Path(dest).write_bytes(b.b_module_data)
'''


def _private(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def _root(tmp):
    root = _private(tmp / 'fixture-root')
    for path in acq.ROOTS.values():
        _private(root / path.lstrip('/'))
    return root


def _loc(root, name='system-tls-certs'):
    return root / acq.ROOTS[name].lstrip('/')


def _replace(source, old, new):
    assert source.count(old) == 1, old
    return source.replace(old, new)


def _fixture(tmp, root, *, fqcn=False, exact=False, patch=None):
    source = MODULE.read_text()
    if not exact:
        source = _replace(source, "ROOT_DIRECTORY = '/'", 'ROOT_DIRECTORY = ' + repr(str(root)))
        source = _replace(source, '_TRUSTED_UID = 0', '_TRUSTED_UID = ' + str(os.geteuid()))
        if patch:
            source = patch(source)
    collection_root = _private(tmp / 'collections')
    if fqcn:
        parent = _private(collection_root / 'ansible_collections/security/compliance_pqc_readiness/plugins/modules')
        dest = parent.parent / 'module_utils' / HELPER.name
        _private(dest.parent)
        shutil.copyfile(HELPER, dest)
    else:
        parent = _private(tmp / 'library')
    candidate = parent / MODULE.name
    candidate.write_text(source)
    candidate.chmod(0o600)
    return candidate, collection_root, FQCN if fqcn else MODULE.stem


def _package(tmp, fixture, stage='system', **extra):
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
    dest = tmp / 'AnsiballZ_cert.py'
    args = dict(stage=stage, _ansible_no_log=True, _ansible_check_mode=True) | extra
    p = subprocess.run([sys.executable, '-I', '-B', '-c', PACKAGE, name, str(candidate), str(dest), json.dumps(args)],
                       cwd=tmp, env=env, capture_output=True, timeout=20)
    assert p.returncode == 0, p.stderr.decode(errors='replace')
    dest.chmod(0o600)
    return dest, env


def _invoke(pack, *, fail=False):
    start = time.monotonic()
    p = subprocess.run([BASE_PYTHON, '-I', '-B', str(pack[0])], cwd=pack[0].parent,
                       env=pack[1], capture_output=True, timeout=32)
    assert len(p.stdout) + len(p.stderr) <= acq.WRAPPER_BYTES
    if fail:
        assert p.returncode != 0 and b'"receipt"' not in p.stdout
        return None
    assert p.returncode == 0 and not p.stderr, (p.returncode, p.stdout[:300], p.stderr[:300])
    outer = json.loads(p.stdout)
    assert set(outer) == {'changed', 'receipt', 'invocation'} and outer['changed'] is False
    assert outer['invocation'] == {'module_args': {'stage': 'system'}}
    receipt = acq.validate_receipt(outer['receipt'], 'system')
    assert len(p.stdout) == acq._wrapper_size(receipt)
    print('NATIVE_FRAME', len(acq.canonical(receipt)), len(p.stdout), flush=True)
    return receipt, time.monotonic() - start


def _payload(receipt):
    assert (receipt['reason_code'], receipt['rc'], receipt['cleanup_confirmed']) == ('COMMAND_OK', 0, True)
    assert receipt['payload']['system_python_available'] is True
    return receipt['payload']


@pytest.fixture(scope='module')
def certs(tmp_path_factory):
    p = _private(tmp_path_factory.mktemp('public-fixture'))
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'OPENSSL_CONF': '/dev/null', 'HOME': str(p)}
    def cli(*args, data=None):
        return subprocess.run(['/usr/bin/openssl', *args], input=data, cwd=p, env=env,
                              capture_output=True, timeout=10, check=True).stdout
    results = {}
    try:
        for name, key, dn in (('rsa', 'rsa:2048', '/CN=fixture-rsa.example.invalid'),
                              ('ec', 'ec', '/CN=fixture-ec.example.invalid'),
                              ('unsafe', 'ec', '/CN={{FIXTURE_SENTINEL}}')):
            params = ['-pkeyopt', 'ec_paramgen_curve:prime256v1'] if key == 'ec' else []
            cli('req', '-x509', '-newkey', key, *params, '-nodes', '-keyout', name + '.key',
                '-out', name + '.pem', '-days', '1', '-subj', dn)
            pem = (p / (name + '.pem')).read_bytes()
            der = cli('x509', '-inform', 'PEM', '-outform', 'DER', data=pem)
            results[name] = (pem, der, hashlib.sha256(der).hexdigest())
        return results
    finally:
        for pth in p.glob('*.key'):
            pth.unlink()


def _legacy(root):
    # Exact #18 role helper; only the synthetic root trust seam is changed.
    role = yaml.safe_load(ROLE.read_text())[0]
    ns = {'__name__': '_legacy_fixture'}
    exec(compile(role['block'][4]['ansible.builtin.command']['argv'][8], '<reviewed-helper>', 'exec'), ns)
    ns['trusted'] = lambda st: st.st_uid == os.geteuid() and not st.st_mode & 0o022
    fd = os.open(root, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return ns['Reader'](fd, time.monotonic() + 23).collect()
    finally:
        os.close(fd)


def _source(roots, name, slot='system-tls-certs'):
    sid = acq.source_id(acq.ROOTS[slot] + '/' + name)
    return next(s for s in roots[slot]['sources'] if s['source_id'] == sid)


def _observations(roots):
    return [b['certificate'] for row in roots.values() for s in row['sources'] for b in s['blocks'] if b['certificate']]


def test_mirror_fixed_contract():
    assert os.geteuid() != 0
    assert MODULE.read_bytes() == MIRROR.read_bytes()
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o644 for p in (MODULE, MIRROR))
    assert HELPER.read_bytes() == (COLL / 'plugins/module_utils' / HELPER.name).read_bytes()
    assert acq.STAGES == ('system',) and acq.ROOT_DIRECTORY == '/' and acq._TRUSTED_UID == 0
    assert (acq.WORK_SECONDS, acq.ALARM_SECONDS, acq.STAGE_SECONDS) == (23, 25, 29)
    assert (acq.PARSE_SECONDS, acq.CLEANUP_SECONDS, acq.MAX_OUTPUT) == (3.5, 1, 16384)
    assert (acq.MAX_PROJECTION, acq.METADATA_BUDGET, acq.CHILD_BYTES, acq.RECEIPT_BYTES, acq.WRAPPER_BYTES) == (196608, 131072, 196609, 196707, 393411)
    assert acq._trusted_executable('/usr/bin/python3', alias=True)
    assert acq._trusted_executable('/usr/bin/openssl', alias=False)
    for bad in ('/', 'nginx', 'config', True, None, ['system']):
        with pytest.raises(ValueError):
            acq._stage(bad)


@pytest.mark.parametrize('fqcn', [False, True], ids=['short', 'fqcn'])
def test_native_actual_public_and_rejected_args(tmp_path, certs, fqcn):
    root = _root(tmp_path)
    q = _loc(root)
    (q / 'a.pem').write_bytes(certs['rsa'][0])
    (q / 'b.der').write_bytes(certs['ec'][1])
    (q / 'c.crt').write_bytes(certs['rsa'][0] + certs['ec'][0])
    (q / 'd.pem').write_bytes(certs['unsafe'][0])
    expected = _legacy(root)
    fixture = _fixture(tmp_path / 'candidate', root, fqcn=fqcn)
    receipt, elapsed = _invoke(_package(tmp_path / 'native', fixture))
    roots = _payload(receipt)['roots']
    assert roots == expected
    assert elapsed < 29 and len(_observations(roots)) == 5
    assert {c['fingerprint'] for c in _observations(roots)} == {v[2] for v in certs.values()}
    assert _source(roots, 'd.pem')['blocks'][0]['certificate']['subject'] is None
    assert b'FIXTURE_SENTINEL' not in acq.canonical(roots)
    (q / 'z-alias.pem').symlink_to('a.pem')
    roots = _payload(_invoke(_package(tmp_path / 'alias', fixture))[0])['roots']
    assert _source(roots, 'a.pem')['target_id'] == _source(roots, 'z-alias.pem')['target_id']
    assert len(_observations(roots)) == 6
    exact = _fixture(tmp_path / 'exact', root, fqcn=fqcn, exact=True)
    assert exact[0].read_bytes() == MODULE.read_bytes()
    _invoke(_package(tmp_path / 'bad-stage', exact, stage='nginx'), fail=True)
    _invoke(_package(tmp_path / 'bad-root', exact, root=str(root), path=str(q), argv=['fixture']), fail=True)


def test_native_private_and_outside_are_not_disclosed(tmp_path, certs):
    root = _root(tmp_path)
    q = _loc(root)
    outside = tmp_path / 'outside.pem'
    outside.write_bytes(b'OUTSIDE_SENTINEL')
    os.utime(outside, ns=(1000000000, 1000000000))
    (q / 'escape.pem').symlink_to(outside)
    os.link(outside, q / 'hardlink.pem')
    os.mkfifo(q / 'fifo.pem', 0o600)
    (q / 'secret.pem').write_bytes(b'-----BEGIN PRIVATE KEY-----\n' + b'PRIVATE_SENTINEL' * 10000)
    (q / 'bad.der').write_bytes(certs['rsa'][1] + b'X')
    (q / 'aux.pem').write_bytes(b'-----BEGIN TRUSTED CERTIFICATE-----\nBAD\n')
    (q / 'mixed.pem').write_bytes(certs['rsa'][0] + b'-----BEGIN PRIVATE KEY-----\nPRIVATE_SENTINEL\n' + certs['ec'][0])
    denied = q / 'denied.pem'
    denied.write_bytes(certs['rsa'][0]); denied.chmod(0)
    try:
        roots = _payload(_invoke(_package(tmp_path / 'native', _fixture(tmp_path, root)))[0])['roots']
    finally:
        denied.chmod(0o600)
    for name in ('escape.pem', 'hardlink.pem', 'fifo.pem'):
        assert _source(roots, name)['gaps'] == ['UNSAFE_SOURCE']
    assert _source(roots, 'secret.pem')['gaps'] == ['NON_PUBLIC_BLOCK']
    assert _source(roots, 'aux.pem')['gaps'] == ['UNSUPPORTED_TRUSTED_CERTIFICATE']
    assert _source(roots, 'bad.der')['blocks'][0]['reason'] == 'INVALID_DER'
    assert _source(roots, 'denied.pem')['gaps'] == ['PERMISSION_DENIED']
    assert len(_observations(roots)) == 1
    assert b'SENTINEL' not in acq.canonical(roots) and outside.stat().st_atime_ns == 1000000000


def test_fixed_tool_preflight_zero_acquisition(tmp_path):
    root = _root(tmp_path)
    for tool, expected in (('_SYSTEM_PYTHON', 'TOOL_UNAVAILABLE'), ('_OPENSSL', 'COMMAND_START_FAILED')):
        def patch(s):
            old = "_SYSTEM_PYTHON = '/usr/bin/python3'" if tool == '_SYSTEM_PYTHON' else "_OPENSSL = '/usr/bin/openssl'"
            return _replace(s, old, tool + " = '/usr/bin/pqc-nonexistent-fixture-tool'")
        receipt, _ = _invoke(_package(tmp_path / tool, _fixture(tmp_path / (tool + '-src'), root, patch=patch)))
        assert receipt['reason_code'] == expected and receipt['rc'] is None and receipt['cleanup_confirmed']
        assert receipt['payload'] == (acq._python_unavailable() if tool == '_SYSTEM_PYTHON' else None)


def _sized_payload(size):
    roots = {k: acq.empty() for k in acq.ROOTS}
    for k in roots:
        roots[k]['root_target_id'] = acq.source_id(acq.ROOTS[k])
    row = roots['system-tls-certs']
    row['entries'] = 128
    certs = []
    for i in range(128):
        blocks = []
        for j in range(2):
            c = dict(fingerprint=hashlib.sha256(('fixture-%d-%d' % (i, j)).encode()).hexdigest(),
                     public_key_algorithm='rsaEncryption', public_key_bits=2048,
                     signature_inner='sha256WithRSAEncryption', signature_outer='sha256WithRSAEncryption',
                     issuer='CN=a', subject='CN=b', not_before='2026-01-01T00:00:00Z',
                     not_after='2026-01-02T00:00:00Z', gaps=[])
            certs.append(c)
            blocks.append(dict(rc=0, reason='OK', certificate=c))
        sid = acq.source_id(acq.ROOTS['system-tls-certs'] + '/fixture-%03d.pem' % i)
        row['sources'].append(dict(source_id=sid, target_id=sid, format='PEM', gaps=[], blocks=blocks))
    row['sources'].sort(key=lambda x: x['source_id'])
    payload = dict(system_python_available=True, roots=roots)
    remaining = size - len(acq.canonical(payload))
    assert remaining >= 0
    for c in certs:
        for k in ('subject', 'issuer'):
            n = min(remaining, 512 - len(c[k]))
            c[k] += 'a' * n
            remaining -= n
    assert remaining == 0 and len(acq.canonical(payload)) == size
    return payload


@pytest.mark.parametrize('delta', [0, 1])
def test_native_payload_exact_plus_one(tmp_path, delta):
    data = _sized_payload(acq.MAX_PROJECTION + delta)
    if delta:
        with pytest.raises(ValueError):
            acq._decode(acq.canonical(data) + b'\n')
    else:
        assert acq._decode(acq.canonical(data) + b'\n') == data
        assert len(acq.canonical(acq._receipt('system', 'COMMAND_OK', 0, True, data))) == acq.RECEIPT_BYTES
    def patch(s):
        return _replace(s, 'def _acquire(deadline):\n', 'def _acquire(deadline):\n    return ' + repr(data['roots']) + '\n')
    receipt, _ = _invoke(_package(tmp_path / 'native', _fixture(tmp_path, _root(tmp_path), patch=patch)))
    result = _payload(receipt)
    assert result == (dict(system_python_available=True, roots=acq._error_roots('PROJECTION_LIMIT')) if delta else data)


def test_closed_receipt_and_invalid_raw():
    roots = acq._error_roots('TIMEOUT')
    good = acq._receipt('system', 'COMMAND_OK', 0, True, dict(system_python_available=True, roots=roots))
    assert acq.validate_receipt(good, 'system') == good
    for bad in (good | {'format': True}, good | {'rc': True}, good | {'cleanup_confirmed': False},
                good | {'stage': 'nginx'}, good | {'extra': 1}, good | {'payload': acq._python_unavailable()},
                good | {'reason_code': 'COMMAND_FAILED'}, good | {'payload': {'system_python_available': True, 'roots': acq._error_roots('CLEANUP_FAILED')}}):
        with pytest.raises(ValueError):
            acq.validate_receipt(bad, 'system')
    for raw in (b'{"x":1,"x":2}\n', b'{"x":NaN}\n', b'{"x":1.0}\n', b'{}', b'{}\n\n', b'x' * (acq.CHILD_BYTES + 1)):
        with pytest.raises(ValueError):
            acq._decode(raw)
    for clean in (True, False):
        result = acq._from_result('system', helper.CommandResult('COMMAND_FAILED' if clean else 'REMOTE_CLEANUP_UNCONFIRMED', 70, b'', b'', clean))
        assert result == acq._receipt('system', 'REMOTE_CLEANUP_UNCONFIRMED', 70, False, None)


def _capture_control(tmp, program, *, deadline=.4, fault=False):
    # The actual outer runner supplies the unique process group. No test child
    # can acquire a real root; it exercises the exact candidate capture code.
    script = '''import importlib.util,json,os,signal,sys,time
spec=importlib.util.spec_from_file_location('fixture_cert',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert os.getpid()==os.getpgrp()
if sys.argv[4]=='1': m.reap=lambda *a: False
for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM): signal.signal(sig,m._interrupt)
try:
 rc,raw,why=m.capture(['/usr/bin/python3','-I','-B','-c',sys.argv[2]],b'',time.monotonic()+float(sys.argv[3]))
except m.Fault as e:
 rc,raw,why=None,None,e.reason
print(json.dumps(dict(rc=rc,size=None if raw is None else len(raw),reason=why,uncertain=m._cleanup_uncertain,pgid=os.getpgrp())))
'''
    result = helper._run_bounded([sys.executable, '-I', '-B', '-c', script, str(MODULE), program, str(deadline), str(int(fault))], 4, 16384)
    assert result.reason_code == 'COMMAND_OK' and result.cleanup_confirmed and not result.stderr
    actual = json.loads(result.stdout)
    with pytest.raises(ProcessLookupError):
        os.killpg(actual['pgid'], 0)
    return actual


@pytest.mark.parametrize('program,why,size', [
    ("import os;os.write(1,b'x'*16384)", None, 16384),
    ("import os;os.write(1,b'x'*16385)", 'OUTPUT_LIMIT', None),
    ("import os;os.write(2,b'x'*16385)", 'OUTPUT_LIMIT', None),
    ("import os;os.write(1,b'x'*9000);os.write(2,b'x'*9000)", 'OUTPUT_LIMIT', None),
    ("import time;time.sleep(10)", 'TIMEOUT', None)])
def test_actual_capture_bounds(tmp_path, program, why, size):
    actual = _capture_control(tmp_path, program)
    assert actual['reason'] == why and actual['size'] == size and actual['uncertain'] is False


def test_actual_adopted_residue_is_reaped_and_fatal(tmp_path):
    witness = tmp_path / 'pid'
    # Handshake: the adopted child records its identity before the direct
    # parent exits. No race with TERM before the witness is complete.
    program = ('import os,time;rd,wr=os.pipe();pid=os.fork();\n'
               'if pid:\n os.close(wr);assert os.read(rd,1)==b"x";os.close(rd);os._exit(0)\n'
               'os.close(rd);os.close(0);os.close(1);os.close(2);\n'
               'with open(' + repr(str(witness)) + ',"w") as f: f.write(str(os.getpid()))\n'
               'os.write(wr,b"x");os.close(wr);time.sleep(10)')
    actual = _capture_control(tmp_path, program, deadline=1)
    assert actual['reason'] == 'CLEANUP_FAILED' and actual['uncertain'] is True and actual['size'] is None
    assert witness.is_file()
    with pytest.raises(ProcessLookupError):
        os.kill(int(witness.read_text()), 0)


def test_native_sticky_cleanup_failure_stops_after_actual_parse(tmp_path, certs):
    root = _root(tmp_path)
    for i in range(3):
        (_loc(root) / ('cert-%d.pem' % i)).write_bytes(certs['rsa'][0])
    # Actual x509 capture on the first block, then fault-injected cleanup
    # uncertainty. A later read/parse is forbidden; child marker must dominate.
    witness = tmp_path / 'cleanup-witness'
    def patch(s):
        s = _replace(s, 'def reap(proc, terminate):\n',
                     'def reap(proc, terminate):\n    proc.wait(timeout=0.1)\n'
                     '    with open(' + repr(str(witness)) + ',"w") as f: f.write("actual-parse-complete")\n    return False\n')
        for sig in ('    def read_at(self, fd, offset, size):\n', '    def pin(self, p, root=False):\n',
                    '    def parse_block(self, der):\n'):
            s = _replace(s, sig, sig + '        assert not os.path.exists(' + repr(str(witness)) + '), "continued after cleanup failure"\n')
        return s
    receipt, _ = _invoke(_package(tmp_path / 'native', _fixture(tmp_path, root, patch=patch)))
    assert receipt == acq._receipt('system', 'REMOTE_CLEANUP_UNCONFIRMED', 70, False, None)
    assert witness.read_text() == 'actual-parse-complete'


def _wait_for_witness(witness, timeout=2):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if witness.is_file() and witness.stat().st_size:
            try:
                return json.loads(witness.read_text())
            except (ValueError, OSError):
                pass
        time.sleep(.01)
    pytest.fail('synthetic process witness missing')


def _absent(witness):
    for pid in witness['pids']:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)
    with pytest.raises(ProcessLookupError):
        os.killpg(witness['pgid'], 0)


@pytest.mark.parametrize('kind', ['timeout', 'interrupt', 'parent-loss', 'residual'])
def test_native_actual_group_cleanup(tmp_path, kind):
    # Code-only fixture: real fixed capture/outer runner, synthetic child only.
    # No product invocation ever selects arbitrary commands or real roots.
    root = _root(tmp_path)
    witness = tmp_path / 'process.json'
    write = 'with open(' + repr(str(witness)) + ',"w") as f: json.dump(dict(pids=[os.getppid(),os.getpid()],pgid=os.getpgrp()),f)\n'
    if kind == 'residual':
        program = ('import os,signal,time,json;rd,wr=os.pipe();pid=os.fork()\n'
                   'if pid:\n os.close(wr);assert os.read(rd,1)==b"x";os.close(rd);os._exit(0)\n'
                   'os.close(rd);signal.signal(signal.SIGTERM,signal.SIG_IGN);os.close(0);os.close(1);os.close(2)\n'
                   + write + 'os.write(wr,b"x");os.close(wr);time.sleep(60)')
    else:
        program = 'import os,signal,time,json\n' + write + ('os.kill(os.getppid(),signal.SIGKILL)\n' if kind == 'parent-loss' else '') + 'time.sleep(60)'
    def patch(s):
        body = ('def _acquire(deadline):\n'
                '    rc,raw,why=capture([_SYSTEM_PYTHON,"-I","-B","-c",' + repr(program) + '],b"",time.monotonic()+10)\n'
                '    if _cleanup_uncertain: fail("CLEANUP_FAILED")\n'
                '    return _error_roots(why or "COMMAND_FAILED")\n')
        s = _replace(s, 'def _acquire(deadline):\n', body)
        if kind == 'timeout':
            s = _replace(s, 'WORK_SECONDS, ALARM_SECONDS, STAGE_SECONDS = 23, 25, 29',
                         'WORK_SECONDS, ALARM_SECONDS, STAGE_SECONDS = 23, 25, 3')
        return s
    pack = _package(tmp_path / 'native', _fixture(tmp_path / 'candidate', root, patch=patch))
    if kind == 'interrupt':
        with subprocess.Popen([BASE_PYTHON,'-I','-B',str(pack[0])], cwd=pack[0].parent, env=pack[1],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
            seen = _wait_for_witness(witness)
            proc.send_signal(signal.SIGTERM)
            out, err = proc.communicate(timeout=5)
            assert proc.returncode == 0 and not err
        receipt = acq.validate_receipt(json.loads(out)['receipt'], 'system')
        assert receipt['reason_code'] == 'INTERRUPTED' and receipt['cleanup_confirmed'] is True
    else:
        receipt, elapsed = _invoke(pack)
        seen = _wait_for_witness(witness)
        assert elapsed < 5
        if kind == 'timeout':
            assert receipt['reason_code'] == 'COMMAND_TIMEOUT' and receipt['cleanup_confirmed'] is True
        elif kind == 'parent-loss':
            assert receipt['reason_code'] in ('COMMAND_FAILED','RESIDUAL_PROCESS') and receipt['rc'] == -9 and receipt['cleanup_confirmed'] is True
        else:
            assert receipt == acq._receipt('system','REMOTE_CLEANUP_UNCONFIRMED',70,False,None)
    assert receipt['payload'] is None
    _absent(seen)


@pytest.mark.parametrize('stream', [1, 2])
def test_native_child_output_limit(tmp_path, stream):
    def patch(s):
        return _replace(s, 'def _child(stage):\n', 'def _child(stage):\n    os.write(' + str(stream) + ',b"x"*(CHILD_BYTES+1))\n    return\n')
    receipt, _ = _invoke(_package(tmp_path / 'native', _fixture(tmp_path / 'candidate', _root(tmp_path), patch=patch)))
    assert receipt['reason_code'] == 'COMMAND_OUTPUT_LIMIT' and receipt['payload'] is None and receipt['cleanup_confirmed'] is True


def test_actual_metadata_soft_budget(tmp_path, certs):
    from tools import cert_assets as original
    root = _root(tmp_path)
    for i in range(128):
        (_loc(root) / ('chain-%03d.pem' % i)).write_bytes(certs['rsa'][0] + certs['ec'][0])
    payload = _payload(_invoke(_package(tmp_path / 'native', _fixture(tmp_path / 'candidate', root)))[0])
    roots = payload['roots']; original.validate_snapshot(roots)
    row = roots['system-tls-certs']
    assert row['entries'] == 128 and len(row['sources']) == 128
    assert sum(len(s['blocks']) for s in row['sources']) == 256
    assert 0 < len(_observations(roots)) < 256
    assert any('PROJECTION_LIMIT' in s['gaps'] for s in row['sources'])
    assert len(acq.canonical(payload)) <= acq.MAX_PROJECTION


def test_native_signature_conflict_and_scope_gaps(tmp_path, certs):
    from tools import cert_assets as original
    root = _root(tmp_path)
    _loc(root, 'system-ca-anchors').rmdir()
    q = _loc(root)
    der = certs['rsa'][1]
    oid = bytes.fromhex('06092a864886f70d01010b')
    assert der.count(oid) == 2
    at = der.rfind(oid) + len(oid) - 1
    changed = der[:at] + b'\x0c' + der[at+1:]
    (q / 'conflict.der').write_bytes(changed)
    with (q / 'too-big.pem').open('wb') as f:
        f.truncate(acq.MAX_FILE + 1)
    (q / 'a/b/c/d').mkdir(parents=True)
    roots = _payload(_invoke(_package(tmp_path / 'native', _fixture(tmp_path, root)))[0])['roots']
    original.validate_snapshot(roots)
    assert roots == _legacy(root)
    row = _source(roots, 'conflict.der')['blocks'][0]
    if row['certificate'] is not None:
        cert = row['certificate']
        assert cert['fingerprint'] == hashlib.sha256(changed).hexdigest()
        assert cert['signature_inner'] != cert['signature_outer'] and 'SIGNATURE_CONFLICT' in cert['gaps']
    else:
        assert row['reason'] != 'OK'
    assert 'LIMIT_REACHED' in _source(roots, 'too-big.pem')['gaps']
    assert 'DEPTH_LIMIT' in roots['system-tls-certs']['gaps']
    assert roots['system-ca-anchors']['gaps'] == ['SOURCE_ABSENT']
    assert original.root_status(roots['system-ca-anchors'])[0] == 'UNKNOWN'
    assert original.root_status(roots['system-ssl-certs'])[0] == 'COLLECTED'


def test_native_drift_keeps_count_and_rc(tmp_path, certs):
    from tools import cert_assets as original
    root = _root(tmp_path)
    f = _loc(root) / 'drift.pem'
    f.write_bytes(certs['rsa'][0])
    def patch(s):
        old = '            row = parse(der, self.deadline)\n'
        return _replace(s, old, old + '            with open(' + repr(str(f)) + ',"wb") as stream: stream.write(b"fixture-drift")\n')
    roots = _payload(_invoke(_package(tmp_path / 'native', _fixture(tmp_path, root, patch=patch)))[0])['roots']
    original.validate_snapshot(roots)
    row = _source(roots, 'drift.pem')
    assert row['gaps'] == ['SOURCE_CHANGED'] and len(row['blocks']) == 1
    assert row['blocks'][0]['rc'] == 0 and row['blocks'][0]['certificate'] is None


def test_original_controller_actual_oracle(tmp_path, certs):
    # The actual unchanged controller validator/normalizer and legacy test
    # fixture are mandatory, not a mocked or reimplemented acceptance oracle.
    from tools import assessment, cert_assets as ca
    legacy = _load('certificate_legacy_test', ROOT / 'tests/unit/test_cert_assets.py')
    root = _root(tmp_path)
    (_loc(root) / 'chain.pem').write_bytes(certs['rsa'][0] + certs['ec'][0])
    (_loc(root) / 'duplicate.der').write_bytes(certs['ec'][1])
    (_loc(root) / 'invalid.cer').write_bytes(b'invalid')
    native = _payload(_invoke(_package(tmp_path / 'native', _fixture(tmp_path, root)))[0])['roots']
    expected = _legacy(root)
    ca.validate_snapshot(native)
    assert native == expected
    rules = assessment.load_rules((ROOT / 'config/assessment_rules.yml').read_bytes())
    doc = legacy.doc()
    result = legacy.build(doc, native, rules)
    assert result == legacy.build(doc, expected, rules)
    ca.validate_cert_details(legacy.merged(doc, result), result['details'], rules)
    for delta in (0, 1):
        ca.validate_snapshot(_sized_payload(acq.MAX_PROJECTION + delta)['roots'])
