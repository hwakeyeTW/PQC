"""O1 fixed native acquisition: isolated local packages and anonymous fixtures.

No managed host, network endpoint, installed RPM, or real inventory is used.
Fixture copies replace only fixed executable literals and narrow deadlines.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
COLLECTION = ROOT / 'ansible_collections/security/compliance_pqc_readiness'
MODULE = COLLECTION / 'plugins/modules/pqc_openssl_acquire.py'
MIRROR = ROOT / 'plugins/modules/pqc_openssl_acquire.py'
HELPER = ROOT / 'plugins/module_utils/pqc_bounded_execution.py'
SPEC = importlib.util.spec_from_file_location('pqc_openssl_acquisition_test', MODULE)
acquire = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acquire)
BASE_PYTHON = os.path.abspath(sys._base_executable)
FQCN = 'security.compliance_pqc_readiness.pqc_openssl_acquire'
SHORT = 'pqc_openssl_acquire'
PACKAGE = '''import sys
from pathlib import Path
from ansible.plugins.loader import init_plugin_loader, module_loader
from ansible.executor.module_common import modify_module
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar
init_plugin_loader()
name, source, dest, args = sys.argv[1:]
import json
context = module_loader.find_plugin_with_context(name)
assert context.resolved and Path(context.plugin_resolved_path).resolve() == Path(source).resolve()
variables = {'ansible_python_interpreter': sys._base_executable, 'ansible_playbook_python': sys.executable}
built = modify_module(module_name=context.resolved_fqcn, module_path=context.plugin_resolved_path,
    module_args=json.loads(args), templar=Templar(loader=DataLoader(), variables=variables),
    task_vars=variables, remote_is_local=False)
assert built.module_style == 'new'
Path(dest).write_bytes(built.b_module_data)
'''


def _private(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _env(tmp, library):
    home = _private(tmp / 'home')
    config = tmp / 'ansible.cfg'
    config.write_text('[defaults]\nhost_key_checking = True\nretry_files_enabled = False\n')
    return dict(PATH=str(Path(sys.executable).parent) + ':/usr/bin:/bin', HOME=str(home),
                TMPDIR=str(_private(tmp / 'tmp')), LC_ALL='C.UTF-8', ANSIBLE_CONFIG=str(config),
                ANSIBLE_LIBRARY=str(library), ANSIBLE_MODULE_UTILS=str(HELPER.parent),
                ANSIBLE_COLLECTIONS_PATH=str(ROOT), ANSIBLE_COLLECTIONS_SCAN_SYS_PATH='false',
                ANSIBLE_LOCAL_TEMP=str(_private(tmp / 'local')), ANSIBLE_REMOTE_TEMP=str(_private(tmp / 'remote')),
                ANSIBLE_HOST_KEY_CHECKING='true', ANSIBLE_NOCOLOR='1')


def _package(tmp, stage, source=MIRROR, name=SHORT, **extra):
    env = _env(tmp, source.parent)
    wrapper = tmp / ('AnsiballZ_' + stage + '.py')
    args = dict(stage=stage, _ansible_no_log=True, _ansible_check_mode=True) | extra
    proc = subprocess.run([sys.executable, '-I', '-B', '-c', PACKAGE, name, str(source), str(wrapper), json.dumps(args)],
                          cwd=tmp, env=env, capture_output=True, timeout=20)
    assert proc.returncode == 0, proc.stderr.decode(errors='replace')
    wrapper.chmod(0o600)
    return wrapper, env


def _invoke(pack, stage, *, failure=False):
    path, env = pack
    start = time.monotonic()
    proc = subprocess.run([BASE_PYTHON, '-I', '-B', str(path)], cwd=path.parent, env=env,
                          capture_output=True, timeout=34)
    elapsed = time.monotonic() - start
    assert len(proc.stdout) <= acquire.WRAPPER_BYTES
    if failure:
        assert proc.returncode != 0 and b'"receipt"' not in proc.stdout
        return None, elapsed
    assert proc.returncode == 0 and not proc.stderr, (proc.returncode, 'native wrapper failed')
    result = json.loads(proc.stdout)
    assert result['changed'] is False
    receipt = acquire.validate_receipt(result['receipt'], stage)
    assert len(acquire._json_bytes(receipt)) <= acquire.OUTPUT_BYTES
    return receipt, elapsed


def _script(executable, code, mode=0o700):
    executable.write_text('#!' + BASE_PYTHON + ' -I\nimport os,sys,time,signal,json\n' + code + '\n')
    executable.chmod(mode)


def _fixed_fixture(tmp, *, outer=30, inner=27):
    executable = tmp / 'fixed-query-fixture'
    library = _private(tmp / 'library')
    source = MODULE.read_text()
    for literal in ("RPM_EXECUTABLE = '/usr/bin/rpm'", "OPENSSL_EXECUTABLE = '/usr/bin/openssl'"):
        assert source.count(literal) == 1
        source = source.replace(literal, literal.split(' = ')[0] + ' = ' + repr(str(executable)))
    assert 0.5 <= outer <= 30 and 0.5 <= inner <= 27
    source = source.replace('STAGE_SECONDS = 30', 'STAGE_SECONDS = ' + repr(outer))
    source = source.replace('INNER_SECONDS = 27', 'INNER_SECONDS = ' + repr(inner))
    candidate = library / MODULE.name
    candidate.write_text(source)
    candidate.chmod(0o644)
    return executable, candidate


def _reply(exe, stdout=b'', stderr=b'', rc=0):
    _script(exe, f'os.write(1,{stdout!r});os.write(2,{stderr!r});sys.exit({rc})')


def _payload(receipt, state, reason, rc, rows=None):
    assert receipt['reason_code'] == 'COMMAND_OK' and receipt['rc'] == 0 and receipt['cleanup_confirmed'] is True
    actual = receipt['payload']
    assert (actual['state'], actual['reason'], actual['rc']) == (state, reason, rc)
    if rows is not None:
        assert actual['rows'] == rows
    return actual


@pytest.mark.parametrize('stage', ['version', 'providers', 'kem', 'signature', 'tls-groups'])
def test_actual_short_fqcn_openssl(tmp_path, stage):
    if not Path('/usr/bin/openssl').is_file() or not os.access('/usr/bin/openssl', os.X_OK):
        pytest.skip('fixed local OpenSSL unavailable')
    bare = subprocess.run([BASE_PYTHON, '-I', '-S', '-c',
        "import importlib.util; assert importlib.util.find_spec('ansible') is None"], timeout=5)
    assert bare.returncode == 0
    short, _ = _invoke(_package(_private(tmp_path / 'short'), stage), stage)
    fqcn, _ = _invoke(_package(_private(tmp_path / 'fqcn'), stage, MODULE, FQCN), stage)
    assert short == fqcn and short['reason_code'] == 'COMMAND_OK' and short['cleanup_confirmed']
    if stage == 'version':
        assert short['payload']['state'] == 'COLLECTED' and short['payload']['rc'] == 0


@pytest.fixture(scope='module')
def packs(tmp_path_factory):
    tmp = _private(tmp_path_factory.mktemp('openssl-acquisition'))
    executable, candidate = _fixed_fixture(tmp)
    result = {stage: _package(_private(tmp / stage), stage, candidate) for stage in acquire.STAGES}
    return executable, result


VALID = {
    'rpm-openssl': (b'openssl\t3.5.5\t1.el9\tx86_64\n', [['openssl', '3.5.5', '1.el9', 'x86_64']]),
    'rpm-openssl-libs': (b'openssl-libs\t3.5.5\t1.el9\tx86_64\n', [['openssl-libs', '3.5.5', '1.el9', 'x86_64']]),
    'version': (b'OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026)\n', [['3.5.5', '3.5.5']]),
    'providers': (b'Providers:\n  default\n    version: 3.5.5\n    status: active\n', [['default', '3.5.5', 'active']]),
    'kem': (b'KEM Algorithms:\n  { 2.16.840.1.101.3.4.4.2, ML-KEM-768, MLKEM768 } @ default\n', [['default', ['2.16.840.1.101.3.4.4.2', 'ML-KEM-768', 'MLKEM768']]]),
    'signature': (b'Provided:\n ML-DSA-44 @ default\n', [['default', ['ML-DSA-44']]]),
    'tls-groups': (b'x25519:X25519MLKEM768\n', [[None, ['X25519MLKEM768']], [None, ['x25519']]]),
}


@pytest.mark.parametrize('stage', acquire.STAGES)
def test_actual_fixed_commands(packs, stage):
    exe, packaged = packs
    raw, rows = VALID[stage]
    argv = acquire.COMMANDS[stage][1:]
    _script(exe, f'assert sys.argv[1:] == {list(argv)!r};assert os.getcwd()=="/";'
                 'assert os.environ["LC_ALL"]=="C" and os.environ["PATH"]=="/usr/bin:/bin";'
                 'assert not set(os.environ).intersection({"OPENSSL_CONF","OPENSSL_MODULES","HOME","SSH_AUTH_SOCK"});'
                 f'os.write(1,{raw!r})')
    receipt, elapsed = _invoke(packaged[stage], stage)
    _payload(receipt, 'COLLECTED', 'OK', 0, rows)
    assert elapsed < 30


@pytest.mark.parametrize('stage,out,err,rc,state,reason,rows', [
    ('rpm-openssl', b'package openssl is not installed\n', b'', 1, 'COLLECTED', 'PACKAGE_ABSENT', [['openssl', None, None, None]]),
    ('rpm-openssl-libs', b'', b'package openssl-libs is not installed\n', 1, 'COLLECTED', 'PACKAGE_ABSENT', [['openssl-libs', None, None, None]]),
    ('rpm-openssl', b'package openssl-libs is not installed\n', b'', 1, 'ERROR', 'COMMAND_FAILED', []),
    ('rpm-openssl', b'package openssl is not installed\n', b'lock failed', 1, 'ERROR', 'COMMAND_FAILED', []),
    ('rpm-openssl', b'', b'Permission denied', 1, 'PERMISSION_DENIED', 'PERMISSION_DENIED', []),
    ('version', b'OpenSSL 1.1.1k  FIPS 25 Mar 2021\n', b'', 0, 'COLLECTED', 'OK', [['1.1.1k', None]]),
    ('version', b'LibreSSL 3.4.1\n', b'', 0, 'UNKNOWN', 'UNRECOGNIZED_OUTPUT', []),
    ('version', b'OpenSSL 3.5.5', b'', 0, 'ERROR', 'INCOMPLETE_OUTPUT', []),
    ('providers', b'Providers:\n  default\n    version: 3.5.5\n', b'', 0, 'PARTIAL', 'FORMAT_GAP', [['default', '3.5.5', None]]),
    ('providers', b'Providers:\n  default\n  default\n    version: 3.5.5\n    status: active\n', b'', 0, 'UNKNOWN', 'UNRECOGNIZED_OUTPUT', []),
    ('kem', b'ML-KEM-768 @ default\n', b'list: Unknown option: -kem-algorithms\n', 1, 'UNKNOWN', 'UNSUPPORTED_FLAG', []),
    ('signature', b'ML-DSA-44 @ default\n', b'provider failure', 0, 'ERROR', 'COMMAND_FAILED', []),
    ('kem', b'{ ML-KEM-768, bad alias } @ default\nML-KEM-512 @ default\n', b'', 0, 'PARTIAL', 'FORMAT_GAP', [['default', ['ML-KEM-512']]]),
    ('signature', b'{ ML-DSA-44, ML-DSA-65, bad alias } @ default\n', b'', 0, 'UNKNOWN', 'UNRECOGNIZED_OUTPUT', []),
    ('kem', b'{ ML-KEM-768, ML-KEM-768 } @ default\n', b'', 0, 'PARTIAL', 'FORMAT_GAP', [['default', ['ML-KEM-768']]]),
    ('kem', b'ML-KEM-768 @ default\nML-KEM-768 @ default\n', b'', 0, 'PARTIAL', 'FORMAT_GAP', [['default', ['ML-KEM-768']]]),
    ('kem', b'future-algorithm @ default\n', b'', 0, 'COLLECTED', 'OK', [['default', ['future-algorithm']]]),
    ('tls-groups', b'x25519:\n', b'', 0, 'UNKNOWN', 'UNRECOGNIZED_OUTPUT', []),
    ('tls-groups', b'', b'', 0, 'UNKNOWN', 'NO_OUTPUT', []),
    ('signature', b'\xff\n', b'', 0, 'ERROR', 'INVALID_ENCODING', []),
])
def test_native_original_grammar(packs, stage, out, err, rc, state, reason, rows):
    exe, packaged = packs
    _reply(exe, out, err, rc)
    receipt, _ = _invoke(packaged[stage], stage)
    _payload(receipt, state, reason, rc, rows)


@pytest.mark.parametrize('stage,raw,reason', [
    ('rpm-openssl', b'openssl\t3.5.5\t1.el9\tx86_64\n'*33, 'ROW_LIMIT'),
    ('kem', b'ML-KEM-768 @ default\n'*257, 'ROW_LIMIT'),
    ('signature', ('{ '+', '.join(['ML-DSA-44']*33)+' } @ default\n').encode(), 'ROW_LIMIT'),
    ('tls-groups', (':'.join('G%03d'%i+'x'*55 for i in range(256))+'\n').encode(), 'OUTPUT_LIMIT'),
])
def test_typed_and_row_caps(packs, stage, raw, reason):
    exe, packaged = packs
    assert len(raw) <= acquire.OUTPUT_BYTES
    _reply(exe, raw)
    receipt, _ = _invoke(packaged[stage], stage)
    _payload(receipt, 'ERROR', reason, 0, [])


def test_combined_raw_output_cap(packs):
    exe, packaged = packs
    _reply(exe, b'x'*9000, b'y'*9000)
    receipt, _ = _invoke(packaged['kem'], 'kem')
    assert receipt['payload']['reason'] == 'OUTPUT_LIMIT'
    _payload(receipt, 'ERROR', 'OUTPUT_LIMIT', receipt['payload']['rc'], [])
    assert type(receipt['payload']['rc']) is int


@pytest.mark.parametrize('kind', ['missing', 'non-executable', 'symlink', 'directory'])
def test_regular_executable_boundary(packs, tmp_path, kind):
    exe, packaged = packs
    if exe.exists() or exe.is_symlink():
        exe.unlink()
    if kind == 'non-executable':
        _script(exe, 'raise AssertionError("must not run")', 0o600)
    elif kind == 'symlink':
        target = tmp_path / 'other'
        _script(target, 'raise AssertionError("must not run")')
        exe.symlink_to(target)
    elif kind == 'directory':
        exe.mkdir()
    try:
        receipt, _ = _invoke(packaged['version'], 'version')
        _payload(receipt, 'UNKNOWN', 'TOOL_UNAVAILABLE', None, [])
    finally:
        if exe.is_symlink() or exe.is_file():
            exe.unlink()
        elif exe.is_dir():
            exe.rmdir()


def _witness(exe, path, *, residual=False, late=False, fork=True):
    code = 'signal.signal(signal.SIGTERM,signal.SIG_IGN)\n'
    if fork:
        code += 'child=os.fork()\nif child==0:\n'
        code += '    os.close(1);os.close(2)\n' if residual else ''
        code += '    time.sleep(60);os._exit(0)\n'
    code += f'with open({str(path)!r},"w") as f: json.dump(dict(pids=[os.getpid()'+(',child' if fork else '')+'],pgid=os.getpgrp(),uid=os.geteuid()),f)\n'
    if residual or late:
        code += 'print("ML-KEM-768 @ default",flush=True)\n'
    if not residual:
        code += 'time.sleep(60)\n'
    _script(exe, code)


def _group_gone(witness):
    data = json.loads(witness.read_bytes())
    assert data['uid'] == os.geteuid() != 0
    with pytest.raises(ProcessLookupError):
        os.killpg(data['pgid'], 0)
    for pid in data['pids']:
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)


@pytest.fixture(scope='module')
def bounded(tmp_path_factory):
    tmp = _private(tmp_path_factory.mktemp('openssl-bounded'))
    exe, source = _fixed_fixture(tmp, outer=2, inner=27)
    return tmp, exe, _package(_private(tmp/'native'), 'kem', source)


@pytest.mark.parametrize('kind', ['timeout', 'residual', 'late'])
def test_owned_group_cleanup(bounded, kind):
    tmp, exe, pack = bounded
    witness = tmp / (kind + '.json')
    _witness(exe, witness, residual=kind == 'residual', late=kind == 'late')
    receipt, elapsed = _invoke(pack, 'kem')
    assert receipt['reason_code'] == ('RESIDUAL_PROCESS' if kind == 'residual' else 'COMMAND_TIMEOUT')
    assert receipt['cleanup_confirmed'] and receipt['payload'] is None and type(receipt['rc']) is int
    assert elapsed < 3.5
    _group_gone(witness)


def test_inner_timeout_real_rc(tmp_path):
    exe, source = _fixed_fixture(tmp_path, outer=4, inner=1.5)
    witness = tmp_path/'inner.json'
    _witness(exe, witness, fork=False, late=True)
    receipt, elapsed = _invoke(_package(_private(tmp_path/'native'), 'kem', source), 'kem')
    _payload(receipt, 'ERROR', 'TIMEOUT', -9, [])
    assert elapsed < 4
    _group_gone(witness)


def test_consumer_loss(bounded):
    tmp, exe, pack = bounded
    witness = tmp/'consumer.json'
    _witness(exe, witness, late=True)
    path, env = pack
    start = time.monotonic()
    with subprocess.Popen([BASE_PYTHON, '-I', '-B', str(path)], cwd=path.parent, env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
        proc.stdout.close()
        proc.wait(timeout=5)
    assert time.monotonic()-start < 4
    _group_gone(witness)


def test_closed_receipts_and_fixed_contract(packs, tmp_path):
    exe, packaged = packs
    _reply(exe, VALID['kem'][0])
    receipt, _ = _invoke(packaged['kem'], 'kem')
    payload = receipt['payload']
    for bad in [receipt | {'extra': 1}, receipt | {'format': True}, receipt | {'rc': True},
                receipt | {'rc': 1}, receipt | {'cleanup_confirmed': False}, receipt | {'stage': 'signature'},
                receipt | {'reason_code': 'COMMAND_FAILED'}, receipt | {'payload': payload | {'rc': 1}},
                receipt | {'payload': payload | {'rows': payload['rows']*2}},
                receipt | {'payload': payload | {'rows': [['default', ['bad alias']]]}},
                receipt | {'payload': payload | {'extra': 'raw'}},
                receipt | {'payload': payload | {'rows': [['default', ['x']*33]]}}]:
        with pytest.raises(ValueError):
            acquire.validate_receipt(bad, 'kem')
    with pytest.raises(ValueError):
        acquire.validate_receipt(receipt, 'signature')
    for raw in (b'{"state":"UNKNOWN","state":"COLLECTED"}', b'{"rc":NaN}', b'x'*16385):
        with pytest.raises(ValueError):
            acquire._decode(raw)
    failure = acquire._receipt('kem', 'REMOTE_CLEANUP_UNCONFIRMED', None, False, None)
    assert acquire.validate_receipt(failure, 'kem') == failure
    _invoke(_package(_private(tmp_path/'bad-stage'), 'foreign'), 'foreign', failure=True)
    _invoke(_package(_private(tmp_path/'bad-argument'), 'version', path='/fixture/never'), 'version', failure=True)


def test_original_snapshot_normalizer(packs):
    from tools import assessment, evidence, openssl_runtime as runtime
    exe, packaged = packs
    slots = {}
    for stage in acquire.STAGES:
        if stage == 'rpm-openssl-libs':
            _reply(exe, b'package openssl-libs is not installed\n', rc=1)
        elif stage == 'kem':
            _reply(exe, b'{ ML-KEM-768, bad alias } @ default\nML-KEM-512 @ default\n')
        elif stage == 'signature':
            _reply(exe, b'', b'list: Unknown option: -signature-algorithms\n', 1)
        else:
            _reply(exe, VALID[stage][0])
        receipt, _ = _invoke(packaged[stage], stage)
        slots[stage] = receipt['payload']
    rules = assessment.load_rules((ROOT/'config/assessment_rules.yml').read_bytes())
    now = '2026-01-01T00:00:00Z'
    host = evidence.host_id('fixture-authority', 'fixture-host.example.invalid')
    source = dict(source_kind='SYNTHETIC', producer_id=runtime.PRODUCER, producer_version=runtime.VERSION,
                  origin_ref='fixture-openssl-o1', input_sha256=None)
    doc = dict(schema_version='1.1.0', run=dict(run_id='fixture-run-o1', run_state='COMPLETE',
        recorded_at=now, started_at=None, finished_at=None, source=source, expected_host_ids=[host]),
        hosts=[dict(host_id=host, target_id='fixture-host.example.invalid', identity_scope='STABLE',
                    host_state='COMPLETE', reason_code='FIXTURE', inventory_authority_id='fixture-authority', identity_key=None)],
        collections=[], assets=[], evidence=[], claims=[], findings=[])
    snap = dict(flags=dict(pqc_collect_packages=True, pqc_collect_openssl=True), platform_status='UNVERIFIED', slots=slots)
    runtime.validate_snapshot(snap)
    normalized, diagnostics = runtime.normalize_openssl(doc, host, snap, source, now, rules)
    evidence.validate_document(normalized)
    assert not doc['evidence'] and not normalized['claims'] and not normalized['findings']
    assert {d['slot'] for d in diagnostics} == set(acquire.STAGES)
    assert all(row['evidence_kind'] in ('PACKAGE_INVENTORY','ASSET_METADATA','RUNTIME_CAPABILITY','COLLECTION_SUMMARY')
               for row in normalized['evidence'])
    assert any(row['evidence_kind']=='PACKAGE_INVENTORY' and row['data']['name']=='openssl-libs' and row['data']['present'] is False for row in normalized['evidence'])
    assert not any('ML-KEM-768' in d.get('aliases', []) for diag in diagnostics if diag['slot']=='kem' for d in diag.get('observations', []))
    assert next(d for d in diagnostics if d['slot']=='signature')['state']=='UNKNOWN'
    for packages, openssl, status in ((False, True, 'UNVERIFIED'), (True, False, 'UNVERIFIED'), (True, True, 'UNKNOWN'), (True, True, 'OUT_OF_SCOPE')):
        projected = {}
        for stage in acquire.STAGES:
            enabled = packages if stage in acquire.RPM_STAGES else openssl
            projected[stage] = (acquire._result('NOT_SCANNED','DISABLED_BY_USER') if not enabled else
                                acquire._result('UNKNOWN','PLATFORM_UNRESOLVED') if status=='UNKNOWN' else
                                acquire._result('NOT_APPLICABLE','PLATFORM_OUT_OF_SCOPE') if status=='OUT_OF_SCOPE' else slots[stage])
        runtime.validate_snapshot(dict(flags=dict(pqc_collect_packages=packages,pqc_collect_openssl=openssl),platform_status=status,slots=projected))


def test_fixed_source_mirrors_and_limits():
    assert MODULE.read_bytes() == MIRROR.read_bytes()
    assert stat.S_IMODE(MODULE.stat().st_mode) == stat.S_IMODE(MIRROR.stat().st_mode) == 0o644
    assert HELPER.read_bytes() == (COLLECTION/'plugins/module_utils/pqc_bounded_execution.py').read_bytes()
    assert acquire.STAGES == tuple(VALID)
    assert acquire.STAGE_SECONDS == 30 and acquire.INNER_SECONDS == 27
    assert acquire.OUTPUT_BYTES == 16384 and acquire.WRAPPER_BYTES == 32768
