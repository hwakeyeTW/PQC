"""I1b P1: actual packaged module, bounded child and typed platform receipts.

Only local synthetic inventory and private fixture executables. The installed
RPM and the managed transport are never invoked. Fixture copies replace a
single fixed RPM literal and may narrow (never widen) the stage deadline.
"""
import copy
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
import yaml

from tools import evidence as ev
from tools import platform as normalizer

ROOT = Path(__file__).resolve().parents[2]
COLLECTION = ROOT / 'ansible_collections/security/compliance_pqc_readiness'
MODULE = COLLECTION / 'plugins/modules/pqc_platform_acquire.py'
MIRROR = ROOT / 'plugins/modules/pqc_platform_acquire.py'
HELPER = ROOT / 'plugins/module_utils/pqc_bounded_execution.py'
SPEC = importlib.util.spec_from_file_location('pqc_platform_acquisition_test', MODULE)
acquire = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acquire)
BASE_PYTHON = os.path.abspath(sys._base_executable)
SOURCE = dict(source_kind='SYNTHETIC', producer_id='pqc-platform', producer_version='1.0.0',
              origin_ref='fixture-platform-p1', input_sha256=None)
TS = '2026-01-01T00:00:00Z'
HID = ev.host_id('fixture-authority', 'fixture-host.example.invalid')
NAME, EL9 = acquire.PACKAGES


def _private(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _env(tmp, *, library=ROOT / 'plugins/modules', collections=None):
    env = dict(os.environ)
    for key in tuple(env):
        if key.startswith('ANSIBLE_') or key in ('SSH_AUTH_SOCK', 'SSH_AGENT_PID', 'PYTHONPATH', 'PYTHONHOME'):
            env.pop(key, None)
    home = _private(tmp / 'home')
    env.update(HOME=str(home), TMPDIR=str(_private(tmp / 'tmp')), LC_ALL='C.UTF-8',
               ANSIBLE_CONFIG=str(ROOT / 'ansible.cfg'), ANSIBLE_LIBRARY=str(library),
               ANSIBLE_MODULE_UTILS=str(HELPER.parent), ANSIBLE_COLLECTIONS_SCAN_SYS_PATH='false',
               ANSIBLE_COLLECTIONS_PATH=str(collections or _private(tmp / 'empty-collections')),
               ANSIBLE_LOCAL_TEMP=str(_private(tmp / 'local')),
               ANSIBLE_REMOTE_TEMP=str(_private(tmp / 'remote')),
               ANSIBLE_HOST_KEY_CHECKING='true', ANSIBLE_KEEP_REMOTE_FILES='1',
               ANSIBLE_NOCOLOR='1', ANSIBLE_RETRY_FILES_ENABLED='false')
    return env


def _cli(name):
    path = shutil.which(name)
    if not path:
        pytest.skip('qualified Ansible runtime unavailable')
    return path


def _play(tmp, tasks, env, *, syntax=True):
    play = tmp / 'fixture.yml'
    play.write_text(yaml.safe_dump([dict(hosts='localhost', gather_facts=False, connection='local',
        become=False, vars={'ansible_python_interpreter': BASE_PYTHON}, tasks=tasks)], sort_keys=False))
    play.chmod(0o600)
    command = [_cli('ansible-playbook'), '-i', 'localhost,', str(play)]
    if syntax:
        p = subprocess.run(command + ['--syntax-check'], cwd=tmp, env=env, capture_output=True, timeout=15)
        assert p.returncode == 0, p.stdout.decode(errors='replace')
    p = subprocess.run(command, cwd=tmp, env=env, capture_output=True, timeout=40)
    assert p.returncode == 0, p.stdout.decode(errors='replace')


def _doc():
    return dict(schema_version='1.1.0', run=dict(run_id='fixture-run-p1', run_state='COMPLETE', recorded_at=TS,
        started_at=None, finished_at=None, source=SOURCE, expected_host_ids=[HID]),
        hosts=[dict(host_id=HID, target_id='fixture-host.example.invalid', identity_scope='STABLE',
                    host_state='COMPLETE', reason_code='FIXTURE', inventory_authority_id='fixture-authority', identity_key=None)],
        collections=[], assets=[], evidence=[], claims=[], findings=[])


def _build(snapshot):
    doc = _doc()
    result = normalizer.build_platform_evidence(doc, HID, source=SOURCE, observed_at=TS, snapshot=snapshot)
    assert len(result['collections']) == 10
    assert {c['scope_key'] for c in result['collections']} == {'platform-info',
        *('tool-' + k for k in normalizer.TOOL_SLOTS), *('release-rpm-' + n for n in normalizer.PACKAGES)}
    for c in result['collections']:
        assert c['collection_id'] == ev.collection_id(doc['run']['run_id'], HID, normalizer.COLLECTOR, c['scope_key'])
        assert c['source'] == SOURCE
    for e in result['evidence']:
        assert e['evidence_id'] == ev.evidence_id(doc['run']['run_id'], HID, e['collection_id'], e['observation_key'])
        assert e['source'] == SOURCE and e['observed_at'] == TS and e['algorithm'] is None
    full = {**doc, 'collections': result['collections'], 'evidence': result['evidence']}
    assert ev.canonical_bytes(ev.parse_evidence_bytes(ev.canonical_bytes(full))) == ev.canonical_bytes(full)
    assert not full['claims'] and not full['findings']
    return result


def _write_json_task(path, expression):
    return {'ansible.builtin.copy': {'dest': str(path), 'mode': '0600', 'content': expression}, 'no_log': True}


def _native_metadata(tmp, module_name, *, fqcn=False):
    env = _env(tmp, collections=ROOT if fqcn else None)
    result = tmp / 'receipt.json'
    tasks = [{module_name: {'stage': 'metadata'}, 'register': 'probe', 'no_log': True},
        {'ansible.builtin.setup': {'gather_subset': ['!all', '!min', 'distribution', 'os_family', 'architecture'],
            'filter': ['ansible_' + k for k in acquire.FACT_NAMES]}, 'register': 'facts', 'no_log': True},
        {'ansible.builtin.stat': {'path': '{{ item }}', 'follow': False, 'get_checksum': False,
            'get_mime': False, 'get_attributes': False}, 'loop': [p for paths in acquire.TOOL_PATHS.values() for p in paths],
            'register': 'stats', 'no_log': True, 'ignore_errors': True},
        _write_json_task(result, """{% set ns = namespace(rows=[]) %}
{% for r in stats.results %}{% set s=r.stat|default({}) %}
{% set row = {'state': ('PERMISSION_DENIED' if 'Permission denied' in (r.msg|default('')) else 'ERROR')} if r.failed|default(false) else {'state':'OK','exists':s.exists|default(none),'isreg':s.isreg|default(none),'islnk':s.islnk|default(none),'executable':(s.executable|default(none)) if s.isreg|default(false) else none} %}
{% set ns.rows=ns.rows+[row] %}{% endfor %}
{{ {'receipt':probe.receipt,'facts':facts.ansible_facts,'rows':ns.rows}|to_json }}""")]
    _play(tmp, tasks, env)
    data = json.loads(result.read_bytes())
    receipt = acquire.validate_receipt(data['receipt'], 'metadata')
    assert receipt['reason_code'] == 'COMMAND_OK' and receipt['cleanup_confirmed'] and receipt['rc'] == 0
    payload = receipt['payload']
    assert payload['facts_state'] == 'OK'
    assert payload['facts'] == {k: data['facts']['ansible_' + k] for k in acquire.FACT_NAMES}
    assert [row for k in acquire.TOOL_PATHS for row in payload['tools'][k]] == data['rows']
    snap = {**payload, 'rpms': {}}
    built = _build(snap)
    # Non-OL local metadata is not permission to query RPM. No RPM module call.
    assert built['platform_status'] == 'OUT_OF_SCOPE'
    assert all(c['collection_state'] == 'NOT_SCANNED' and c['reason_code'] == 'NOT_ATTEMPTED'
               for c in built['collections'] if c['scope_key'].startswith('release-rpm-'))
    return receipt


def test_actual_metadata_short_and_fqcn_packaging(tmp_path):
    # The target interpreter is separate from the restored Ansible controller.
    check = subprocess.run([BASE_PYTHON, '-I', '-S', '-c',
        "import importlib.util; assert importlib.util.find_spec('ansible') is None"], timeout=5)
    assert check.returncode == 0
    short = _native_metadata(_private(tmp_path / 'standalone'), 'pqc_platform_acquire')
    fqcn = _native_metadata(_private(tmp_path / 'collection'),
        'security.compliance_pqc_readiness.pqc_platform_acquire', fqcn=True)
    assert short == fqcn


def _fixture_executable(path, code, *, mode=0o700):
    path.write_text('#!' + BASE_PYTHON + ' -I\n' + code)
    path.chmod(mode)


def _fixture_module(tmp, executable, *, timeout=30, metadata_stall=False, metadata_flood=False):
    library = _private(tmp / 'library')
    text = MODULE.read_text()
    assert text.count("RPM_EXECUTABLE = '/usr/bin/rpm'") == 1
    text = text.replace("RPM_EXECUTABLE = '/usr/bin/rpm'", 'RPM_EXECUTABLE = ' + repr(str(executable)))
    assert 0.5 <= timeout <= 30 and text.count('STAGE_SECONDS = 30') == 1
    text = text.replace('STAGE_SECONDS = 30', 'STAGE_SECONDS = ' + repr(timeout))
    if metadata_stall:
        assert text.count('    state, facts = _facts(archive)') == 1
        text = text.replace('    state, facts = _facts(archive)', '    time.sleep(60)\n    state, facts = _facts(archive)')
    if metadata_flood:
        assert text.count('    state, facts = _facts(archive)') == 1
        text = text.replace('    state, facts = _facts(archive)',
                            "    os.write(1, b'x' * 9000)\n    os.write(2, b'y' * 9000)\n    state, facts = _facts(archive)")
    candidate = library / MODULE.name
    candidate.write_text(text)
    candidate.chmod(0o644)
    return library


def _packaged(tmp, stage, library):
    env = _env(tmp, library=library)
    dest = tmp / 'receipt.json'
    _play(tmp, [{'pqc_platform_acquire': {'stage': stage}, 'register': 'probe', 'no_log': True},
        _write_json_task(dest, '{{ probe.receipt|to_json }}')], env)
    wrappers = list((tmp / 'remote').rglob('AnsiballZ_pqc_platform_acquire.py'))
    assert len(wrappers) == 1 and wrappers[0].is_file()
    receipt = acquire.validate_receipt(json.loads(dest.read_bytes()), stage)
    return wrappers[0], env, receipt


def _invoke(pack, stage):
    path, env, _ = pack
    start = time.monotonic()
    p = subprocess.run([BASE_PYTHON, str(path)], cwd=path.parent, env=env, capture_output=True, timeout=35)
    assert p.returncode == 0 and not p.stderr, (p.returncode, 'fixture wrapper failed')
    value = json.loads(p.stdout)
    assert value['changed'] is False and not value.get('failed', False)
    receipt = acquire.validate_receipt(value['receipt'], stage)
    return receipt, time.monotonic() - start


@pytest.fixture(scope='module')
def rpm_packs(tmp_path_factory):
    tmp = _private(tmp_path_factory.mktemp('rpm-fixture'))
    executable = tmp / 'fixed-rpm-surrogate'
    # Fixed literal executable is the ONLY fixture substitution in the full
    # positive packaging case. It checks exact argv, C locale and UID.
    _fixture_executable(executable, """import os,sys
assert os.geteuid() != 0 and os.environ['LC_ALL'] == 'C'
assert sys.argv[1:4] == ['-q','--queryformat','%{NAME}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\n']
assert sys.argv[4] in ('oraclelinux-release','oraclelinux-release-el9') and len(sys.argv)==5
assert os.read(0,1)==b''
if sys.argv[4].endswith('el9'):
    print('package '+sys.argv[4]+' is not installed',file=sys.stderr);sys.exit(1)
print(sys.argv[4]+'\\t9.10\\t0.1\\tx86_64')
""")
    library = _fixture_module(tmp, executable)
    packs = {stage: _packaged(_private(tmp / ('stage-' + str(i))), stage, library)
             for i, stage in enumerate(acquire.RPM_STAGES)}
    return tmp, executable, packs


def test_actual_two_release_stages_and_normalizer(rpm_packs):
    _, _, packs = rpm_packs
    a = packs['release-rpm-' + NAME][2]
    b = packs['release-rpm-' + EL9][2]
    assert a['reason_code'] == b['reason_code'] == 'COMMAND_OK'
    assert a['rc'] == b['rc'] == 0 and a['cleanup_confirmed'] and b['cleanup_confirmed']
    assert a['rpm_rc'] == 0 and a['payload'] == dict(state='COLLECTED', reason='OK', rows=[[NAME,'9.10','0.1','x86_64']])
    assert b['rpm_rc'] == 1 and b['payload'] == dict(state='ABSENT', reason='PACKAGE_ABSENT', rows=[])
    facts = dict(distribution='OracleLinux', os_family='RedHat', distribution_version='9.10',
                 distribution_major_version='9', architecture='x86_64')
    tools = {k: [dict(state='OK', exists=True, isreg=True, islnk=False, executable=True) for _ in paths]
             for k, paths in acquire.TOOL_PATHS.items()}
    result = _build(dict(facts_state='OK', facts=facts, tools=tools, rpms={NAME:a['payload'],EL9:b['payload']}))
    assert result['platform_status'] == 'UNVERIFIED'
    packages = [e['data'] for e in result['evidence'] if e['evidence_kind'] == 'PACKAGE_INVENTORY']
    assert {e['name']:e['present'] for e in packages} == {NAME:True,EL9:False}


def _row(name=NAME, version='9.10', release='0.1'):
    return f'{name}\t{version}\t{release}\tx86_64\n'


@pytest.mark.parametrize('code,state,reason,inner,count', [
    ("print('package '+sys.argv[4]+' is not installed');sys.exit(1)", 'ABSENT','PACKAGE_ABSENT',1,0),
    ("print('package '+sys.argv[4]+' is not installed');print('lock failure',file=sys.stderr);sys.exit(1)", 'ERROR','COMMAND_FAILED',1,0),
    ("print('Permission denied',file=sys.stderr);sys.exit(1)", 'PERMISSION_DENIED','PERMISSION_DENIED',1,0),
    ("print('database locked',file=sys.stderr);sys.exit(1)", 'ERROR','COMMAND_FAILED',1,0),
    ('pass','UNKNOWN','NO_DATA',0,0),
    ("print('malformed')",'ERROR','MALFORMED_OUTPUT',0,0),
    ('sys.stdout.write('+repr(_row()+_row()+'malformed\n')+')','PARTIAL','INCOMPLETE_RPM_ROWS',0,1),
    ('sys.stdout.write('+repr(_row('foreign-package'))+')','ERROR','MALFORMED_OUTPUT',0,0),
    ('sys.stdout.write('+repr(''.join(_row(release=str(i)) for i in range(33)))+')','ERROR','OUTPUT_LIMIT',0,0),
    ("os.write(1,b'x'*9000);os.write(2,b'y'*9000)",'ERROR','OUTPUT_LIMIT',None,0),
])
def test_actual_rpm_capture_parser(rpm_packs, code, state, reason, inner, count):
    _, executable, packs = rpm_packs
    _fixture_executable(executable, 'import os,sys\n'+code+'\n')
    receipt, elapsed = _invoke(packs['release-rpm-' + NAME], 'release-rpm-' + NAME)
    assert receipt['reason_code'] == 'COMMAND_OK' and receipt['rc'] == 0 and receipt['cleanup_confirmed']
    payload = receipt['payload']
    assert (payload['state'], payload['reason'], len(payload['rows'])) == (state,reason,count)
    assert receipt['rpm_rc'] == inner if inner is not None else type(receipt['rpm_rc']) is int
    normalizer.normalize_rpm(NAME, payload)
    assert elapsed < 30 and len(acquire._json_bytes(receipt)) <= 16384


@pytest.mark.parametrize('available', [False, True])
def test_actual_rpm_missing_or_denied(rpm_packs, available):
    _, executable, packs = rpm_packs
    if executable.exists():
        executable.unlink()
    if available:
        _fixture_executable(executable, 'raise AssertionError("must not execute")\n', mode=0o600)
    r,_ = _invoke(packs['release-rpm-' + NAME], 'release-rpm-' + NAME)
    assert r['rpm_rc'] is None and r['cleanup_confirmed'] and r['reason_code']=='COMMAND_OK'
    assert r['payload']==(dict(state='PERMISSION_DENIED',reason='PERMISSION_DENIED',rows=[]) if available
        else dict(state='UNKNOWN',reason='TOOL_UNAVAILABLE',rows=[]))


def _witness_script(witness, *, residual=False):
    return f"""import json,os,signal,sys,time
signal.signal(signal.SIGTERM,signal.SIG_IGN)
child=os.fork()
if child==0:
    {'os.close(1);os.close(2)' if residual else 'pass'}
    time.sleep(60);os._exit(0)
with open({str(witness)!r},'w') as f:
    json.dump(dict(pids=[os.getpid(),child],pgid=os.getpgrp(),uid=os.geteuid()),f)
{'print(sys.argv[4]+"\\t9.10\\t0.1\\tx86_64")' if residual else 'time.sleep(60)'}
"""


def _group_gone(witness):
    data = json.loads(witness.read_bytes())
    assert data['uid'] == os.geteuid() != 0
    with pytest.raises(ProcessLookupError):
        os.killpg(data['pgid'],0)
    for pid in data['pids']:
        with pytest.raises(ProcessLookupError):
            os.kill(pid,0)


@pytest.fixture(scope='module')
def bounded_pack(tmp_path_factory):
    tmp = _private(tmp_path_factory.mktemp('bounded-rpm'))
    exe = tmp / 'fixed-rpm-surrogate'
    _fixture_executable(exe, 'import sys\nprint(sys.argv[4]+"\\t9.10\\t0.1\\tx86_64")\n')
    library = _fixture_module(tmp, exe, timeout=2)
    stage = 'release-rpm-' + EL9
    pack = _packaged(_private(tmp / 'native'), stage, library)
    assert pack[2]['reason_code']=='COMMAND_OK' and pack[2]['rpm_rc']==0
    return tmp,exe,stage,pack


@pytest.mark.parametrize('residual',[False,True])
def test_actual_bounded_group_cleanup(bounded_pack,residual):
    tmp,exe,stage,pack=bounded_pack
    witness=tmp/('residual.json' if residual else 'timeout.json')
    _fixture_executable(exe,_witness_script(witness,residual=residual))
    receipt,elapsed=_invoke(pack,stage)
    assert receipt['reason_code']==('RESIDUAL_PROCESS' if residual else 'COMMAND_TIMEOUT')
    assert receipt['cleanup_confirmed'] and receipt['payload'] is None and receipt['rpm_rc'] is None
    assert elapsed < 3.5
    _group_gone(witness)


def test_transport_consumer_loss_surrogate(bounded_pack):
    tmp,exe,stage,pack=bounded_pack
    witness=tmp/'transport-loss.json'
    _fixture_executable(exe,_witness_script(witness))
    path,env,_=pack
    start=time.monotonic()
    # No controller reads the target result pipe. The target's independent
    # bounded runner must still terminate/reap the child group.
    with subprocess.Popen([BASE_PYTHON,str(path)],cwd=path.parent,env=env,
                          stdout=subprocess.PIPE,stderr=subprocess.DEVNULL) as p:
        p.stdout.close()
        p.wait(timeout=5)
    assert time.monotonic()-start < 4
    _group_gone(witness)


def test_metadata_deadline_actual_packaged_child(tmp_path):
    tmp=_private(tmp_path/'metadata-stall')
    library=_fixture_module(tmp,tmp/'never-executed',timeout=2,metadata_stall=True)
    _,_,r=_packaged(_private(tmp/'native'),'metadata',library)
    assert r['reason_code']=='COMMAND_TIMEOUT' and r['cleanup_confirmed']
    assert r['payload'] is None and r['rpm_rc'] is None


def test_metadata_outer_combined_output_cap(tmp_path):
    tmp = _private(tmp_path / 'metadata-flood')
    library = _fixture_module(tmp, tmp / 'never-executed', metadata_flood=True)
    _, _, r = _packaged(_private(tmp / 'native'), 'metadata', library)
    assert r['reason_code'] == 'COMMAND_OUTPUT_LIMIT' and r['cleanup_confirmed']
    assert r['payload'] is None and r['rpm_rc'] is None


def _ol_snapshot(**changes):
    facts=dict(distribution='OracleLinux',os_family='RedHat',distribution_version='9.10',
               distribution_major_version='9',architecture='x86_64') | changes
    tools={k:[dict(state='OK',exists=True,isreg=True,islnk=False,executable=True) for _ in paths]
           for k,paths in acquire.TOOL_PATHS.items()}
    return dict(facts_state='OK',facts=facts,tools=tools,rpms={})


@pytest.mark.parametrize('changes,status',[
    ({'distribution_version':v},'UNVERIFIED') for v in ('9.7','9.8','9.9','9.10')
]+[({'distribution_version':'8.10','distribution_major_version':'8'},'OUT_OF_SCOPE'),
    ({'distribution':'Debian','os_family':'Debian'},'OUT_OF_SCOPE'),
    ({'distribution':None},'UNKNOWN'),({'distribution_major_version':'8'},'UNKNOWN'),
    ({'os_family':'Debian'},'UNKNOWN'),({'distribution_version':None},'UNKNOWN')])
def test_typed_metadata_original_normalizer(changes,status):
    snap=_ol_snapshot(**changes)
    payload={k:v for k,v in snap.items() if k!='rpms'}
    r=dict(format=1,stage='metadata',reason_code='COMMAND_OK',rc=0,cleanup_confirmed=True,payload=payload,rpm_rc=None)
    assert acquire.validate_receipt(r,'metadata')==r
    p=_build(snap)
    assert p['platform_status']==status
    assert all(c['collection_state']=='NOT_SCANNED' for c in p['collections'] if c['scope_key'].startswith('release-rpm-'))


def test_stat_no_follow_and_gaps(tmp_path):
    f=tmp_path/'regular';f.write_text('unread content');f.chmod(0o700)
    assert acquire._stat(str(f))==dict(state='OK',exists=True,isreg=True,islnk=False,executable=True)
    f.chmod(0o600)
    assert acquire._stat(str(f))['executable'] is False
    link=tmp_path/'link';link.symlink_to(f)
    row=acquire._stat(str(link));assert row['islnk'] and row['executable'] is None
    snap=_ol_snapshot();snap['tools']['rpm']=[row]
    assert normalizer.normalize_tools(snap['tools'])['rpm'][2]['available'] is None
    assert acquire._stat(str(tmp_path/'missing'))['exists'] is False
    assert acquire._stat(str(tmp_path))['isreg'] is False
    denied=tmp_path/'denied';denied.mkdir(mode=0o700);(denied/'file').touch();denied.chmod(0)
    try:
        assert acquire._stat(str(denied/'file'))=={'state':'PERMISSION_DENIED'}
    finally:
        denied.chmod(0o700)


def test_receipt_closed_shape_and_cleanup(rpm_packs):
    _,_,packs=rpm_packs
    stage='release-rpm-'+NAME
    r=packs[stage][2]
    for bad in [r|{'format':True}, r|{'rc':True}, r|{'rc':1}, r|{'rpm_rc':1},r|{'cleanup_confirmed':False},
                r|{'stage':'metadata'}, r|{'reason_code':'FOREIGN'}, r|{'extra':'fixture'},
                r|{'reason_code':'COMMAND_FAILED'},r|{'payload':r['payload']|{'rows':r['payload']['rows']*2}},
                r|{'payload':r['payload']|{'rows':[['foreign','9','1','x86_64']]}}]:
        with pytest.raises(ValueError,match='INVALID_STAGE_RECEIPT'):
            acquire.validate_receipt(bad,stage)
    assert acquire.validate_receipt(dict(format=1,stage=stage,reason_code='REMOTE_CLEANUP_UNCONFIRMED',
        rc=None,cleanup_confirmed=False,payload=None,rpm_rc=None),stage)['payload'] is None
    with pytest.raises(ValueError):
        acquire.validate_receipt(r,'release-rpm-'+EL9)
    with pytest.raises(ValueError):
        acquire.validate_receipt(r,'arbitrary-stage')


def test_invalid_module_stage_and_arguments(tmp_path):
    env=_env(tmp_path)
    for args in ('stage=arbitrary-stage','stage=metadata path=/private/fixture'):
        p=subprocess.run([_cli('ansible'),'localhost','-i','localhost,','-c','local','-e',
            'ansible_python_interpreter='+BASE_PYTHON,'-m','pqc_platform_acquire','-a',args],
            cwd=tmp_path,env=env,capture_output=True,timeout=15)
        assert p.returncode!=0 and b'"receipt"' not in p.stdout


def test_fixed_module_and_helper_mirrors():
    assert MODULE.read_bytes()==MIRROR.read_bytes()
    assert stat.S_IMODE(MODULE.stat().st_mode)==stat.S_IMODE(MIRROR.stat().st_mode)==0o644
    assert HELPER.read_bytes()==(COLLECTION/'plugins/module_utils/pqc_bounded_execution.py').read_bytes()
    assert acquire.STAGE_SECONDS==30 and acquire.OUTPUT_BYTES==16384
    assert len(acquire.TOOL_PATHS)==7 and sum(map(len,acquire.TOOL_PATHS.values()))==8
    assert acquire.PACKAGES==normalizer.PACKAGES and acquire.FACT_NAMES==normalizer.FACT_NAMES
