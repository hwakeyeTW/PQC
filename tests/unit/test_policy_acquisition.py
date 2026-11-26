"""CP1 fixed native acquisition; only anonymous private roots and local workers."""
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

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import crypto_policy as original

COLL = ROOT / 'ansible_collections/security/compliance_pqc_readiness'
MODULE = COLL / 'plugins/modules/pqc_policy_acquire.py'
MIRROR = ROOT / 'plugins/modules/pqc_policy_acquire.py'
HELPER = ROOT / 'plugins/module_utils/pqc_bounded_execution.py'
FQCN = 'security.compliance_pqc_readiness.pqc_policy_acquire'
BASE_PYTHON = os.path.abspath(sys._base_executable)


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


acq = _load('policy_acquisition_test', MODULE)
helper = _load('policy_helper_test', HELPER)
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


def _private(p):
    p.mkdir(parents=True, exist_ok=True, mode=0o700)
    p.chmod(0o700)
    return p


def _write(root, name, data):
    path = root / name.lstrip('/')
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data)
    path.chmod(0o600)
    return path


RAW = {
    'profile-config': b'# fixture\nDEFAULT\n', 'kernel-fips': b'0\n',
    'current-policy': b'cipher = AES-256-GCM\nsign = RSA-SHA2-256\n',
    'backend-openssh': b'Ciphers aes256-gcm@openssh.com\nKexAlgorithms curve25519-sha256\n',
    'backend-opensshserver': b'HostKeyAlgorithms ssh-ed25519\n',
    'backend-openssl': b'Ciphersuites = TLS_AES_256_GCM_SHA384\n',
    'backend-opensslcnf': b'MinProtocol = TLSv1.2\n',
}


def _root(tmp):
    root = _private(tmp / 'root')
    for scope, data in RAW.items():
        _write(root, acq.PATHS[scope], data)
    _write(root, acq.LOCAL_DIR + '/openssh-fixture.txt', b'Ciphers aes256-ctr\n')
    return root


def _script(root, stage, code):
    path = _write(root, acq.SHOW_PATHS[stage], ('#!' + BASE_PYTHON + ' -I\nimport os,sys,time,signal,json\n' + code + '\n').encode())
    path.chmod(0o700)
    return path


def _reply(root, stage, out=b'DEFAULT\n', err=b'', rc=0):
    return _script(root, stage, "assert sys.argv[1:]==['--show'] and os.read(0,1)==b'' and os.environ['LC_ALL']=='C'\n"
                   f'os.write(1,{out!r});os.write(2,{err!r});sys.exit({rc})')


def _fixture(tmp, root, *, fqcn=False, outer=30, inner=23):
    assert 0.5 <= outer <= 30 and 0.5 <= inner <= 23
    source = MODULE.read_text()
    for a, b in (("ROOT_DIRECTORY = '/'", 'ROOT_DIRECTORY = ' + repr(str(root))),
                 ('_TRUSTED_UID = 0', '_TRUSTED_UID = ' + str(os.geteuid())),
                 ('STAGE_SECONDS = 30', 'STAGE_SECONDS = ' + repr(outer)),
                 ('INNER_SECONDS = 23', 'INNER_SECONDS = ' + repr(inner))):
        assert source.count(a) == 1
        source = source.replace(a, b)
    collection_root = _private(tmp / 'collections')
    if fqcn:
        parent = _private(collection_root / 'ansible_collections/security/compliance_pqc_readiness/plugins/modules')
        h = parent.parent / 'module_utils' / HELPER.name
        h.parent.mkdir(mode=0o700)
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
    cfg.write_text('[defaults]\nhost_key_checking=True\nretry_files_enabled=False\n')
    env = dict(PATH=str(Path(sys.executable).parent) + ':/usr/bin:/bin', HOME=str(_private(tmp / 'home')),
               TMPDIR=str(_private(tmp / 'tmp')), LC_ALL='C.UTF-8', ANSIBLE_CONFIG=str(cfg),
               ANSIBLE_LIBRARY=str(candidate.parent), ANSIBLE_MODULE_UTILS=str(HELPER.parent),
               ANSIBLE_COLLECTIONS_PATH=str(collection_root), ANSIBLE_COLLECTIONS_SCAN_SYS_PATH='false',
               ANSIBLE_LOCAL_TEMP=str(_private(tmp / 'local')), ANSIBLE_REMOTE_TEMP=str(_private(tmp / 'remote')),
               ANSIBLE_NOCOLOR='1')
    dest = tmp / ('AnsiballZ_' + stage + '.py')
    args = dict(stage=stage, _ansible_no_log=True, _ansible_check_mode=True) | extra
    p = subprocess.run([sys.executable, '-I', '-B', '-c', PACKAGE, name, str(candidate), str(dest), json.dumps(args)],
                       cwd=tmp, env=env, capture_output=True, timeout=20)
    assert p.returncode == 0, p.stderr.decode(errors='replace')
    dest.chmod(0o600)
    return dest, env


def _invoke(pack, stage, *, fail=False):
    path, env = pack
    start = time.monotonic()
    p = subprocess.run([BASE_PYTHON, '-I', '-B', str(path)], cwd=path.parent, env=env, capture_output=True, timeout=34)
    assert len(p.stdout) <= acq.WRAPPER_BYTES
    if fail:
        assert p.returncode != 0 and b'"receipt"' not in p.stdout
        return None
    assert p.returncode == 0 and not p.stderr, (p.returncode, p.stdout[:300], p.stderr[:300])
    outer = json.loads(p.stdout)
    assert outer['changed'] is False and not outer.get('failed', False)
    receipt = acq.validate_receipt(outer['receipt'], stage)
    assert len(acq._json_bytes(receipt)) <= acq.RECEIPT_BYTES
    return receipt, time.monotonic()-start


def _payload(receipt):
    assert (receipt['reason_code'], receipt['rc'], receipt['cleanup_confirmed']) == ('COMMAND_OK', 0, True)
    return receipt['payload']


@pytest.fixture
def reader(tmp_path, monkeypatch):
    root = _root(tmp_path)
    monkeypatch.setattr(acq, '_TRUSTED_UID', os.geteuid())
    fd = os.open(root, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        yield root, acq.Reader(fd, time.monotonic()+23)
    finally:
        os.close(fd)


def test_grammar_mirrors_and_caps():
    def grammar(path):
        s = path.read_bytes()
        return s[s.index(b'\n', s.index(b'# BEGIN SHARED POLICY GRAMMAR'))+1:s.index(b'# END SHARED POLICY GRAMMAR')]
    assert grammar(MODULE) == grammar(ROOT/'tools/crypto_policy.py')
    assert MODULE.read_bytes() == MIRROR.read_bytes()
    assert HELPER.read_bytes() == (COLL/'plugins/module_utils'/HELPER.name).read_bytes()
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o644 for p in (MODULE,MIRROR,HELPER,COLL/'plugins/module_utils'/HELPER.name))
    assert acq.FILE_LIMIT == helper.OUTPUT_BYTES == 16384 and acq.TOTAL_LIMIT == acq.PAYLOAD_BYTES == 65536
    assert acq.MAX_VALUES == 64 and acq.MAX_ENTRIES == 32 and acq.INNER_SECONDS == 23
    assert helper.COMMAND_SECONDS == acq.STAGE_SECONDS == 30 and acq.RECEIPT_BYTES == 67584 and acq.WRAPPER_BYTES == 131072


@pytest.mark.parametrize('fqcn', [False,True], ids=['short','fqcn'])
def test_actual_native_reader_show_and_normalizer(tmp_path, fqcn):
    root = _root(tmp_path)
    name = 'openssh.config'
    fixed = root/acq.PATHS['backend-openssh'].lstrip('/')
    fixed.unlink()
    _write(root,'/usr/share/crypto-policies/DEFAULT/'+name,RAW['backend-openssh'])
    fixed.symlink_to('/usr/share/crypto-policies/DEFAULT/'+name)
    _reply(root,'show-bin',b'FIPS\n'); _reply(root,'show-sbin',b'DEFAULT\n')
    fixture = _fixture(tmp_path,root,fqcn=fqcn)
    reader = _payload(_invoke(_package(tmp_path/'reader','reader',fixture),'reader')[0])
    assert set(reader) == set(acq.READER_SCOPES) and len(reader) == 8
    for scope,data in RAW.items():
        assert reader[scope] == original.parse_source(scope,data)
    assert reader['local-overrides'] == original.result('COLLECTED','OK',[['entry-count',1]],overrides=[{
        'override_id':'ov-'+hashlib.sha256(b'openssh-fixture.txt').hexdigest(),'backend':'openssh',
        'result':original.parse_source('backend-openssh',b'Ciphers aes256-ctr\n')}])
    assert b'openssh-fixture.txt' not in acq._json_bytes(reader)
    for stage,value in [('show-bin','FIPS'),('show-sbin','DEFAULT')]:
        show = _payload(_invoke(_package(tmp_path/stage,stage,fixture),stage)[0])
        assert show == {'profile-show':original.parse_source('profile-show',(value+'\n').encode(),rc=0)}
        slots,meta = original.normalize_snapshot(reader|show)
        assert meta['kernel_fips_enabled'] is False and meta['shown_profile']==value
        assert meta['profile_consistency'] == ('CONFLICT' if stage=='show-bin' else 'MATCH')
        assert (slots['profile-config']['reason']=='PROFILE_CONFLICT') == (stage=='show-bin')
        assert reader['profile-config']['reason']=='OK'
    if fqcn:
        pack = _package(tmp_path/'syntax','reader',fixture)
        play = pack[0].parent/'fixture.yml'
        play.write_text('- hosts: localhost\n  gather_facts: false\n  connection: local\n  become: false\n  tasks:\n    - '+FQCN+':\n        stage: reader\n      no_log: true\n')
        p = subprocess.run([str(Path(sys.executable).parent/'ansible-playbook'),'-i','localhost,',str(play),'--syntax-check'],
                           cwd=play.parent,env=pack[1],capture_output=True,timeout=15)
        assert p.returncode==0, p.stderr.decode(errors='replace')


@pytest.mark.parametrize('scope,raw,rc',[
    ('kernel-fips',b'1\n',None),('kernel-fips',b'not enabled\n',None),('kernel-fips',b'',None),
    ('profile-config',b'DEFAULT\nFIPS\n',None),('profile-show',b'FIPS\n',1),
    ('current-policy',b'cipher = AES-256-GCM\nsign = *\n',None),
    ('backend-openssh',b'Ciphers aes256-ctr\nCiphers +aes128-ctr\nKexAlgorithms curve25519-sha256\n',None),
    ('backend-openssl',b'CipherString = DEFAULT@SECLEVEL=2\nMinProtocol = TLSv1.2\n',None),
    ('backend-opensslcnf',b'Include = /fixture\n',None),
])
def test_original_literal_grammar(scope,raw,rc):
    assert acq.parse_source(scope,raw,rc=rc) == original.parse_source(scope,raw,rc=rc)


@pytest.mark.parametrize('kind,reason',[
    ('absent','SOURCE_ABSENT'),('symlink','UNSAFE_SOURCE'),('hardlink','UNSAFE_SOURCE'),('fifo','UNSAFE_SOURCE'),
    ('directory','UNSAFE_SOURCE'),('file-mode','UNSAFE_SOURCE'),('dir-mode','UNSAFE_SOURCE'),
    ('dir-link','UNSAFE_SOURCE'),('permission','PERMISSION_DENIED'),('file-cap','OUTPUT_LIMIT'),
])
def test_reader_unsafe_sources(reader,kind,reason):
    root,r = reader
    p = root/acq.PATHS['profile-config'].lstrip('/')
    if kind in ('absent','symlink','hardlink','fifo','directory','dir-link'):
        p.unlink()
    if kind=='symlink': p.symlink_to('/fixture-outside')
    if kind=='hardlink': os.link(_write(root,'/fixture',b'DEFAULT\n'),p)
    if kind=='fifo': os.mkfifo(p,0o600)
    if kind=='directory': p.mkdir()
    if kind=='file-mode': p.chmod(0o666)
    if kind=='dir-mode': p.parent.chmod(0o777)
    if kind=='dir-link':
        parent=p.parent; parent.rename(parent.with_name('other'));parent.symlink_to('other')
    if kind=='permission': p.chmod(0)
    if kind=='file-cap': p.write_bytes(b'x'*(acq.FILE_LIMIT+1))
    row=r.slot('profile-config')
    assert row['reason']==reason and not row['values']
    assert r.slot('kernel-fips')['values']==[['fips-enabled',False]]


@pytest.mark.parametrize('kind',['loop','wrong-name','wrong-tree','dir-component','too-deep'])
def test_backend_link_rejection(reader,kind):
    root,r=reader
    p=root/acq.PATHS['backend-openssh'].lstrip('/');p.unlink()
    target='/usr/share/crypto-policies/DEFAULT/openssh.config'
    if kind=='loop':
        q=root/target.lstrip('/');q.parent.mkdir(parents=True);q.symlink_to(acq.PATHS['backend-openssh'])
    elif kind=='wrong-name': target='/usr/share/crypto-policies/DEFAULT/openssl.config'
    elif kind=='wrong-tree': target='/usr/share/crypto-policies/CUSTOM/openssh.config'
    elif kind=='dir-component': target='/usr/share/crypto-policies/DEFAULT/../DEFAULT/openssh.config'
    else:
        names=[f'/usr/share/crypto-policies/{v}/openssh.config' for v in acq.LINK_PROFILES]
        for a,b in zip(names,names[1:]+[acq.PATHS['backend-openssh']]):
            q=root/a.lstrip('/');q.parent.mkdir(parents=True);q.symlink_to(b)
    p.symlink_to(target)
    assert r.slot('backend-openssh')==original.result('UNKNOWN','UNSAFE_SOURCE')


def test_reader_file_and_link_identity_drift(reader,monkeypatch):
    root,r=reader
    path=root/acq.PATHS['backend-openssh'].lstrip('/')
    path.unlink(); target='/usr/share/crypto-policies/DEFAULT/openssh.config'
    q=_write(root,target,RAW['backend-openssh']);path.symlink_to(target)
    read=os.read; done=False
    def drift(fd,n):
        nonlocal done
        data=read(fd,n)
        if not done and os.fstat(fd).st_ino==q.stat().st_ino:
            done=True;path.unlink();path.symlink_to(target)
        return data
    monkeypatch.setattr(os,'read',drift)
    assert r.slot('backend-openssh')==original.result('ERROR','SOURCE_CHANGED') and done


def test_reader_entry_value_and_timeout_caps(reader):
    root,r=reader
    local=root/acq.LOCAL_DIR.lstrip('/')
    for i in range(32): _write(root,acq.LOCAL_DIR+f'/unknown-{i}',b'x')
    assert r.overrides()==original.result('ERROR','ENTRY_LIMIT')
    for p in local.iterdir(): p.unlink()
    for i in range(2): _write(root,acq.LOCAL_DIR+f'/openssh-{i}.txt',('Ciphers '+','.join(f'cipher-{j}' for j in range(40))).encode())
    row=r.overrides(); assert row['state']=='PARTIAL' and row['overrides'][1]['result']['reason']=='VALUE_LIMIT'
    assert sum(len(x['result']['values']) for x in row['overrides'])==40
    r.deadline=time.monotonic()-1
    with pytest.raises(acq.Fault,match='TIMEOUT'): r.collect()


def test_actual_large_reader_and_aggregate_gap(tmp_path):
    root=_root(tmp_path);fixture=_fixture(tmp_path,root);pack=_package(tmp_path/'native','reader',fixture)
    tokens=['A'+str(i)+'x'*89 for i in range(64)]
    _write(root,acq.PATHS['current-policy'],('cipher = '+' '.join(tokens)).encode())
    for scope in ('backend-openssh','backend-opensshserver'):
        _write(root,acq.PATHS[scope],('Ciphers '+','.join(tokens)).encode())
    tls=['TLS_'+str(i)+'A'*88 for i in range(64)]
    for scope in ('backend-openssl','backend-opensslcnf'):
        _write(root,acq.PATHS[scope],('Ciphersuites = '+':'.join(tls)).encode())
    receipt,_=_invoke(pack,'reader'); rows=_payload(receipt)
    assert 16384 < len(acq._json_bytes(rows)) <= 65536
    assert all(len(rows[s]['values'])==64 for s in ('current-policy',*('backend-'+v for v in acq.BACKENDS)))
    original.normalize_snapshot(rows|{'profile-show':original.result('NOT_SCANNED','SHOW_TOOL_UNAVAILABLE')})
    # All files stay individually legal; raw aggregate now exceeds the fixed budget.
    for s in ('current-policy',*('backend-'+v for v in acq.BACKENDS)):
        _write(root,acq.PATHS[s],b'#'+b'x'*(acq.FILE_LIMIT-1))
    rows=_payload(_invoke(pack,'reader')[0]);assert rows==acq._gap('reader',original.result('ERROR','TOTAL_LIMIT'))


def test_serialized_cap_is_gap_not_truncation(reader,monkeypatch):
    _,r=reader;rows=r.collect()
    monkeypatch.setattr(acq,'PAYLOAD_BYTES',len(acq._json_bytes(rows))-1)
    result=acq._typed_payload('reader',rows)
    assert result==acq._gap('reader',original.result('ERROR','TOTAL_LIMIT'))


@pytest.fixture(scope='module')
def show_pack(tmp_path_factory):
    tmp=tmp_path_factory.mktemp('policy-show');root=_root(tmp);fixture=_fixture(tmp,root)
    return root,_package(tmp/'native','show-bin',fixture)


@pytest.mark.parametrize('out,err,rc,state,reason',[
    (b'DEFAULT\n',b'',0,'COLLECTED','OK'),(b'FIPS\nDEFAULT\n',b'',0,'UNKNOWN','AMBIGUOUS_PROFILE'),
    (b'DEFAULT\n',b'warning',0,'UNKNOWN','AMBIGUOUS_PROFILE'),(b'',b'Permission denied\n',126,'PERMISSION_DENIED','PERMISSION_DENIED'),
    (b'DEFAULT\n',b'',7,'ERROR','COMMAND_FAILED'),(b'x'*9000,b'y'*9000,0,'ERROR','OUTPUT_LIMIT'),
])
def test_actual_show_capture(show_pack,out,err,rc,state,reason):
    root,pack=show_pack;_reply(root,'show-bin',out,err,rc)
    row=_payload(_invoke(pack,'show-bin')[0])['profile-show']
    assert (row['state'],row['reason'])==(state,reason)
    if reason!='OUTPUT_LIMIT': assert row['rc']==rc
    else: assert type(row['rc']) is int and not row['values']


@pytest.mark.parametrize('kind,reason',[('missing','TOOL_UNAVAILABLE'),('nonexec','TOOL_UNAVAILABLE'),('symlink','UNSAFE_SOURCE'),('hardlink','UNSAFE_SOURCE'),('directory','UNSAFE_SOURCE'),('writable','UNSAFE_SOURCE')])
def test_actual_show_fixed_executable_no_fallback(show_pack,kind,reason):
    root,pack=show_pack;p=root/acq.SHOW_PATHS['show-bin'].lstrip('/')
    if p.is_dir() and not p.is_symlink(): p.rmdir()
    elif p.exists() or p.is_symlink(): p.unlink()
    fallback=_reply(root,'show-sbin',b'FIPS\n')
    if kind=='symlink': p.symlink_to(fallback)
    elif kind=='hardlink': os.link(fallback,p)
    elif kind=='directory': p.mkdir()
    elif kind in ('nonexec','writable'): _reply(root,'show-bin').chmod(0o600 if kind=='nonexec' else 0o777)
    row=_payload(_invoke(pack,'show-bin')[0])['profile-show']
    assert row['reason']==reason and not row['values'] and row['rc'] is None
    if p.is_dir() and not p.is_symlink(): p.rmdir()
    elif p.exists() or p.is_symlink(): p.unlink()


def test_show_executable_drift(show_pack):
    root,pack=show_pack
    _script(root,'show-bin','os.chmod(sys.argv[0],0o500);print("DEFAULT")')
    assert _payload(_invoke(pack,'show-bin')[0])['profile-show']==original.result('ERROR','SOURCE_CHANGED',rc=0)


def _witness(root,residual=False):
    witness=root/'witness.json'
    _script(root,'show-bin',f'''signal.signal(signal.SIGTERM,signal.SIG_IGN)
child=os.fork()
if child==0:
    {"os.close(1);os.close(2)" if residual else "pass"}
    time.sleep(60);os._exit(0)
with open({str(witness)!r},'w') as f:json.dump(dict(pids=[os.getpid(),child],pgid=os.getpgrp(),uid=os.geteuid()),f)
{'print("DEFAULT")' if residual else 'time.sleep(60)'}''')
    return witness


def _gone(witness):
    row=json.loads(witness.read_bytes());assert row['uid']==os.geteuid()!=0
    for pid in row['pids']:
        with pytest.raises(ProcessLookupError):os.kill(pid,0)
    with pytest.raises(ProcessLookupError):os.killpg(row['pgid'],0)


@pytest.mark.parametrize('kind',['timeout','residual','consumer-loss','interrupt'])
def test_actual_owned_group_cleanup(tmp_path,kind):
    root=_root(tmp_path);witness=_witness(root,kind=='residual')
    pack=_package(tmp_path/'native','show-bin',_fixture(tmp_path,root,outer=2.5))
    if kind in ('timeout','residual'):
        receipt,elapsed=_invoke(pack,'show-bin')
        assert receipt['reason_code']==('RESIDUAL_PROCESS' if kind=='residual' else 'COMMAND_TIMEOUT')
        assert receipt['cleanup_confirmed'] and receipt['payload'] is None and elapsed<4
    else:
        path,env=pack;start=time.monotonic()
        with subprocess.Popen([BASE_PYTHON,'-I','-B',str(path)],cwd=path.parent,env=env,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL) as p:
            if kind=='consumer-loss':
                p.stdout.close();p.wait(timeout=5)
            else:
                while not witness.exists() and time.monotonic()-start<1.5:time.sleep(.01)
                assert witness.exists();p.send_signal(signal.SIGTERM)
                out,_=p.communicate(timeout=5);receipt=json.loads(out)['receipt']
                assert receipt['reason_code']=='INTERRUPTED' and receipt['cleanup_confirmed'] and receipt['payload'] is None
        assert time.monotonic()-start<5
    _gone(witness)


def test_inner_timeout_preserves_inner_rc(tmp_path):
    root=_root(tmp_path);_script(root,'show-bin','time.sleep(60)')
    pack=_package(tmp_path/'native','show-bin',_fixture(tmp_path,root,inner=1.2,outer=4))
    receipt,elapsed=_invoke(pack,'show-bin');row=_payload(receipt)['profile-show']
    assert row['state']=='ERROR' and row['reason']=='TIMEOUT' and row['rc']==-signal.SIGKILL and elapsed<4


def test_fixed_receipts_and_invalid_args(tmp_path):
    root=_root(tmp_path);fixture=_fixture(tmp_path,root);receipt=_invoke(_package(tmp_path/'native','reader',fixture),'reader')[0]
    for bad in (receipt|{'format':True},receipt|{'rc':True},receipt|{'cleanup_confirmed':False},receipt|{'stage':'show-bin'},
                receipt|{'extra':1},receipt|{'payload':receipt['payload']|{'extra':{}}},receipt|{'reason_code':'COMMAND_TIMEOUT'}):
        with pytest.raises(ValueError): acq.validate_receipt(bad,'reader')
    bad=receipt|{'payload':receipt['payload']|{'kernel-fips':original.result('COLLECTED','OK',[['fips-enabled',0]])}}
    with pytest.raises(ValueError):acq.validate_receipt(bad,'reader')
    for raw in (b'{"x":1,"x":2}\n',b'{"x":NaN}\n',b'{"x":1.0}\n',b'{}',b'{}\n\n',b'x'*(65538)):
        with pytest.raises(ValueError):acq._decode(raw)
    bad=receipt|{'payload':receipt['payload']|{'current-policy':original.result('ERROR','TOTAL_LIMIT')}}
    with pytest.raises(ValueError):acq.validate_receipt(bad,'reader')
    assert acq.validate_receipt(acq._receipt('reader','REMOTE_CLEANUP_UNCONFIRMED',None,False,None),'reader')['payload'] is None
    for extra in ({'path':'/fixture'},{'root':'/fixture'},{'argv':['/fixture']},{'timeout':1},{'env':{}},{'stage':'unknown'}):
        # Use a new wrapper per attempted argument; no caller-directed acquisition.
        stage=extra.pop('stage','reader')
        _invoke(_package(tmp_path/('bad-'+str(len(list(tmp_path.glob('bad-*'))))),stage,fixture,**extra),stage,fail=True)


@pytest.mark.parametrize('entry,cap', [('run_bounded',16384),('run_policy_bounded',65537)])
def test_helper_combined_cap_and_original_contract(entry,cap):
    run=getattr(helper,entry)
    def argv(n):return [BASE_PYTHON,'-I','-S','-B','-c',f'import os;os.write(1,b"x"*{n//2});os.write(2,b"y"*{n-n//2})']
    ok=run(argv(cap),timeout_s=3)
    assert ok.reason_code=='COMMAND_OK' and ok.cleanup_confirmed and len(ok.stdout)+len(ok.stderr)==cap
    bad=run(argv(cap+1),timeout_s=3)
    assert bad.reason_code=='COMMAND_OUTPUT_LIMIT' and bad.cleanup_confirmed and bad.stdout==bad.stderr==b''
    invalid=run(argv(1),timeout_s=31)
    assert invalid.reason_code=='INVALID_COMMAND_CONTRACT' and invalid.rc is None


def test_actual_projection_keeps_fips_and_readiness_separate(reader):
    from tools import assessment, evidence, platform
    root,r=reader
    _write(root,acq.PATHS['kernel-fips'],b'1\n')
    snapshot=r.collect()|{'profile-show':original.parse_source('profile-show',b'FIPS\n',rc=0)}
    source=dict(source_kind='SYNTHETIC',producer_id=original.COLLECTOR,producer_version=original.COLLECTOR_VERSION,
                origin_ref='fixture-policy-cp1',input_sha256=None)
    host=evidence.host_id('fixture-authority','fixture-policy.example.invalid');ts='2026-01-01T00:00:00Z'
    doc=dict(schema_version='1.1.0',run=dict(run_id='fixture-run-cp1',run_state='COMPLETE',recorded_at=ts,
        started_at=None,finished_at=None,source=source,expected_host_ids=[host]),
        hosts=[dict(host_id=host,target_id='fixture-policy.example.invalid',identity_scope='STABLE',host_state='COMPLETE',
                    reason_code='FIXTURE',inventory_authority_id='fixture-authority',identity_key=None)],
        collections=[],assets=[],evidence=[],claims=[],findings=[])
    rules=assessment.load_rules((ROOT/'config/assessment_rules.yml').read_bytes())
    facts=dict(distribution='OracleLinux',os_family='RedHat',distribution_version='9.8',distribution_major_version='9',architecture='x86_64')
    tools={k:[dict(state='OK',exists=True,isreg=True,islnk=False,executable=True) for _ in range(n)] for k,n in platform.TOOL_SLOTS.items()}
    rows=original.build_crypto_policy_evidence(doc,host,source=source,observed_at=ts,snapshot=snapshot,rules=rules,
                platform_snapshot=dict(facts_state='OK',facts=facts,tools=tools,rpms={}),requested=True)
    assert len(rows['collections'])==9 and rows['metadata']['kernel_fips_enabled'] is True
    assert rows['metadata']['profile_consistency']=='CONFLICT'
    configs=[e for e in rows['evidence'] if e['evidence_kind']=='EFFECTIVE_CONFIGURATION']
    assert configs and all(e['data']['allowed'] is None for e in configs)
    evaluated=assessment.evaluate_document(doc|{'collections':rows['collections'],'evidence':rows['evidence']},rules)
    assert evaluated['claims'] and all(c['level']=='L3' and c['assessment_state']=='UNKNOWN' for c in evaluated['claims'])


def test_untrusted_root_and_exact_file_cap(reader,monkeypatch):
    root,r=reader
    monkeypatch.setattr(acq,'_TRUSTED_UID',0)
    with pytest.raises(acq.Fault,match='UNSAFE_SOURCE'):acq.Reader(r.root,time.monotonic()+23)
    monkeypatch.setattr(acq,'_TRUSTED_UID',os.geteuid())
    data=b'DEFAULT\n#'+b'x'*(acq.FILE_LIMIT-len(b'DEFAULT\n#'))
    _write(root,acq.PATHS['profile-config'],data)
    assert r.slot('profile-config')==original.parse_source('profile-config',data)
