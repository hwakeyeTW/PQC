"""I1a R2: actual native synthetic worker and existing producer APIs.

Only fixed, private, synthetic inputs and trusted test-injected adapters.
No real transport, inventory, credentials or acquisition commands.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import sys
import time

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import scan_collectors as bridge, evidence, assessment, openssl_runtime as ssl
from tools import platform, crypto_policy as policy, ssh_posture as ssh, cert_assets as cert
from test_batch import batch, fixture, helper, cmd, selected_flags, _observe_native_queue, _signal_state

RULES = assessment.load_rules((ROOT / 'config/assessment_rules.yml').read_bytes())
RUN = 'i1a-fixture'
HOST = 'host.example.invalid'
TIME = '2026-01-01T00:00:00Z'
ALL = selected_flags(bridge.PACKAGES, bridge.SSL, bridge.POLICY_FLAG, bridge.SSHD, bridge.KEYS, bridge.CERT_FLAG)


def platform_snapshot(distribution='OracleLinux'):
    return dict(facts_state='OK', facts=dict(distribution=distribution, os_family='RedHat',
        distribution_version='9.9', distribution_major_version='9', architecture='x86_64'),
        tools={k: [dict(state='OK', exists=True, isreg=True, islnk=False, executable=True) for _ in range(n)]
               for k, n in platform.TOOL_SLOTS.items()},
        rpms={k: dict(state='COLLECTED', reason='OK', rows=[[k, '9.9', '1', 'x86_64']]) for k in platform.PACKAGES}
        if distribution == 'OracleLinux' else {})


def ssl_snapshot(p, flags=ALL, partial=False):
    values = {'rpm-openssl': [['openssl', '3.5.5', '1', 'x86_64']],
              'rpm-openssl-libs': [['openssl-libs', '3.5.5', '1', 'x86_64']],
              'version': [['3.5.5', '3.5.5']],
              'providers': [[f'fixture-{i:03}', '3.5.5', 'active'] for i in range(p)],
              'kem': [['fixture-000', ['ML-KEM-768']]],
              'signature': [['fixture-000', ['ML-DSA-44']]],
              'tls-groups': [[None, ['X25519MLKEM768']]]}
    if partial and p:
        values['providers'][0][1] = None
    slots = {}
    for s, rows in values.items():
        enabled = flags[bridge.PACKAGES if s in ssl.PACKAGES else bridge.SSL]
        if not enabled:
            slots[s] = dict(state='NOT_SCANNED', reason='DISABLED_BY_USER', rc=None, rows=[])
        elif not rows:
            slots[s] = dict(state='UNKNOWN', reason='NO_OUTPUT', rc=0, rows=[])
        else:
            gap = s == 'providers' and partial
            slots[s] = dict(state='PARTIAL' if gap else 'COLLECTED', reason='FORMAT_GAP' if gap else 'OK', rc=0, rows=rows)
    return dict(flags={f: flags[f] for f in ssl.FLAGS}, platform_status='UNVERIFIED', slots=slots)


def policy_snapshot():
    rows = {s: policy.result('UNKNOWN', 'SOURCE_ABSENT') for s in policy.SCOPES}
    rows['profile-config'] = policy.result('COLLECTED', 'OK', [['profile', 'DEFAULT']])
    rows['profile-show'] = policy.result('COLLECTED', 'OK', [['profile', 'DEFAULT']], rc=0)
    rows['kernel-fips'] = policy.result('COLLECTED', 'OK', [['fips-enabled', False]])
    rows['local-overrides'] = policy.result('COLLECTED', 'OK', [['entry-count', 0]])
    return rows


def ssh_snapshot(flags=ALL, contexts=2):
    result = dict(flags={f: flags[f] for f in ssh.FLAGS}, platform_status='UNVERIFIED',
                  context_refs=['global-default', ssh.digest('ctx', ['fixture-second'])][:contexts], slots={})
    for s in ssh.slots(result):
        enabled = flags[bridge.KEYS if s == 'keys' else bridge.SSHD]
        state, reason = ('NOT_SCANNED', 'DISABLED_BY_USER') if not enabled else (
            ('UNKNOWN', 'KEY_FLAG_REQUIRED') if s.startswith('native-') and not flags[bridge.KEYS] else
            ('UNKNOWN', 'NATIVE_SAFETY_UNPROVEN') if s in ssh.CLIENTS or s.startswith('native-') else ('UNKNOWN', 'TOOL_UNAVAILABLE'))
        result['slots'][s] = dict(state=state, reason=reason, rc=None, rows=[], gaps=[])
    if flags[bridge.KEYS]:
        result['slots']['keys'] = dict(state='COLLECTED', reason='OK', rc=None, gaps=[], rows=[dict(
            source_ref='key-'+'a'*64, key_type='ssh-ed25519', bits=256, fingerprint_sha256='b'*64, grammar='KNOWN')])
    return result


def cert_snapshot(with_cert=True):
    roots = {s: dict(attempted=True, rc=0, entries=0, directories=0, skipped=0,
        root_target_id='src-'+hashlib.sha256(cert.ROOT_PATHS[s].encode()).hexdigest(), gaps=[], sources=[]) for s in cert.ROOTS}
    if with_cert:
        c = dict(fingerprint='c'*64, public_key_algorithm='rsaEncryption', public_key_bits=2048,
                 signature_inner='sha256WithRSAEncryption', signature_outer='sha256WithRSAEncryption',
                 issuer='CN=fixture-ca', subject='CN=fixture-cert', not_before=TIME,
                 not_after='2027-01-01T00:00:00Z', gaps=[])
        root = roots[cert.ROOTS[0]]
        root.update(entries=1, sources=[dict(source_id='src-'+'d'*64, target_id='src-'+'e'*64,
                      format='DER', gaps=[], blocks=[dict(rc=0, reason='OK', certificate=c)])])
    return dict(system_python_available=True, roots=roots)


def snapshots(p=2, flags=ALL, partial=False):
    return {bridge.PLATFORM: platform_snapshot(), bridge.OPENSSL: ssl_snapshot(p, flags, partial),
            bridge.POLICY: policy_snapshot(), bridge.SSH: ssh_snapshot(flags), bridge.CERT: cert_snapshot()}


def envelope(p=2, flags=ALL, target=HOST, partial=False):
    data = snapshots(p, flags, partial)
    rows = [dict(producer_id=prod, observed_at=TIME, reason_code='COMMAND_OK', rc=0,
                 cleanup_confirmed=True, snapshot=data[prod]) for prod in bridge.requested(flags)]
    return dict(handoff_version=1, run_id=RUN, target_id=target, connection='CONNECTED', records=rows)


def project(p=2, flags=ALL, target=HOST, partial=False):
    raw = bridge.wire_bytes(envelope(p, flags, target, partial))
    return bridge.normalize_handoff(bridge.read_wire(raw), RUN, target, flags, TIME, RULES)


@pytest.mark.parametrize('p', [0, 1, 2, 256])
def test_actual_projection_and_exact_scope(p):
    projection = project(p)
    assert projection.provider_count == p
    doc = projection.document
    evidence.validate_document(doc)
    assert evidence.parse_evidence_bytes(evidence.canonical_bytes(doc)) == evidence.parse_evidence_bytes(evidence.canonical_bytes(copy.deepcopy(doc)))
    assessed = assessment.evaluate_document(doc, RULES)
    assert evidence.canonical_bytes(assessed)
    out = projection.outcomes
    expected = {bridge.PLATFORM: 10, bridge.PACKAGES: 2, bridge.SSL: 5+p, bridge.POLICY_FLAG: 9,
                bridge.SSHD: 8, bridge.KEYS: 1, bridge.CERT_FLAG: 3, bridge.NGINX: 0, bridge.TLS: 0}
    assert {k: len(v['collection_ids']) for k,v in out.items()} == expected
    refs = {i for v in out.values() for i in v['collection_ids']}
    assert len(refs) == len(doc['collections']) == 38+p
    scopes = {ssl.key('openssl-provider', f'fixture-{i:03}') for i in range(p)}
    hid = doc['hosts'][0]['host_id']
    assert {evidence.collection_id(RUN, hid, bridge.OPENSSL, s) for s in scopes} <= set(out[bridge.SSL]['collection_ids'])
    assert all(c['source']['source_kind'] == 'SYNTHETIC' for c in doc['collections'])
    assert all(c['level'] not in ('L3','L4','L5') or c['assessment_state'] != 'PASS' for c in assessed['claims'])
    assert ssh.validate_details(doc, projection.companions[bridge.SSH], RULES) is None
    assert cert.validate_cert_details(doc, projection.companions[bridge.CERT], RULES) is None
    assert len(doc['assets']) == 2


def test_partial_provider_metadata_is_not_dropped():
    p = project(2, partial=True)
    assert len(p.outcomes[bridge.SSL]['collection_ids']) == 7
    cid = evidence.collection_id(RUN, p.document['hosts'][0]['host_id'], bridge.OPENSSL, ssl.key('openssl-provider','fixture-000'))
    assert next(c for c in p.document['collections'] if c['collection_id']==cid)['collection_state'] == 'PARTIAL'


@pytest.mark.parametrize('fault', ['257', 'duplicate', 'malformed', 'wrong-flags', 'claimed-p', 'wrong-order', 'foreign', 'extra-record', 'partial-record'])
def test_actual_bridge_rejects_invalid_typed_snapshots(fault):
    data = envelope()
    s = data['records'][1]['snapshot']
    if fault == '257':
        s['slots']['providers']['rows'] = ssl_snapshot(257)['slots']['providers']['rows']
    elif fault == 'duplicate':
        s['slots']['providers']['rows'].append(s['slots']['providers']['rows'][0].copy())
    elif fault == 'malformed':
        s['slots']['providers']['rows'][0][0] = 'bad name'
    elif fault == 'wrong-flags':
        s['flags'][bridge.SSL] = False
    elif fault == 'claimed-p':
        data['provider_count'] = 256
    elif fault == 'wrong-order':
        data['records'][0], data['records'][1] = data['records'][1], data['records'][0]
    elif fault == 'foreign':
        data['target_id'] = 'foreign.example.invalid'
    elif fault == 'extra-record':
        data['records'].append(copy.deepcopy(data['records'][-1]))
    else:
        data['records'].pop()
    with pytest.raises((bridge.BridgeError, evidence.EvidenceError, ValueError)):
        bridge.normalize_handoff(bridge.read_wire(bridge.wire_bytes(data)), RUN, HOST, ALL, TIME, RULES)


@pytest.mark.parametrize('fault', ['hash','partial','duplicate','foreign','wrong-run','receipt-extra','mode','symlink','hardlink','overflow','malformed','extra-slot'])
def test_private_handoff_receipt_and_files(tmp_path, monkeypatch, fault):
    monkeypatch.setattr(bridge.tempfile, 'tempdir', str(tmp_path))
    handoff = bridge.Handoff(RUN, [HOST])
    name,fd,_ = handoff.slots[HOST]
    path=Path(handoff.path)
    assert stat.S_IMODE(path.stat().st_mode)==0o700
    assert stat.S_IMODE(os.fstat(fd).st_mode)==0o600
    receipt=handoff.write(HOST, envelope())
    slot=path/name
    external=tmp_path/'external'
    external.write_bytes(b'unchanged')
    try:
        if fault=='hash':
            os.pwrite(fd,b'X',0)
        elif fault=='partial':
            os.ftruncate(fd, receipt['byte_count']-1)
        elif fault=='duplicate':
            assert handoff.read(HOST,receipt)==envelope()
        elif fault=='foreign':
            receipt['target_id']='foreign.example.invalid'
        elif fault=='wrong-run':
            receipt['run_id']='other-run'
        elif fault=='receipt-extra':
            receipt['path']=str(external)
        elif fault=='mode':
            os.fchmod(fd,0o644)
        elif fault=='symlink':
            slot.rename(path/'saved'); slot.symlink_to(external)
        elif fault=='hardlink':
            os.link(slot,tmp_path/'link')
        elif fault=='overflow':
            os.ftruncate(fd, bridge.MAX_WIRE+1)
        elif fault=='malformed':
            bad=b'{"x":1,"x":2}'
            os.ftruncate(fd,0); os.pwrite(fd,bad,0)
            receipt.update(byte_count=len(bad),sha256=hashlib.sha256(bad).hexdigest())
        elif fault=='extra-slot':
            with pytest.raises(bridge.BridgeError):
                handoff.write('foreign.example.invalid', envelope(target='foreign.example.invalid'))
            return
        with pytest.raises((bridge.BridgeError,OSError)):
            handoff.read(HOST,receipt)
    finally:
        assert external.read_bytes()==b'unchanged'
        # Explicitly undo test-only interference before closing. A separate
        # test below proves cleanup refuses a replaced file.
        if fault=='symlink':
            slot.unlink(); (path/'saved').rename(slot)
        if fault=='hardlink': (tmp_path/'link').unlink()
        if fault=='mode': os.fchmod(fd,0o600)
        assert handoff.close()
        assert not path.exists()


def test_cleanup_never_unlinks_replacement(tmp_path, monkeypatch):
    monkeypatch.setattr(bridge.tempfile, 'tempdir', str(tmp_path))
    h=bridge.Handoff(RUN,[HOST]); path=Path(h.path); slot=path/h.slots[HOST][0]
    external=tmp_path/'external'; external.write_bytes(b'unchanged')
    slot.rename(path/'saved'); slot.symlink_to(external)
    assert not h.close()
    assert slot.is_symlink() and external.read_bytes()==b'unchanged'
    slot.unlink(); (path/'saved').unlink(); path.rmdir()


@pytest.mark.parametrize('kind', ['directory', 'slot'])
def test_partial_handoff_initialization_closes_owned_fds(tmp_path, monkeypatch, kind):
    monkeypatch.setattr(bridge.tempfile, 'tempdir', str(tmp_path))
    original_fstat = os.fstat
    opened = []
    failed = []

    def fail_once(fd):
        current = original_fstat(fd)
        if not failed and (stat.S_ISDIR(current.st_mode) if kind == 'directory' else
                           stat.S_ISREG(current.st_mode)):
            failed.append(fd)
            raise OSError('synthetic initial fstat failure')
        return current

    original_open = os.open

    def track_open(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        opened.append(fd)
        return fd

    monkeypatch.setattr(os, 'open', track_open)
    monkeypatch.setattr(os, 'fstat', fail_once)
    with pytest.raises(OSError, match='synthetic initial fstat failure'):
        bridge.Handoff(RUN, [HOST])
    assert failed and opened
    for fd in opened:
        with pytest.raises(OSError):
            original_fstat(fd)
    assert not list(tmp_path.iterdir())


def test_wire_capacity_and_secret_rejection():
    for data in ({'x':'x'*bridge.MAX_WIRE}, {'private':'-----BEGIN PRIVATE KEY-----'}, {'x':'{{sentinel}}'}, {'x':float('nan')}):
        with pytest.raises(bridge.BridgeError): bridge.wire_bytes(data)
    assert bridge.read_wire(bridge.wire_bytes({'x':'a'*100}))=={'x':'a'*100}


def register(monkeypatch, trace, p=2, modes=None, delay=0, slots=bridge.PRODUCERS):
    """Actual bounded local producer surrogate, never an acquisition adapter."""
    modes=modes or {}
    def acquire(prod, name, flags, platform_data):
        mode=modes.get((name,prod),'ok')
        if mode=='worker-loss': os._exit(17)
        if mode=='cleanup':
            return dict(reason_code='REMOTE_CLEANUP_UNCONFIRMED',rc=None,cleanup_confirmed=False,snapshot=None)
        payload=snapshots(p[name] if isinstance(p,dict) else p,flags)[prod]
        if mode=='bad': payload['raw_private_key']='DUMMY_PRIVATE_SENTINEL'
        if mode=='out-of-scope': payload=platform_snapshot('Debian')
        if mode=='uncertain-snapshot':
            payload['slots']['providers'] = dict(state='ERROR',reason='CLEANUP_UNCONFIRMED',rc=None,rows=[])
        path=trace.parent/(name+'.'+prod+'.json')
        source=trace.parent/(name+'.'+prod+'.fixture')
        fd=os.open(source,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w',encoding='ascii') as f:
            json.dump(payload,f,separators=(',',':'))
        code=f'''import json,os,pathlib,time
start=time.monotonic_ns()
time.sleep({(1.0 if mode=='timeout' else delay)!r})
pathlib.Path({str(path)!r}).write_text(json.dumps([start,time.monotonic_ns(),os.getpid(),os.getppid()]))
print(pathlib.Path({str(source)!r}).read_text())
raise SystemExit({7 if mode=='error' else 0})
'''
        r=helper.run_bounded(cmd(code),timeout_s=.5 if mode=='timeout' else 3)
        return dict(reason_code=r.reason_code,rc=r.rc,cleanup_confirmed=r.cleanup_confirmed,
                    snapshot=json.loads(r.stdout) if r.reason_code=='COMMAND_OK' else None)
    monkeypatch.setattr(bridge,'_producer_adapters',lambda:{prod:(lambda n,f,d,prod=prod:acquire(prod,n,f,d)) for prod in slots})
    monkeypatch.setattr(batch,'_restricted_connection',lambda n:'CONNECTED')


def checked(ctx):
    rc, manifest, bundle=batch.execute_producer_batch(ctx,RULES)
    assert batch.validate_producer_manifest(manifest,rc) is None
    evidence.validate_document(bundle['document'])
    evidence.validate_document(bundle['assessed'])
    with pytest.raises(batch.Denied): batch.validate_terminal_manifest(manifest,rc)
    return rc,manifest,bundle


def test_native_256_provider_handoff(fixture, monkeypatch):
    make,_,trace,trap,_=fixture
    ctx,names=make(count=1,flags=ALL)
    register(monkeypatch,trace,p=256)
    rc,m,bundle=checked(ctx)
    n=names[0]; row=m['hosts'][0]; d=bundle['document']; metrics=bundle['handoff_metrics'][n]
    assert rc==5 and row['host_state']=='PARTIAL', (rc,m,bundle['handoff_metrics'])  # policy/SSH gaps retained
    assert len(row['platform']['collection_ids'])==10
    by={x['collector_id']:x for x in row['collectors']}
    assert len(by[bridge.SSL]['collection_ids'])==261
    assert sum(len(x['collection_ids']) for x in [row['platform'],*row['collectors']])==len(d['collections'])==294
    assert 0<metrics['typed_bytes']<=bridge.MAX_WIRE and 0<metrics['ipc_bytes']<=3500
    intervals=[json.loads((trace.parent/(n+'.'+prod+'.json')).read_text()) for prod in bridge.PRODUCERS]
    assert len({x[3] for x in intervals})==1 and intervals[0][3]!=os.getpid()
    assert all(a[1]<=b[0] for a,b in zip(intervals,intervals[1:]))
    assert all(not Path('/proc',str(x[2])).exists() for x in intervals)
    assert not Path('/proc',str(intervals[0][3])).exists()
    assert trace.read_text().splitlines()==['["--list"]'] and not trap.exists()
    print('I1A_256',json.dumps(dict(**metrics,normalized_bytes=len(evidence.canonical_bytes(d)),
              assessed_bytes=len(evidence.canonical_bytes(bundle['assessed'])),collections=len(d['collections']),
              companion_bytes=len(json.dumps(bundle['companions'],separators=(',',':')).encode()),
              max_surrogate_output_bytes=max((trace.parent/(n+'.'+prod+'.fixture')).stat().st_size+1 for prod in bridge.PRODUCERS),
              worker=intervals[0][3])))


@pytest.mark.parametrize('fault',['missing','nginx','tls','disabled'])
def test_v2_before_connect_no_dispatch(fixture, monkeypatch, fault):
    make,_,trace,trap,_=fixture
    flags=selected_flags() if fault=='disabled' else selected_flags(bridge.SSL if fault=='missing' else bridge.NGINX if fault=='nginx' else bridge.TLS)
    if fault=='tls':
        with pytest.raises(batch.Denied): make(count=1,flags=flags)
        return
    ctx,_=make(count=2,flags=flags,profile='extended' if fault=='nginx' else 'baseline')
    monkeypatch.setattr(batch,'_restricted_connection',lambda n:pytest.fail('connected'))
    if fault=='disabled':
        rc,m,b=checked(ctx); assert rc==6 and all(not r['attempted'] for r in m['hosts']) and not b['document']['collections']
    else:
        with pytest.raises(batch.Denied): batch.execute_producer_batch(ctx,RULES)
    assert not trap.exists() and not list(trace.parent.glob('*.json'))


@pytest.mark.parametrize('fault',['missing','extra','wrong-diagnostic','wrong-source'])
def test_actual_normalizer_partition_negative(monkeypatch, fault):
    original=ssl.normalize_openssl
    def corrupt(*args):
        doc,diagnostics=original(*args)
        diag=next(d for d in diagnostics if d.get('provider')=='fixture-001')
        cid=diag['collection_id']; c=next(c for c in doc['collections'] if c['collection_id']==cid)
        if fault=='missing':
            doc['collections'].remove(c)
            doc['evidence']=[e for e in doc['evidence'] if e['collection_id']!=cid]
            diagnostics.remove(diag)
        elif fault=='extra':
            extra={**c,'scope_key':ssl.key('openssl-provider','unobserved'), 'evidence_ids':[],
                   'collection_state':'UNKNOWN','reason_code':'NO_DATA'}
            extra['collection_id']=evidence.collection_id(doc['run']['run_id'],c['host_id'],c['collector_id'],extra['scope_key'])
            doc['collections'].append(extra)
            diagnostics.append({**diag,'collection_id':extra['collection_id'],'provider':'unobserved','state':'UNKNOWN','reason':'NO_DATA'})
        elif fault=='wrong-diagnostic':
            diag['provider']='fixture-000'
        else:
            c['source']['input_sha256']='f'*64
            for e in doc['evidence']:
                if e['collection_id']==cid: e['source']['input_sha256']='f'*64
        evidence.validate_document(doc)
        return doc,diagnostics
    monkeypatch.setattr(ssl,'normalize_openssl',corrupt)
    with pytest.raises(bridge.BridgeError,match='PRODUCER_(SCOPE|DETAIL|SOURCE)_MISMATCH'):
        project(2)


def test_native_exact_binding_and_per_host_cap(fixture, monkeypatch):
    make,_,trace,trap,_=fixture
    ctx,names=make(count=2,flags=ALL)
    register(monkeypatch,trace,p={names[0]:0,names[1]:2})
    captured={}; original=batch._ProducerSession.finish
    def finish(self,ctx,ledger,interrupted):
        captured.update(ledger.projections)
        return original(self,ctx,ledger,interrupted)
    monkeypatch.setattr(batch._ProducerSession,'finish',finish)
    rc,m,bundle=checked(ctx)
    doc,details=bundle['document'],bundle['companions']
    assert bridge.validate_bindings(m,doc,details,captured) is None
    def ssl_refs(row): return next(c for c in row['collectors'] if c['collector_id']==bridge.SSL)['collection_ids']
    a,b=map(ssl_refs,m['hosts'])
    assert len(a)==5 and len(b)==7
    foreign=next(c['collection_id'] for c in doc['collections'] if c['collector_id']==bridge.OPENSSL and c['host_id']==captured[names[1]].document['hosts'][0]['host_id'] and c['scope_key']==ssl.key('openssl-provider','fixture-001'))
    for fault in ('missing','duplicate','extra','wrong-host','wrong-scope','borrow-cap','wrong-outcome','companion','document'):
        altered=copy.deepcopy(m); d=copy.deepcopy(doc); c=copy.deepcopy(details)
        x,y=map(ssl_refs,altered['hosts'])
        if fault=='missing': x.pop()
        elif fault=='duplicate': y.append(y[0]); y.sort()
        elif fault=='extra': x.append('c-'+'f'*64); x.sort()
        elif fault=='wrong-host': x[0],y[0]=y[0],x[0]; x.sort(); y.sort()
        elif fault=='wrong-scope': x[0]='c-'+'0'*64; x.sort()
        elif fault=='borrow-cap': y.remove(foreign); x.append(foreign); x.sort()
        elif fault=='wrong-outcome':
            out=next(z for z in altered['hosts'][0]['collectors'] if z['collector_id']==bridge.SSL)
            out.update(state='UNKNOWN',reason_code='UNKNOWN_RESULT',rc=None)
        elif fault=='companion': c[names[1]][bridge.OPENSSL][-1]['provider']='bad-provider'
        else:
            d['collections']=[z for z in d['collections'] if z['collection_id']!=foreign]
            d['evidence']=[z for z in d['evidence'] if z['collection_id']!=foreign]
            evidence.validate_document(d)
        if fault in ('missing','extra','wrong-host','wrong-scope','borrow-cap'):
            assert batch.validate_producer_manifest(altered,rc) is None
        with pytest.raises(bridge.BridgeError): bridge.validate_bindings(altered,d,c,captured)
    assert not trap.exists()


def test_v2_disabled_refs_and_v1_caps(fixture, monkeypatch):
    make,_,trace,trap,_=fixture
    ctx,names=make(count=1,flags=selected_flags(bridge.PACKAGES))
    register(monkeypatch,trace)
    rc,m,bundle=checked(ctx)
    row=m['hosts'][0]; by={r['collector_id']:r for r in row['collectors']}
    assert rc==0 and len(by[bridge.SSL]['collection_ids'])==5 and by[bridge.SSL]['state']=='NOT_SCANNED'
    assert len(bundle['document']['collections'])==17
    legacy=copy.deepcopy(m); legacy['batch_manifest_version']=1
    legacy['hosts']=[batch._v2_base_row(row)]
    assert batch.validate_terminal_manifest(legacy,rc) is None
    bad=copy.deepcopy(legacy)
    pkg=next(r for r in bad['hosts'][0]['collectors'] if r['collector_id']==bridge.PACKAGES)
    pkg['collection_ids']=[f'c-{i:064x}' for i in range(9)]
    with pytest.raises(batch.Denied): batch.validate_terminal_manifest(bad,rc)
    assert not trap.exists()


def test_v2_platform_gap_does_not_call_later_adapter(fixture, monkeypatch):
    make,_,trace,trap,_=fixture
    ctx,names=make(count=1,flags=ALL)
    register(monkeypatch,trace,modes={(names[0],bridge.PLATFORM):'out-of-scope'})
    rc,m,bundle=checked(ctx)
    assert len(list(trace.parent.glob('*.pqc-*.json')))==1
    assert m['hosts'][0]['platform']['state'] in ('PARTIAL','COLLECTED')
    assert all(c['collection_state'] in ('NOT_SCANNED','NOT_APPLICABLE') for c in bundle['document']['collections'] if c['collector_id']!=bridge.PLATFORM)
    assert not any(c['level'] in ('L2','L3','L4','L5') and c['assessment_state']=='PASS' for c in bundle['assessed']['claims'])
    assert not trap.exists()


@pytest.mark.parametrize('fault',['error','cleanup','bad','worker-loss','uncertain-snapshot'])
def test_v2_native_failure_and_stop(fixture,monkeypatch,fault):
    make,_,trace,trap,_=fixture
    ctx,names=make(count=3,forks=1,flags=selected_flags(bridge.PACKAGES,bridge.SSL))
    register(monkeypatch,trace,modes={(names[0],bridge.OPENSSL):fault})
    rc,m,b=checked(ctx)
    states=[r['host_state'] for r in m['hosts']]
    if fault=='error':
        assert rc==5 and states==['ERROR','COMPLETE','COMPLETE']
        assert len(m['hosts'][0]['platform']['collection_ids'])==10
    else:
        assert rc==6 and states==['ERROR','NOT_ATTEMPTED','NOT_ATTEMPTED']
        assert not list(trace.parent.glob(names[1]+'.*'))
    if fault=='uncertain-snapshot':
        assert m['reason_code']=='REMOTE_CLEANUP_UNCONFIRMED'
        assert len(b['document']['collections'])==17
    if fault=='worker-loss':
        assert not b['document']['collections']
    assert not trap.exists()


@pytest.mark.parametrize('mutation',['foreign','wrong-task','duplicate','hash','partial','path','crash-after'])
def test_native_receipt_fault_and_reap(fixture,monkeypatch,mutation):
    make,_,trace,trap,_=fixture
    ctx,names=make(count=3,forks=1,flags=selected_flags(bridge.PACKAGES,bridge.SSL))
    register(monkeypatch,trace)
    original=batch._make_queue
    def queue(validator=None):
        q=original(validator); put=q.put; send=q.send_task_result
        if mutation=='crash-after':
            def crash(result): send(result); os._exit(12)
            q.send_task_result=crash
        else:
            def corrupt(raw):
                value=json.loads(raw)
                if mutation=='duplicate': put(raw)
                elif mutation=='foreign': value['target_id']='excluded.example.invalid'
                elif mutation=='wrong-task': value['task_uuid']='foreign-task'
                elif mutation=='hash': value['row']['sha256']='0'*64
                elif mutation=='partial': value['row']['byte_count']-=1
                else: value['row']['path']='DUMMY_PRIVATE_SENTINEL'
                put(json.dumps(value,separators=(',',':')).encode())
            q.put=corrupt
        return q
    monkeypatch.setattr(batch,'_make_queue',queue)
    launches=_observe_native_queue(monkeypatch)
    rc,m,b=checked(ctx)
    assert rc==6 and [r['host_state'] for r in m['hosts']]==['ERROR','NOT_ATTEMPTED','NOT_ATTEMPTED']
    assert m['reason_code']==('CONTROLLER_WORKER_FAILED' if mutation=='crash-after' else 'INVALID_NATIVE_RESULT')
    assert len(launches)==1 and not Path('/proc',str(launches[0][1])).exists()
    assert not trap.exists() and 'DUMMY_PRIVATE_SENTINEL' not in json.dumps(m)
    assert not list(trace.parent.glob(names[1]+'.*'))
    if mutation in ('duplicate','crash-after'): assert len(b['document']['collections'])==19
    else: assert not b['document']['collections']


def test_native_forks_two_real_overlap(fixture,monkeypatch):
    make,_,trace,trap,_=fixture
    ctx,names=make(count=4,forks=2,flags=selected_flags(bridge.PACKAGES,bridge.SSL))
    register(monkeypatch,trace,delay=.3)
    rc,m,b=checked(ctx)
    assert rc==0
    spans=[]
    for n in names:
        a=json.loads((trace.parent/(n+'.'+bridge.PLATFORM+'.json')).read_text())
        z=json.loads((trace.parent/(n+'.'+bridge.OPENSSL+'.json')).read_text())
        assert a[3]==z[3] and a[1]<=z[0] and not Path('/proc',str(a[3])).exists()
        spans.append((a[0],z[1],a[3]))
    assert len({x[2] for x in spans})==4
    assert max(spans[0][0],spans[1][0])<min(spans[0][1],spans[1][1])
    assert max(spans[0][1],spans[1][1])<=min(spans[2][0],spans[3][0])
    assert sum(v['typed_bytes'] for v in b['handoff_metrics'].values())<=10*bridge.MAX_WIRE
    assert not trap.exists()


@pytest.mark.parametrize('fault',['guard','partial-start','signal-after','late-signal'])
def test_v2_guard_lifecycle_and_interrupt(fixture,monkeypatch,fault):
    make,_,trace,trap,_=fixture
    ctx,names=make(count=3,forks=1,flags=selected_flags(bridge.PACKAGES,bridge.SSL))
    register(monkeypatch,trace)
    original_guard=batch._guard
    if fault=='guard':
        def guard(ctx,name):
            if name==names[1]: raise batch.Denied(4,'BATCH_GUARD_DENIED')
            original_guard(ctx,name)
        monkeypatch.setattr(batch,'_guard',guard)
    def after(tqm,name):
        if fault=='partial-start': raise RuntimeError('synthetic-start-fault')
        if fault=='signal-after': os.kill(os.getpid(),signal.SIGTERM)
    launches=_observe_native_queue(monkeypatch,after=after)
    if fault=='late-signal':
        evaluate=bridge.assessment.evaluate_document
        def interrupted(*a,**k):
            os.kill(os.getpid(),signal.SIGINT)
            return evaluate(*a,**k)
        monkeypatch.setattr(bridge.assessment,'evaluate_document',interrupted)
    before=_signal_state()
    rc,m,b=checked(ctx)
    assert rc==(7 if fault in ('signal-after','late-signal') else 5 if fault=='guard' else 6)
    assert m['reason_code']==('INTERRUPTED' if fault in ('signal-after','late-signal') else 'GUARD_REJECTED' if fault=='guard' else 'INVALID_NATIVE_RESULT')
    assert m['run_state']!='COMPLETE' and _signal_state()==before
    assert len(launches)==(3 if fault=='late-signal' else 1)
    assert all(not Path('/proc',str(pid)).exists() for _,pid in launches) and not trap.exists()


def test_cleanup_reports_hardlink_uncertain(tmp_path,monkeypatch):
    monkeypatch.setattr(bridge.tempfile,'tempdir',str(tmp_path))
    h=bridge.Handoff(RUN,[HOST]); path=Path(h.path); slot=path/h.slots[HOST][0]
    h.write(HOST,envelope())
    outside=tmp_path/'outside-link'; os.link(slot,outside)
    assert not h.close() and not path.exists() and outside.is_file()
    outside.unlink()


def test_handoff_capacity_exclusive_slots(tmp_path,monkeypatch):
    monkeypatch.setattr(bridge.tempfile,'tempdir',str(tmp_path))
    targets=[f'host-{i}.example.invalid' for i in range(10)]
    h=bridge.Handoff(RUN,targets)
    try:
        assert len(h.slots)==10
        assert len({s[2].st_ino for s in h.slots.values()})==10
        with pytest.raises(bridge.BridgeError): bridge.Handoff(RUN,targets+['overflow.example.invalid'])
        for n in targets:
            data=envelope(p=0,target=n); receipt=h.write(n,data)
            assert h.read(n,receipt)==data
            with pytest.raises(bridge.BridgeError): h.write(n,data)
        assert h.total<=10*bridge.MAX_WIRE
    finally: assert h.close()


@pytest.mark.parametrize('fault',['future','backward','old'])
def test_observation_time_bound(fault):
    data=envelope()
    if fault=='future': data['records'][1]['observed_at']='9999-01-01T00:00:00Z'
    elif fault=='old': data['records'][0]['observed_at']='2025-01-01T00:00:00Z'
    else:
        data['records'][0]['observed_at']='2026-01-01T00:00:01Z'
    with pytest.raises(bridge.BridgeError,match='PRODUCER_TIME_MISMATCH'):
        bridge.normalize_handoff(data,RUN,HOST,ALL,TIME,RULES)


def test_handoff_overflow_before_write(tmp_path,monkeypatch):
    monkeypatch.setattr(bridge.tempfile,'tempdir',str(tmp_path))
    h=bridge.Handoff(RUN,[HOST]); fd=h.slots[HOST][1]
    try:
        data=envelope(); data['invalid_test_field']='x'*bridge.MAX_WIRE
        with pytest.raises(bridge.BridgeError,match='HANDOFF_SIZE_LIMIT'):
            h.write(HOST,data)
        assert os.fstat(fd).st_size==0
    finally: assert h.close()


def test_v2_native_confirmed_timeout_continues(fixture,monkeypatch):
    make,_,trace,trap,_=fixture
    ctx,names=make(count=2,forks=1,flags=selected_flags(bridge.PACKAGES,bridge.SSL))
    register(monkeypatch,trace,modes={(names[0],bridge.OPENSSL):'timeout'})
    rc,m,b=checked(ctx)
    assert rc==5 and [r['host_state'] for r in m['hosts']]==['ERROR','COMPLETE']
    assert any(c['reason_code']=='COMMAND_TIMEOUT' for c in m['hosts'][0]['collectors'])
    assert not trap.exists()


def test_v2_controller_deadline_reaps_actual_worker(fixture,monkeypatch):
    make,_,trace,trap,_=fixture
    ctx,names=make(count=2,forks=1,flags=selected_flags(bridge.PACKAGES))
    register(monkeypatch,trace)
    monkeypatch.setattr(batch,'_GUARD_SECONDS',2)
    monkeypatch.setattr(batch,'_SSH_SECONDS',.5)
    monkeypatch.setattr(batch,'_COMMAND_SECONDS',.5)
    monkeypatch.setattr(batch,'_WORKER_GRACE',.5)
    marker=trace.parent/'hung-v2-worker'
    def hang(self,*a):
        marker.write_text(str(os.getpid()))
        time.sleep(60)
    monkeypatch.setattr(batch._ProducerSession,'collect',hang)
    begin=time.monotonic(); rc,m,b=checked(ctx); elapsed=time.monotonic()-begin
    assert elapsed<15 and rc==6 and m['reason_code']=='CONTROLLER_TIMEOUT'
    assert [r['host_state'] for r in m['hosts']]==['ERROR','NOT_ATTEMPTED']
    assert not Path('/proc',marker.read_text()).exists() and not trap.exists()
    assert not list(Path(os.environ['TMPDIR']).glob('pqc-i1a-*'))
    print('I1A_DEADLINE',round(elapsed,3))


def test_v2_native_cleanup_uncertainty(fixture,monkeypatch):
    make,_,trace,trap,_=fixture
    ctx,names=make(count=2,forks=1,flags=selected_flags(bridge.PACKAGES))
    register(monkeypatch,trace)
    original=batch._stop_workers; pids=[]
    def stop(workers):
        owned=[w.pid for w in workers if w is not None and w.pid is not None]
        assert original(workers)
        if owned and not pids:
            pids.extend(owned)
            return False
        return True
    monkeypatch.setattr(batch,'_stop_workers',stop)
    rc,m,b=checked(ctx)
    assert rc==6 and m['reason_code']=='CONTROLLER_CLEANUP_UNCONFIRMED'
    assert [r['host_state'] for r in m['hosts']]==['ERROR','NOT_ATTEMPTED']
    assert len(b['document']['collections'])==17 and all(not Path('/proc',str(pid)).exists() for pid in pids)
    assert not trap.exists()


def test_v2_connection_failure_receipt_is_provisional(fixture,monkeypatch):
    make,_,trace,trap,_=fixture
    ctx,names=make(count=2,forks=1,flags=selected_flags(bridge.PACKAGES))
    register(monkeypatch,trace)
    monkeypatch.setattr(batch,'_restricted_connection',lambda n:'CONNECTION_FAILED')
    original=batch._make_queue
    def queue(validator=None):
        q=original(validator); send=q.send_task_result
        def crash(result): send(result); os._exit(12)
        q.send_task_result=crash
        return q
    monkeypatch.setattr(batch,'_make_queue',queue)
    rc,m,b=checked(ctx)
    row=m['hosts'][0]
    assert rc==6 and row['host_state']=='ERROR' and row['platform']['state']=='ERROR'
    assert all(c['state']=='ERROR' for c in row['collectors'] if c['requested'])
    assert not b['document']['collections'] and not trap.exists()


def test_v2_earliest_worker_deadline_interrupts_native_receipt_normalization(fixture, monkeypatch):
    """Both workers run; B's verified receipt must not buy A a fresh guard."""
    make,_,trace,trap,_=fixture
    ctx,names=make(count=3,forks=2,flags=selected_flags(bridge.PACKAGES))
    a,b,unstarted=names
    register(monkeypatch,trace)
    monkeypatch.setattr(batch,'_WORKER_GRACE',3)
    a_started=trace.parent/'a-started'
    b_verified=trace.parent/'b-verified'
    b_sent=trace.parent/'b-sent'
    marks={}; waves=[]; owned=[]; handoffs=[]

    def wait_for(path):
        end=time.monotonic()+10
        while not path.exists():
            if time.monotonic()>=end:
                raise RuntimeError('synthetic synchronization timeout')
            time.sleep(.01)

    collect=batch._ProducerSession.collect
    def collect_sync(self,name,flags,registry):
        if name==a:
            a_started.write_text(str(os.getpid()))
        receipt=collect(self,name,flags,registry)
        if name==a:
            wait_for(b_verified)
        return receipt
    monkeypatch.setattr(batch._ProducerSession,'collect',collect_sync)

    make_queue=batch._make_queue
    def queue(validator=None):
        q=make_queue(validator); send=q.send_task_result
        def send_sync(result):
            if result.as_wire_task_result().host_name==b:
                wait_for(a_started)
                b_sent.write_text(str(os.getpid()))
                send(result)
                # Keep this actual WorkerProcess alive after its synchronous
                # receipt. No helper is still running; bounded test-only wait.
                time.sleep(15)
            else:
                send(result)
        q.send_task_result=send_sync
        return q
    monkeypatch.setattr(batch,'_make_queue',queue)

    track=batch._WorkerWave.track
    def track_earlier(self,name,worker,task_uuid,end):
        now=time.monotonic()
        if name==b:
            end=min(end,now+8)
        track(self,name,worker,task_uuid,end)
        waves.append(self)
        owned.append((name,worker,worker.pid))
        marks[name]={'pid':worker.pid,'tracked':now,'end':end}
    monkeypatch.setattr(batch._WorkerWave,'track',track_earlier)

    accept=batch._ProducerLedger.accept
    def accept_sync(self,message):
        accept(self,message)
        if message['target_id']==b:
            assert b in self.projections and b in self.rows
            marks['b_verified']=time.monotonic()
            b_verified.write_text('verified')
    monkeypatch.setattr(batch._ProducerLedger,'accept',accept_sync)

    initialize=bridge.Handoff.__init__
    def record_handoff(self,*args,**kwargs):
        initialize(self,*args,**kwargs)
        handoffs.append((Path(self.path),[self.dirfd,*[slot[1] for slot in self.slots.values()]]))
    monkeypatch.setattr(bridge.Handoff,'__init__',record_handoff)

    normalize=bridge._normalize
    def slow_normalize(doc,host,producer,*args):
        result=normalize(doc,host,producer,*args)
        if producer==bridge.PLATFORM and host['host_id']==bridge.host_record(doc['run']['run_id'],a)['host_id']:
            wave=waves[-1]
            assert set(wave.workers)=={a,b} and b in wave.ledger.projections
            assert wave.workers[b].is_alive() and b not in wave.confirmed
            assert int(a_started.read_text())==wave.workers[a].pid
            assert int(b_sent.read_text())==wave.workers[b].pid
            earliest=wave.limit(); now=time.monotonic()
            assert earliest==min(wave.ends[b],wave.grace.get(b,wave.ends[b]))<wave.ends[a]
            assert .15<earliest-now<=8
            marks.update(normalize_entered=now,earliest=earliest,alarm=signal.getitimer(signal.ITIMER_REAL)[0])
            try:
                # A real platform normalization has run inside the actual
                # typed handoff normalization, but the host projection is not
                # yet validated/committed. Cross B's existing deadline.
                time.sleep(earliest-now+1.2)
            except batch._Deadline:
                marks['deadline_trigger']=time.monotonic()
                raise
            marks['slow_returned']=time.monotonic()
        return result
    monkeypatch.setattr(bridge,'_normalize',slow_normalize)

    stop=batch._stop_workers
    def observe_stop(workers):
        if any(w is not None and w.pid is not None for w in workers):
            marks.setdefault('stop_entered',time.monotonic())
        quiet=stop(workers)
        if 'stop_entered' in marks:
            marks.setdefault('stop_finished',time.monotonic())
        return quiet
    monkeypatch.setattr(batch,'_stop_workers',observe_stop)
    launches=_observe_native_queue(monkeypatch)
    signals=_signal_state()
    rc,m,bundle=checked(ctx)
    marks['batch_finished']=time.monotonic()
    print('I1A_EARLIEST_WORKER_DEADLINE',json.dumps(marks,sort_keys=True))
    assert 'normalize_entered' in marks and 'deadline_trigger' in marks and 'slow_returned' not in marks
    assert marks['b_verified']<=marks['normalize_entered']<marks['earliest']
    assert 0<marks['alarm']<=marks['earliest']-marks['normalize_entered']+.1
    assert marks['earliest']-.1<=marks['deadline_trigger']<=marks['earliest']+.7
    assert marks['deadline_trigger']<=marks['stop_entered']<=marks['earliest']+.9
    assert marks['stop_finished']-marks['stop_entered']<=batch._WORKER_GRACE+.7
    assert rc==6 and m['reason_code']=='CONTROLLER_TIMEOUT'
    assert [r['host_state'] for r in m['hosts']]==['ERROR','ERROR','NOT_ATTEMPTED']
    assert [r['reason_code'] for r in m['hosts'][:2]]==['CONTROLLER_TIMEOUT']*2
    assert [n for n,_ in launches]==[a,b] and [(n,pid) for n,_,pid in owned]==launches
    assert not list(trace.parent.glob(unstarted+'.*')) and not trap.exists()
    assert set(bundle['handoff_metrics'])==set(bundle['companions'])=={b}
    refs=[cid for row in [m['hosts'][1]['platform'],*m['hosts'][1]['collectors']]
          for cid in row['collection_ids']]
    assert len(refs)==17 and set(refs)=={c['collection_id'] for c in bundle['document']['collections']}
    assert not any(c['collection_ids'] or c['state']=='COLLECTED'
                   for c in [m['hosts'][0]['platform'],*m['hosts'][0]['collectors']])
    assert all(worker._closed and not Path('/proc',str(pid)).exists() and not batch._scope.group_exists(pid)
               for _,worker,pid in owned)
    assert len(handoffs)==1
    for path,fds in handoffs:
        assert not path.exists()
        for fd in fds:
            with pytest.raises(OSError):
                os.fstat(fd)
    assert _signal_state()==signals
