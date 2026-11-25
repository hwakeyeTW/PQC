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


# I1b P2: the product orchestrates, the trusted test driver only packages and
# executes the single stage named by its actual native worker binding. No
# prepared receipt replay, public transport, real RPM, or network access.
class _P2Driver:
    def __init__(self, tmp, ctx, *, ol=True, versions=None, modes=None, stage_seconds=30, fault=None):
        self.tmp, self.ctx = tmp, ctx
        self.ol, self.versions, self.modes = ol, versions or {}, modes or {}
        self.stage_seconds, self.fault = stage_seconds, fault
        self.p1 = ROOT / 'ansible_collections/security/compliance_pqc_readiness/plugins/modules/pqc_platform_acquire.py'
        self.python = os.path.abspath(sys._base_executable)
        self.original = self.p1.read_text()
        self.validator = None

    def markers(self, name, suffix='launch'):
        return sorted(self.tmp.glob(f'{name}-*-{suffix}.json'))

    def prepare(self, binding):
        import subprocess
        import selectors
        from ansible import constants as C
        from ansible.plugins.loader import module_loader, module_utils_loader
        from ansible.executor.module_common import modify_module
        from ansible.parsing.dataloader import DataLoader
        from ansible.template import Templar
        name, stage, ordinal = binding.target_id, binding.stage, binding.ordinal
        assert binding.run_id and name in self.ctx._targets and os.getpid() != self.parent_pid
        assert binding.task_uuid and stage == bridge._PLATFORM_STAGES[ordinal]
        stem = f'{name}-{ordinal}'
        private = self.tmp / stem
        private.mkdir(mode=0o700)
        mode = self.modes.get((name, ordinal), 'ok')
        source = self.p1
        module_name = 'security.compliance_pqc_readiness.pqc_platform_acquire'
        group = self.tmp / (stem + '-group.json')
        if self.ol:
            # Only private fact/stat input, fixed RPM literal and (when
            # required) shortened test-only deadline are changed.
            data = platform_snapshot()
            data['facts'].update(self.versions.get(name, {}))
            tools = data['tools']
            if mode == 'missing-rpm':
                tools['rpm'][0] = dict(state='OK', exists=False, isreg=None, islnk=None, executable=None)
            rpm = private / 'rpm-fixture'
            script = f'''#!{self.python} -I
import json,os,sys,time,signal
assert os.geteuid()=={os.geteuid()} and os.environ['LC_ALL']=='C'
assert sys.argv[1:4]==['-q','--queryformat','%{{NAME}}\\t%{{VERSION}}\\t%{{RELEASE}}\\t%{{ARCH}}\\n']
assert len(sys.argv)==5 and sys.argv[4] in {platform.PACKAGES!r}
assert os.read(0,1)==b''
mode={mode!r}
pids=[os.getpid()]
if mode in ('hang','consumer-loss'):
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    child=os.fork()
    if child==0:
        time.sleep(60);os._exit(0)
    pids.append(child)
with open({str(group)!r},'x') as f:json.dump(dict(pids=pids,pgid=os.getpgrp(),parent=os.getppid(),package=sys.argv[4]),f)
if mode in ('hang','consumer-loss'): time.sleep(60)
if mode=='overflow': os.write(1,b'x'*16385)
if sys.argv[4].endswith('el9'):
    print('package '+sys.argv[4]+' is not installed',file=sys.stderr);sys.exit(1)
print(sys.argv[4]+'\\t9.10\\t0.1\\tx86_64')
'''
            rpm.write_text(script); rpm.chmod(0o700)
            raw = self.original
            fact_body = ("raise ValueError('FIXTURE_METADATA_FAILURE')" if mode == 'metadata-failure' else
                         "return 'OK', " + repr(data['facts']))
            # _stat uses the real fixed path map; return only typed fixture
            # observations for those paths, never a target-selected path.
            source_paths = {'/usr/bin/rpm': tools['rpm'][0], '/usr/bin/openssl': tools['openssl'][0],
                '/usr/bin/ssh': tools['ssh'][0], '/usr/sbin/sshd': tools['sshd'][0],
                '/usr/bin/ssh-keygen': tools['ssh-keygen'][0],
                '/usr/bin/update-crypto-policies': tools['update-crypto-policies'][0],
                '/usr/sbin/update-crypto-policies': tools['update-crypto-policies'][1],
                '/usr/bin/timeout': tools['timeout'][0]}
            changes = {"RPM_EXECUTABLE = '/usr/bin/rpm'": 'RPM_EXECUTABLE = ' + repr(str(rpm)),
                       'STAGE_SECONDS = 30': 'STAGE_SECONDS = ' + str(self.stage_seconds),
                       'def _facts(archive):': 'def _facts(archive):\n    ' + fact_body,
                       'def _stat(path):': 'def _stat(path):\n    return ' + repr(source_paths) + '[path]'}
            for old, new in changes.items():
                assert raw.count(old) == 1
                raw = raw.replace(old, new)
            source = private / self.p1.name
            source.write_text(raw)
            module_name = 'pqc_platform_acquire'
            # The test-only copy is the actual native short-name source.
            # These private loader paths are not used by the product.
            module_loader._extra_dirs = [str(private)]
            module_loader._clear_caches()
            module_utils_loader.add_directory(str(ROOT / 'plugins/module_utils'))
        resolved = module_loader.find_plugin_with_context(module_name, '.py')
        assert resolved.resolved and Path(resolved.plugin_resolved_path).resolve() == source.resolve()
        # No stale AnsiballZ cache across stage/host/fixture copies.
        prior_tmp = C.DEFAULT_LOCAL_TMP
        try:
            C.DEFAULT_LOCAL_TMP = str(private)
            bits = modify_module(module_name=module_name, module_path=str(source),
                module_args={'stage': stage, '_ansible_no_log': True}, templar=Templar(loader=DataLoader()),
                task_vars={'ansible_python_interpreter': self.python, 'ansible_playbook_python': sys.executable},
                remote_is_local=False)
        finally:
            C.DEFAULT_LOCAL_TMP = prior_tmp
        assert bits.module_style == 'new'
        wrapper = private / 'wrapper.py'
        wrapper.write_bytes(bits.b_module_data); wrapper.chmod(0o600)
        if self.fault is not None:
            self.fault('prepare', binding, None)

        def launch(begin):
            end = begin()
            try:
                proc = subprocess.Popen([self.python, '-I', '-B', str(wrapper)], cwd=private,
                    env={'PATH': '/usr/bin:/bin', 'HOME': str(private), 'TMPDIR': str(private), 'LC_ALL': 'C.UTF-8'},
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True)
            except OSError:
                return bridge._StageCompletion(binding, b'', b'', None, False, True)
            (self.tmp / (stem + '-launch.json')).write_text(json.dumps(dict(
                stage=stage, ordinal=ordinal, task=binding.task_uuid, run=binding.run_id,
                worker=os.getpid(), supervisor=proc.pid, began=time.monotonic(), end=end)))
            buffers = [bytearray(), bytearray()]
            try:
                with selectors.DefaultSelector() as sel:
                    for i, stream in enumerate((proc.stdout, proc.stderr)):
                        sel.register(stream, selectors.EVENT_READ, i)
                    while sel.get_map() or proc.poll() is None:
                        if mode == 'consumer-loss' and group.exists():
                            os._exit(17)
                        left = end - time.monotonic()
                        assert left > 0
                        if not sel.get_map():
                            time.sleep(min(.01, left)); continue
                        for key, _ in sel.select(min(.02, left)):
                            room = bridge._STAGE_FRAME_BYTES - sum(map(len, buffers))
                            data = os.read(key.fd, min(4096, room + 1))
                            assert len(data) <= room
                            if data: buffers[key.data].extend(data)
                            else: sel.unregister(key.fileobj)
                proc.wait(timeout=max(.01, end-time.monotonic()))
            finally:
                proc.stdout.close(); proc.stderr.close()
                # Never terminate the sole P1 cleanup supervisor. An abandoned
                # worker's separate session remains bounded by P1 itself; the
                # parent test reaps it independently, not as worker proof.
                if proc.poll() is None:
                    proc.wait(timeout=self.stage_seconds + 1)
            assert proc.returncode == 0 and not buffers[1]
            assert not batch._scope.group_exists(proc.pid)
            if group.exists():
                witness = json.loads(group.read_bytes())
                assert witness['pgid'] != proc.pid
                assert not batch._scope.group_exists(witness['pgid'])
                assert all(not Path('/proc',str(pid)).exists() for pid in witness['pids'])
            # Independently witness actual P1 success/cleanup before any test
            # mutation. The product must still parse, bind and validate the
            # returned frame itself with the original canonical validator.
            raw = bytes(buffers[0]); receipt = json.loads(raw)['receipt']
            self.validator(receipt, stage)
            assert receipt['cleanup_confirmed'] is True
            (self.tmp / (stem + '-done.json')).write_text(json.dumps(dict(
                reason=receipt['reason_code'], rc=receipt['rc'], rpm_rc=receipt['rpm_rc'],
                state=receipt['payload'].get('state') if receipt['payload'] else None,
                cleanup=True, ended=time.monotonic())))
            completion = bridge._StageCompletion(binding, raw, bytes(buffers[1]), proc.returncode, True, True)
            return self.fault('completion', binding, completion) if self.fault is not None else completion
        return launch


def _p2_register(monkeypatch, ctx, trace, **kwargs):
    register(monkeypatch, trace, p=0)
    registry = bridge._producer_adapters()
    driver = _P2Driver(trace.parent, ctx, **kwargs)
    driver.parent_pid = os.getpid()
    # Loader already initialized by the real native InventoryManager.
    driver.validator = bridge._bound_stage_validator()
    registry[bridge.PLATFORM] = bridge._PlatformStageAdapter(driver.prepare)
    monkeypatch.setattr(bridge, '_producer_adapters', lambda: registry)
    return driver


def _p2_rows(driver, name, suffix='launch'):
    return [json.loads(p.read_bytes()) for p in driver.markers(name, suffix)]


def test_p2_platform_fixed_budgets():
    session = batch._ProducerSession(RULES)
    assert batch._platform_budget() == 258
    assert session.budget(bridge.PRODUCERS) == 155
    session.staged = True
    assert session.budget(bridge.PRODUCERS) == 382
    host = batch._GUARD_SECONDS + batch._SSH_SECONDS + session.budget(bridge.PRODUCERS) + batch._WORKER_GRACE + 5
    assert host == 434 and 2*batch._GUARD_SECONDS + 10*(2*batch._GUARD_SECONDS+host)+5 == 5005
    assert not bridge._producer_adapters() and not batch._passive_adapters()
    with pytest.raises(batch.Denied, match='LIVE_NOT_AVAILABLE'):
        batch._restricted_connection(HOST)


@pytest.mark.parametrize('ol', [False, True], ids=['debian-fqcn', 'ol-three-stages-short'])
def test_p2_platform_actual_native_worker(fixture, monkeypatch, ol):
    make,_,trace,trap,_=fixture
    ctx,names=make(count=1,flags=selected_flags(bridge.PACKAGES))
    driver=_p2_register(monkeypatch,ctx,trace,ol=ol)
    launches=_observe_native_queue(monkeypatch)
    rc,m,bundle=checked(ctx)
    n=names[0]; stages=_p2_rows(driver,n); done=_p2_rows(driver,n,'done')
    assert [r['stage'] for r in stages] == list(bridge._PLATFORM_STAGES if ol else ('metadata',)), (m,stages,done)
    assert len(done)==len(stages) and all(r['cleanup'] for r in done)
    assert len({r['worker'] for r in stages})==len({r['task'] for r in stages})==len({r['run'] for r in stages})==1
    assert launches==[(n, stages[0]['worker'])] and stages[0]['worker']!=os.getpid()
    assert all(not Path('/proc',str(r['supervisor'])).exists() for r in stages)
    assert all(a['ended'] <= b['began'] for a,b in zip(done,stages[1:]))
    d=bundle['document']; row=m['hosts'][0]
    assert len(row['platform']['collection_ids'])==10 and len(d['collections'])==17
    scopes={c['scope_key']:c for c in d['collections'] if c['collector_id']==bridge.PLATFORM}
    assert all(c['source']['source_kind']=='SYNTHETIC' for c in scopes.values())
    if ol:
        assert rc==0 and [r['rpm_rc'] for r in done]==[None,0,1]
        assert [r['state'] for r in done[1:]]==['COLLECTED','ABSENT']
        assert all(scopes[s]['collection_state']=='COLLECTED' for s in bridge._PLATFORM_STAGES[1:])
        assert (trace.parent/(n+'.'+bridge.OPENSSL+'.json')).exists()
    else:
        assert all(scopes[s]['collection_state']=='NOT_SCANNED' and scopes[s]['reason_code']=='NOT_ATTEMPTED' for s in bridge._PLATFORM_STAGES[1:])
        assert not (trace.parent/(n+'.'+bridge.OPENSSL+'.json')).exists()
    assert not trap.exists() and trace.read_text().splitlines()==['["--list"]']
    print('P2_NATIVE_STAGES',json.dumps(dict(ol=ol,stages=stages,done=done,rc=rc,collections=len(d['collections']))))


@pytest.mark.parametrize('version,major,family,expected', [
    ('9.7','9','RedHat',True), ('9.8','9','RedHat',True), ('9.9','9','RedHat',True),
    ('9.10','9',None,True), ('8.9','8','RedHat',False), ('9.9','8','RedHat',False),
    ('9','9','RedHat',False), ('9.10','9','Debian',False), (None,'9','RedHat',False),
])
def test_p2_platform_numeric_gate(version, major, family, expected):
    value=platform_snapshot(); value['rpms']={}
    value['facts'].update(distribution_version=version,distribution_major_version=major,os_family=family)
    assert bridge._rpm_eligible(value) is expected
    for tool in ('rpm','timeout'):
        copy_value=copy.deepcopy(value); copy_value['tools'][tool]=[dict(state='UNKNOWN')]
        assert bridge._rpm_eligible(copy_value) is False
    value.update(facts={},facts_state='PERMISSION_DENIED')
    assert bridge._rpm_eligible(value) is False


@pytest.mark.parametrize('fault', ['foreign-target','foreign-run','foreign-task','wrong-order','replayed',
    'missing','untrusted-cleanup','duplicate-json','nan','frame-overflow','receipt-overflow','bad-rc',
    'bad-stage','extra-frame','bad-rpm-rc','not-started'], ids=str)
def test_p2_platform_closed_receipt(fixture, fault):
    make,_,_,_,_=fixture; make(count=1)
    stage=bridge._PLATFORM_STAGES[1] if fault=='bad-rpm-rc' else 'metadata'
    binding=bridge._StageBinding(RUN,HOST,'task-001',stage,1 if stage!='metadata' else 0)
    payload=platform_snapshot(); payload.pop('rpms')
    if stage!='metadata':
        payload=dict(state='ABSENT',reason='PACKAGE_ABSENT',rows=[])
    receipt=dict(format=1,stage=stage,reason_code='COMMAND_OK',rc=0,cleanup_confirmed=True,
                 payload=payload,rpm_rc=1 if stage!='metadata' else None)
    frame=dict(changed=False,invocation={'module_args':{'stage':stage}},receipt=receipt)
    raw=json.dumps(frame).encode('ascii'); complete=bridge._StageCompletion(binding,raw,b'',0,True,True)
    assert bridge._stage_receipt(complete,binding)==receipt
    expected='INVALID_ADAPTER_RESULT'; clean=True
    if fault in ('foreign-target','foreign-run','foreign-task','wrong-order','replayed'):
        field,value={'foreign-target':('target_id','other.example.invalid'),'foreign-run':('run_id','other-run'),
                     'foreign-task':('task_uuid','task-002'),'wrong-order':('ordinal',2),'replayed':('ordinal',binding.ordinal)}[fault]
        complete=complete._replace(binding=binding._replace(**{field:value}))
        expected='REMOTE_CLEANUP_UNCONFIRMED'; clean=False
    elif fault in ('missing','untrusted-cleanup'):
        complete=None if fault=='missing' else complete._replace(clean=False)
        expected='REMOTE_CLEANUP_UNCONFIRMED'; clean=False
    elif fault=='not-started':
        complete=bridge._StageCompletion(binding,b'',b'',None,False,True)
        expected='COMMAND_START_FAILED'
    else:
        if fault=='duplicate-json': raw=raw.replace(b'"changed": false',b'"changed": false, "changed": false')
        elif fault=='nan': raw=raw.replace(b'"rc": 0',b'"rc": NaN')
        elif fault=='frame-overflow': raw=b'x'*(bridge._STAGE_FRAME_BYTES+1)
        elif fault=='receipt-overflow': frame['receipt']['raw']='x'*(bridge._STAGE_RECEIPT_BYTES+1);raw=json.dumps(frame).encode()
        elif fault=='bad-rc': frame['receipt']['rc']=True;raw=json.dumps(frame).encode()
        elif fault=='bad-stage': frame['receipt']['stage']='release-rpm-oraclelinux-release-el9';raw=json.dumps(frame).encode()
        elif fault=='extra-frame': frame['extra']='DUMMY_PRIVATE_SENTINEL';raw=json.dumps(frame).encode()
        elif fault=='bad-rpm-rc': frame['receipt']['rpm_rc']=0;raw=json.dumps(frame).encode()
        complete=complete._replace(stdout=raw)
    with pytest.raises(bridge._StageFailure) as exc:
        bridge._stage_receipt(complete,binding)
    assert exc.value.reason==expected and exc.value.clean is clean
    assert exc.value.value()['snapshot'] is None and 'DUMMY_PRIVATE_SENTINEL' not in str(exc.value)


@pytest.mark.parametrize('mode', ['metadata-failure','missing-rpm','overflow','hang'])
def test_p2_platform_confirmed_failure_and_gate(fixture,monkeypatch,mode):
    make,_,trace,trap,_=fixture
    count=2 if mode=='metadata-failure' else 1
    ctx,names=make(count=count,forks=1,flags=selected_flags(bridge.PACKAGES))
    n=names[0]; ordinal=0 if mode in ('metadata-failure','missing-rpm') else 1
    driver=_p2_register(monkeypatch,ctx,trace,modes={(n,ordinal):mode},stage_seconds=4 if mode=='hang' else 30)
    rc,m,bundle=checked(ctx)
    got=_p2_rows(driver,n); done=_p2_rows(driver,n,'done')
    assert len(got)==len(done)==(1 if ordinal==0 else 3), (m,got,done)
    assert all(r['cleanup'] for r in done)
    scopes={c['scope_key']:c for c in bundle['document']['collections']
            if c['collector_id']==bridge.PLATFORM and c['host_id']==bridge.host_record(got[0]['run'],n)['host_id']}
    if mode=='metadata-failure':
        assert rc==5 and m['hosts'][0]['host_state']=='ERROR' and m['hosts'][1]['host_state']=='COMPLETE'
        assert m['hosts'][0]['platform']['reason_code']=='COMMAND_FAILED' and done[0]['rc']!=0
        assert not scopes and not (trace.parent/(n+'.'+bridge.OPENSSL+'.json')).exists()
        assert len(_p2_rows(driver,names[1]))==3
    elif mode=='missing-rpm':
        assert len(scopes)==10 and all(scopes[s]['collection_state']=='NOT_SCANNED' for s in bridge._PLATFORM_STAGES[1:])
        # Missing release-RPM tool is not a blanket ban on later producers.
        assert (trace.parent/(n+'.'+bridge.OPENSSL+'.json')).exists()
    else:
        first,second=bridge._PLATFORM_STAGES[1:]
        assert scopes[first]['collection_state']=='ERROR' and scopes[first]['reason_code']==('TIMEOUT' if mode=='hang' else 'OUTPUT_LIMIT')
        assert scopes[second]['collection_state']=='COLLECTED' and done[2]['rpm_rc']==1
        assert (trace.parent/(n+'.'+bridge.OPENSSL+'.json')).exists()
        if mode=='hang':
            assert done[1]['reason']=='COMMAND_TIMEOUT' and done[1]['rc']!=0 and done[1]['rpm_rc'] is None
        else:
            assert done[1]['reason']=='COMMAND_OK' and done[1]['state']=='ERROR'
    assert not trap.exists()


@pytest.mark.parametrize('fault', ['late-drift','invalid-frame','untrusted-cleanup','foreign-binding','interrupted'])
def test_p2_platform_fatal_stage_stops_dispatch(fixture,monkeypatch,fault):
    make,_,trace,trap,cfg=fixture
    ctx,names=make(count=2,forks=1,flags=selected_flags(bridge.PACKAGES))
    def corrupt(when,binding,completion):
        if binding.ordinal!=1:return completion
        if fault=='late-drift' and when=='prepare':
            with cfg.open('a') as f:f.write('\n# synthetic late source drift\n')
        elif when=='completion':
            if fault=='invalid-frame':return completion._replace(stdout=b'{"duplicate":1,"duplicate":2}')
            if fault=='untrusted-cleanup':return completion._replace(clean=False)
            if fault=='foreign-binding':return completion._replace(binding=binding._replace(target_id=names[1]))
            if fault=='interrupted':
                frame=json.loads(completion.stdout)
                frame['receipt'].update(reason_code='INTERRUPTED',rc=-15,payload=None,rpm_rc=None)
                return completion._replace(stdout=json.dumps(frame).encode('ascii'))
        return completion
    driver=_p2_register(monkeypatch,ctx,trace,fault=corrupt)
    before=_signal_state(); launches=_observe_native_queue(monkeypatch)
    rc,m,bundle=checked(ctx)
    expected={'late-drift':'GUARD_REJECTED','invalid-frame':'INVALID_ADAPTER_RESULT',
              'untrusted-cleanup':'REMOTE_CLEANUP_UNCONFIRMED','foreign-binding':'REMOTE_CLEANUP_UNCONFIRMED',
              'interrupted':'INTERRUPTED'}[fault]
    assert rc==(7 if fault=='interrupted' else 6) and m['reason_code']==expected, m
    assert m['hosts'][0]['platform']['reason_code']==expected and not bundle['document']['collections']
    assert m['hosts'][1]['host_state']=='NOT_ATTEMPTED' and [n for n,_ in launches]==names[:1]
    assert [r['ordinal'] for r in _p2_rows(driver,names[0])]==([0] if fault=='late-drift' else [0,1])
    assert not _p2_rows(driver,names[1]) and not trap.exists() and _signal_state()==before


# Independently reap adopted test-owned supervisors. A worker's normal exit or
# absence of its own group is NOT proof that the P1 target group has gone.
# The local test parent is already trusted; these witnesses never enter the
# product queue, registry, handoff or evidence, and are not transport proofs.
from contextlib import contextmanager


@contextmanager
def _p2_owned_supervisors(driver):
    import ctypes
    libc=ctypes.CDLL(None,use_errno=True); old=ctypes.c_int()
    assert libc.prctl(37,ctypes.byref(old),0,0,0)==0 and libc.prctl(36,1,0,0,0)==0
    reaped={}
    try:
        yield reaped
    finally:
        try:
            launches=[json.loads(p.read_bytes()) for p in driver.tmp.glob('*-launch.json')]
            groups=[json.loads(p.read_bytes()) for p in driver.tmp.glob('*-group.json')]
            end=max([time.monotonic()+.5]+[x['began']+driver.stage_seconds+3 for x in launches])
            for entry in launches:
                pid=entry['supervisor']
                while Path('/proc',str(pid)).exists() and time.monotonic()<end:
                    try:
                        got,status=os.waitpid(pid,os.WNOHANG)
                        if got:reaped[pid]=os.waitstatus_to_exitcode(status);break
                    except ChildProcessError:
                        pass
                    time.sleep(.02)
                assert not Path('/proc',str(pid)).exists() and not batch._scope.group_exists(pid), 'P1 supervisor still present'
            for entry in groups:
                assert not batch._scope.group_exists(entry['pgid']), 'P1 target group still present'
                assert all(not Path('/proc',str(pid)).exists() for pid in entry['pids']), 'P1 descendant still present'
            print('P2_OWNED_CLEANUP',json.dumps(dict(supervisors=len(launches),groups=len(groups),adopted_reaped=reaped)))
        finally:
            assert libc.prctl(36,old.value,0,0,0)==0


def _p2_wait(path,seconds=8):
    end=time.monotonic()+seconds
    while not path.exists():
        if time.monotonic()>=end:raise AssertionError('fixture synchronization timed out')
        time.sleep(.01)


@pytest.mark.parametrize('mode',['consumer-loss','signal'])
def test_p2_platform_worker_loss_and_signal_cleanup(fixture,monkeypatch,mode):
    make,_,trace,trap,_=fixture
    ctx,names=make(count=2,forks=1,flags=selected_flags(bridge.PACKAGES))
    n=names[0]; driver=_p2_register(monkeypatch,ctx,trace,
        modes={(n,1):'consumer-loss' if mode=='consumer-loss' else 'hang'},stage_seconds=4)
    sent=[]; before=_signal_state(); launches=_observe_native_queue(monkeypatch)
    if mode=='signal':
        poll=batch._ProducerWorkerWave.poll
        def interrupt(self):
            if not sent and (trace.parent/f'{n}-1-group.json').exists():
                sent.append(time.monotonic());os.kill(os.getpid(),signal.SIGINT)
            return poll(self)
        monkeypatch.setattr(batch._ProducerWorkerWave,'poll',interrupt)
    with _p2_owned_supervisors(driver) as reaped:
        rc,m,bundle=checked(ctx)
    assert rc==(7 if mode=='signal' else 6) and m['reason_code']==('INTERRUPTED' if mode=='signal' else 'REMOTE_CLEANUP_UNCONFIRMED'),m
    assert (mode!='signal' or sent) and m['hosts'][0]['host_state']=='ERROR' and m['hosts'][1]['host_state']=='NOT_ATTEMPTED'
    assert [n for n,_ in launches]==names[:1] and len(_p2_rows(driver,n))==2 and len(_p2_rows(driver,n,'done'))==1
    assert _p2_rows(driver,n)[1]['supervisor'] in reaped
    assert not bundle['document']['collections'] and not trap.exists() and _signal_state()==before


def test_p2_platform_peer_fatal_stop_cleans_independent_group(fixture,monkeypatch):
    make,_,trace,trap,_=fixture
    ctx,names=make(count=3,forks=2,flags=selected_flags(bridge.PACKAGES))
    a,b,_=names
    def corrupt(when,binding,completion):
        if when=='completion' and binding.target_id==a and binding.ordinal==1:
            group=trace.parent/f'{b}-1-group.json'; _p2_wait(group)
            assert batch._scope.group_exists(json.loads(group.read_bytes())['pgid'])
            return completion._replace(stdout=b'{"bad":true}')
        return completion
    driver=_p2_register(monkeypatch,ctx,trace,modes={(b,1):'hang'},stage_seconds=6,fault=corrupt)
    before=_signal_state(); launches=_observe_native_queue(monkeypatch)
    with _p2_owned_supervisors(driver) as reaped:
        rc,m,bundle=checked(ctx)
    assert rc==6 and m['reason_code']=='REMOTE_CLEANUP_UNCONFIRMED', m
    assert m['hosts'][0]['platform']['reason_code']=='INVALID_ADAPTER_RESULT'
    assert [r['host_state'] for r in m['hosts']]==['ERROR','ERROR','NOT_ATTEMPTED']
    assert [n for n,_ in launches]==names[:2] and all(len(_p2_rows(driver,n))==2 for n in names[:2])
    assert _p2_rows(driver,b)[1]['supervisor'] in reaped and len(_p2_rows(driver,b,'done'))==1
    assert not bundle['document']['collections'] and not trap.exists() and _signal_state()==before


@pytest.mark.parametrize('in_flight',[False,True],ids=['no-new-stage','active-stage'])
def test_p2_platform_dual_worker_earliest_lease(fixture,monkeypatch,in_flight):
    make,_,trace,trap,_=fixture
    ctx,names=make(count=3,forks=2,flags=selected_flags(bridge.PACKAGES))
    a,b,_=names; ready=trace.parent/'a-ready'; verified=trace.parent/'b-verified'
    marks={}; waves=[]
    def synchronize(when,binding,completion):
        if not in_flight and when=='prepare' and binding.target_id==a and binding.ordinal==1:
            ready.write_text('ready'); _p2_wait(verified)
            worker=batch._PLATFORM_WORKER.get(); end=worker.lease.limit(a)
            (trace.parent/'child-lease.json').write_text(json.dumps(dict(end=end,now=time.monotonic())))
        return completion
    driver=_p2_register(monkeypatch,ctx,trace,versions={b:{'distribution':'Debian','os_family':'Debian'}},
        modes={(a,1):'hang'} if in_flight else {},stage_seconds=6 if in_flight else 30,fault=synchronize)
    make_queue=batch._make_queue
    def queue(validator=None):
        q=make_queue(validator); send=q.send_task_result
        def hold(result):
            if result.as_wire_task_result().host_name==b:
                _p2_wait(trace.parent/f'{a}-1-group.json' if in_flight else ready)
                send(result);time.sleep(15)
            else:send(result)
        q.send_task_result=hold;return q
    monkeypatch.setattr(batch,'_make_queue',queue)
    accepted=batch._ProducerWorkerWave._receipt_accepted
    def observe(self):
        result=accepted(self)
        if b in self.ledger.projections and not verified.exists():
            assert b not in self.confirmed and self.workers[b].is_alive()
            end=self.limit(); assert end==min(self.ends[b],self.grace[b])<self.ends[a]
            assert self.lease.limit(a)==end
            marks.update(earliest=end,verified=time.monotonic());waves.append(self)
            verified.write_text('verified')
        return result
    monkeypatch.setattr(batch._ProducerWorkerWave,'_receipt_accepted',observe)
    before=_signal_state();launches=_observe_native_queue(monkeypatch)
    with _p2_owned_supervisors(driver) as reaped:
        rc,m,bundle=checked(ctx);marks['finished']=time.monotonic()
    assert waves and marks['verified']<marks['earliest'] and [n for n,_ in launches]==names[:2],m
    assert [r['host_state'] for r in m['hosts']]==['ERROR','ERROR','NOT_ATTEMPTED']
    # A refused launch can return its own validated, empty failure envelope.
    # An already active stage cannot turn a late receipt into observations.
    assert rc==6 and set(bundle['handoff_metrics'])==set(bundle['companions'])
    assert b in bundle['companions'] and set(bundle['companions']) <= {a,b}
    assert not bundle['companions'].get(a)
    assert all(not r['collection_ids'] for r in [m['hosts'][0]['platform'], *m['hosts'][0]['collectors']])
    assert len(bundle['document']['collections'])==17 and not trap.exists() and _signal_state()==before
    if in_flight:
        assert set(bundle['companions'])=={b}
        assert m['reason_code']=='REMOTE_CLEANUP_UNCONFIRMED'
        assert len(_p2_rows(driver,a))==2 and len(_p2_rows(driver,a,'done'))==1
        assert _p2_rows(driver,a)[1]['supervisor'] in reaped
        assert marks['earliest']-.15<=marks['finished']<=marks['earliest']+batch._WORKER_GRACE+2
    else:
        child=json.loads((trace.parent/'child-lease.json').read_bytes())
        assert child['end']==marks['earliest'] and 0<child['end']-child['now']<=batch._WORKER_GRACE
        assert len(_p2_rows(driver,a))==1 and m['reason_code']=='CONTROLLER_TIMEOUT'
        assert set(bundle['companions'])=={a,b} and m['hosts'][0]['platform']['reason_code']=='CONTROLLER_TIMEOUT'
    assert all(not _p2_rows(driver,n) for n in names[2:])
    print('P2_EARLIEST_LEASE',json.dumps(dict(in_flight=in_flight,**marks)))
