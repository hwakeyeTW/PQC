"""Private Store tests using actual synthetic five-producer replay, no transport."""
import copy
import hashlib
import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
import pytest
import test_c3a_capacity_profile as f
from tools import run_store as store, run_store_v3 as v3, run_store_v2 as v2
from tools import scan_collectors as bridge, batch_execution as batch, evidence
from ansible_collections.security.compliance_pqc_readiness.plugins.modules import pqc_policy_acquire as pa

LIMITS = dict(max_hosts=10,forks=2,serial=2,ssh_timeout_s=15,command_timeout_s=30)
RECOVER = '2026-01-01T00:00:06Z'
RID = f.RUN


def expanded_snapshots():
    snap=f._snapshots(); pol=snap[bridge.POLICY]
    declarations={
        'current-policy':'group = '+' '.join('fixture-group-%02d'%i for i in range(64))+'\n',
        'backend-openssh':'KexAlgorithms '+','.join('fixture-client-kex-%02d@fixture.invalid'%i for i in range(64))+'\n',
        'backend-opensshserver':'HostKeyAlgorithms '+','.join('fixture-server-key-%02d@fixture.invalid'%i for i in range(64))+'\n',
        'backend-openssl':'CipherSuites = '+':'.join('TLS_FIXTURE_SUITE_%02d'%i for i in range(64))+'\n',
        'backend-opensslcnf':'CipherString = '+':'.join('FIXTURE-AES-SUITE-%02d'%i for i in range(64))+'\n'}
    total=0
    for scope,text in declarations.items():
        raw=text.encode('ascii'); total+=len(raw); row=pa.parse_source(scope,raw)
        assert row['state']=='COLLECTED' and len(row['values'])==64; pol[scope]=row
    overrides=[]
    for i in range(32):
        name='fixture-%02d.config'%i
        raw=('KexAlgorithms fixture-override-%02d-a@fixture.invalid,fixture-override-%02d-b@fixture.invalid\n'%(i,i)).encode('ascii'); total+=len(raw)
        row=pa.parse_source('backend-openssh',raw); assert row['state']=='COLLECTED' and len(row['values'])==2
        overrides.append(dict(override_id='ov-'+hashlib.sha256(name.encode()).hexdigest(),backend='openssh',result=row))
    overrides.sort(key=lambda o:o['override_id']);pol['local-overrides']=f.policy.result('COLLECTED','OK',[['entry-count',32]],overrides=overrides)
    assert total<=pa.TOTAL_LIMIT
    reader={scope:pol[scope] for scope in bridge._POLICY_READER_SCOPES};pa.validate_receipt(pa._receipt('reader','COMMAND_OK',0,True,reader),'reader')
    # The new positive does not use the original byte-boundary DN padding.
    for root in snap[bridge.CERT]['roots'].values():
        for i,source in enumerate(root['sources']):
            for j,block in enumerate(source['blocks']):
                c=block['certificate'];c['issuer']='CN=Fixture intermediate CA,O=Example Test PKI';c['subject']='CN=fixture-cert-%d-%d.example.invalid,O=Example Test PKI'%(i,j)
    f.certacq.validate_receipt(dict(format=1,stage='system',reason_code='COMMAND_OK',rc=0,cleanup_confirmed=True,payload=snap[bridge.CERT]),'system')
    return snap


def fragment(row, projection=None):
    h=bridge.host_record(RID,row['target_id'],row['host_state'],row['reason_code'])
    d=bridge.document(RID,f.TIME,[h],store._run_state([h]),f.FIN if row['attempted'] else None)
    d['run']['recorded_at']=f.FIN
    if projection is not None:
        for k in ('collections','assets','evidence'): d[k]=projection[k]
    return d


def replay(args):
    i,snap,flags=args;n='fixture-%02d.example.invalid'%i
    env=dict(handoff_version=1,run_id=RID,target_id=n,connection='CONNECTED',records=[dict(producer_id=p,observed_at=f.TIME,reason_code='COMMAND_OK',rc=0,cleanup_confirmed=True,snapshot=snap[p]) for p in bridge.requested(flags)])
    wire=bridge.wire_bytes(env)
    p=bridge.normalize_handoff(bridge.read_wire(wire),RID,n,flags,f.TIME,f.rules,staged_openssl=any(flags[x] for x in (bridge.PACKAGES,bridge.SSL)),staged_policy=flags[bridge.POLICY_FLAG],staged_ssh=any(flags[x] for x in (bridge.SSHD,bridge.KEYS)),staged_cert=flags[bridge.CERT_FLAG])
    row=batch._host(n,True,[p.outcomes[x] for x in batch._COLLECTORS],p.special);row['platform']=p.outcomes[bridge.PLATFORM]
    doc=fragment(row,p.document);details={v3.HANDOFF:wire,**{v3.PRODUCER_SLOTS[k]:v3._detail_bytes(v3.PRODUCER_SLOTS[k],val) for k,val in p.companions.items()}}
    return flags,row,doc,details,p


def small(i=0):
    flags={x:x==bridge.CERT_FLAG for x in bridge.FLAGS};roots={k:f.certacq.empty() for k in f.certacq.ROOTS}
    for k,r in roots.items():r['root_target_id']=f.certacq.source_id(f.certacq.ROOTS[k])
    payload=dict(system_python_available=True,roots=roots)
    f.certacq.validate_receipt(dict(format=1,stage='system',reason_code='COMMAND_OK',rc=0,cleanup_confirmed=True,payload=payload),'system')
    return replay((i,{bridge.PLATFORM:f._platform_snapshot(),bridge.CERT:payload},flags))


def blank(i,mode):
    n='fixture-%02d.example.invalid'%i;active=mode!='disabled';ff={x:active and x==bridge.CERT_FLAG for x in bridge.FLAGS}
    if mode=='connection':
        row=batch._host(n,True,[batch._outcome(x,True,'UNREACHABLE','CONNECTION_FAILED') if ff[x] else batch._outcome(x,False,'NOT_SCANNED','DISABLED') for x in batch._COLLECTORS],'CONNECTION_FAILED');row['platform']=batch._outcome(bridge.PLATFORM,True,'UNREACHABLE','CONNECTION_FAILED')
    else:
        reason={'disabled':'NO_EXECUTABLE_COLLECTORS','worker':'CONTROLLER_WORKER_FAILED'}[mode];row=batch._blank(n,ff,reason,active);row['platform']=batch._outcome(bridge.PLATFORM,active,'ERROR' if active else 'NOT_SCANNED','OUTCOME_UNKNOWN' if active else 'DISABLED')
    return ff,row,fragment(row),{},None


def terminal(items):
    rows=sorted([x[1] for x in items],key=lambda x:x['target_id']);state,reason,rc=batch._run_state(rows,'CONTROLLER_WORKER_FAILED' if any(r['reason_code']=='CONTROLLER_WORKER_FAILED' for r in rows) else None)
    m=dict(batch_manifest_version=2,target_ids=[r['target_id'] for r in rows],target_count=len(rows),limits=LIMITS,profile='extended',run_state=state,reason_code=reason,hosts=rows);batch.validate_producer_manifest(m,rc);return m,rc


def start(s,items,monkeypatch):
    monkeypatch.setattr(v3,'_clock',lambda:f.TIME);names=[x[1]['target_id'] for x in items]
    return s._begin_v3(run_id=RID,expected_hosts=[dict(target_id=n,inventory_authority_id=None,identity_key=n) for n in names],requested_flags={x[1]['target_id']:x[0] for x in items},limits=LIMITS,profile='extended',producer_rules_raw=f.RULE_BYTES,started_at=f.TIME)


def record(w,items,monkeypatch):
    for _,r,d,_,_ in items:
        if r['attempted']:w.dispatch_intent(d['hosts'][0]['host_id'])
    monkeypatch.setattr(v3,'_clock',lambda:f.FIN)
    for _,r,d,ds,_ in items:w.record_host(d,attempted=r['attempted'],terminal=r,details=ds)


def publish(w,items):
    b,rc=terminal(items);return w.finalize(batch_raw=bridge.wire_bytes(b),batch_rc=rc,finished_at=f.FIN)


@pytest.fixture
def root(tmp_path):
    p=tmp_path/'reports';p.mkdir(mode=0o700);return p


def check(root,result,items,*,expanded=False):
    import jsonschema
    m=result.manifest;d=result.document;b,rc=terminal(items)
    assert m['manifest_version']==v3.VERSION and m['batch_contract']==v3.CONTRACT and m['capacity_profile']==v3.CAPACITY_PROFILE
    assert m['run_state']==b['run_state'] and m['batch_rc']==rc and not m['recovery']
    assert m['recorded_at']==f.FIN and m['reserved_at']==f.TIME and m['recovered_at'] is None
    assert m['producer_rules_sha256']==hashlib.sha256(f.RULE_BYTES).hexdigest()
    schema=json.loads((f.ROOT/'schemas/run-manifest-1.1.0.schema.json').read_bytes());assert schema==v3.manifest_schema_v3();jsonschema.Draft202012Validator(schema).validate(m)
    run=root/RID;artifacts={e['path']:e for e in m['artifacts']};assert set(artifacts)==set(result.artifacts)
    for path,raw in result.artifacts.items():
        assert (run/path).read_bytes()==raw and len(raw)==artifacts[path]['size']
        assert hashlib.sha256(raw).hexdigest()==artifacts[path]['sha256']
    raw=result.artifacts['evidence.json'];assessed=result.artifacts['assessed_evidence.json'];c=result.artifacts['cff_projection.json'];proj=json.loads(c)
    assert evidence._canonical_v3_raw(d)==raw and evidence._canonical_v3_assessed(result.assessed)==assessed
    assert proj['evidence_document_sha256']==hashlib.sha256(assessed).hexdigest()
    assert len(proj['per_host'])==len(items) and [p['host_id'] for p in proj['per_host']]==m['expected_host_ids']
    validator=jsonschema.Draft202012Validator(json.loads((f.ROOT/'schemas/cff-projection-1.0.0.schema.json').read_bytes()))
    validator.validate(proj)
    for _,r,doc,ds,p in items:
        hid=doc['hosts'][0]['host_id'];h=next(h for h in m['hosts'] if h['host_id']==hid)
        assert h['terminal']==r and h['checkpoint_recorded_at']==f.FIN and h['dispatch_intent_at']==(f.TIME if r['attempted'] else None)
        for slot,original in ds.items():
            path=f'details/{hid}/{slot}.json';assert result.artifacts[path]==original
            ids={c['collection_id'] for c in doc['collections']} if slot==v3.HANDOFF else {c['collection_id'] for c in doc['collections'] if v3.PRODUCER_SLOTS[c['collector_id']]==slot}
            er=[r for r in doc['evidence'] if r['collection_id'] in ids]
            assert artifacts[path]['collection_ids']==sorted(ids) and artifacts[path]['evidence_ids']==sorted(e['evidence_id'] for e in er)
            assert artifacts[path]['asset_ids']==sorted({e['asset_id'] for e in er if e['asset_id'] is not None})
    if expanded:
        assert 32*v3.MIB<len(raw)<=64*v3.MIB
        companions={x[1]['target_id']:x[4].companions for x in items};projections={x[1]['target_id']:x[4] for x in items}
        with pytest.raises(evidence.EvidenceError,match='SIZE_LIMIT'):bridge.validate_bindings(b,d,companions,projections)
        bridge._validate_v3_bindings(b,d,companions,projections)
    cps=sorted((run/'checkpoints').glob('*.json'))
    print('STORE_METRICS',json.dumps(dict(hosts=len(items),expanded=expanded,counts={k:len(d[k]) for k in evidence.REGISTRIES},raw=len(raw),assessed=len(assessed),cff=len(c),core=sum(map(len,result.artifacts.values())),manifest=(run/'run_manifest.json').stat().st_size,journal=(run/'journal.json').stat().st_size,prepared=(run/'prepared.json').stat().st_size,checkpoints=[p.stat().st_size for p in cps],checkpoint_total=sum(p.stat().st_size for p in cps),artifacts={path:len(raw) for path,raw in result.artifacts.items()},digests={k:hashlib.sha256(result.artifacts[k]).hexdigest() for k in ('evidence.json','assessed_evidence.json','cff_projection.json','batch_manifest.json')},assessed_digest=proj['evidence_document_sha256'],rc=rc),sort_keys=True),flush=True)


def actual(root,items,monkeypatch,*,expanded=False):
    with store.RunStore(root) as s:
        with start(s,items,monkeypatch) as w:record(w,items,monkeypatch);result=publish(w,items)
        check(root,result,items,expanded=expanded)
        with pytest.raises(store.StoreError):s.open(RID)
        expected_digest=hashlib.sha256((root/RID/'run_manifest.json').read_bytes()).hexdigest();del result
        opened=s._open_v3(RID);assert hashlib.sha256((root/RID/'run_manifest.json').read_bytes()).hexdigest()==expected_digest and opened.manifest['batch_rc']==terminal(items)[1]
        with pytest.raises(store.StoreError):s._recover_v3(RID)
        return opened


@pytest.mark.parametrize('modes',[('complete',),('disabled',),('complete','connection','worker')])
def test_r2s_small_actual(root,monkeypatch,modes):
    items=[small(i) if m=='complete' else blank(i,m) for i,m in enumerate(modes)];result=actual(root,items,monkeypatch)
    if modes==('complete',):assert result.manifest['run_state']=='COMPLETE'


@pytest.fixture(scope='module')
def baseline():
    snap=f._snapshots()
    with ProcessPoolExecutor(max_workers=4,mp_context=multiprocessing.get_context('fork')) as pool:result=list(pool.map(replay,[(i,snap,f.ALL) for i in range(10)]))
    assert len({x[1]['target_id'] for x in result})==10 and all(len(x[3][v3.HANDOFF])==348632 and len(x[2]['evidence'])==2892 for x in result);return result


@pytest.mark.parametrize('count',[7,10])
def test_r2s_actual_baseline(root,monkeypatch,baseline,count):actual(root,baseline[:count],monkeypatch)


def test_r2s_actual_raw_over_32(root,monkeypatch):
    snap=expanded_snapshots()
    with ProcessPoolExecutor(max_workers=4,mp_context=multiprocessing.get_context('fork')) as pool:items=list(pool.map(replay,[(i,snap,f.ALL) for i in range(20,30)]))
    assert len({x[1]['target_id'] for x in items})==10;actual(root,items,monkeypatch,expanded=True)


def test_r2s_recover_unknown_and_missing(root,monkeypatch):
    items=[small(0),blank(1,'connection'),blank(2,'connection')]
    with store.RunStore(root) as s:
        with start(s,items,monkeypatch) as w:
            for x in items[:2]:w.dispatch_intent(x[2]['hosts'][0]['host_id'])
            monkeypatch.setattr(v3,'_clock',lambda:f.FIN)
            _,r,d,ds,_=items[0];w.record_host(d,attempted=True,terminal=r,details=ds)
        cp=next((root/RID/'checkpoints').glob('*.json'));old=cp.read_bytes()
        with pytest.raises(store.StoreError):s.recover(RID)
        monkeypatch.setattr(v3,'_clock',lambda:RECOVER);result=s._recover_v3(RID)
        assert result.manifest['recovery'] and result.manifest['recovered_at']==RECOVER and result.manifest['finished_at'] is None
        by_target={h['target_id']:h for h in result.manifest['hosts']};first,unknown,never=[by_target[x[1]['target_id']] for x in items]
        assert first['terminal']==items[0][1] and first['checkpoint_recorded_at']==f.FIN
        assert unknown['attempt_status']=='UNKNOWN' and unknown['attempted'] is None and unknown['reason_code']=='OUTCOME_UNKNOWN' and unknown['terminal'] is None
        assert never['attempt_status']=='NOT_ATTEMPTED' and never['attempted'] is False and never['terminal'] is None
        assert result.assessed is None and not any(k in result.artifacts for k in ('assessed_evidence.json','cff_projection.json','batch_manifest.json','assessment_rules.json'))
        assert cp.read_bytes()==old and s._open_v3(RID)==result


@pytest.mark.parametrize('stage,mod,key,limit',[('RAW_EVIDENCE',v3,'RAW_BYTES',1000),('ASSESSED_EVIDENCE',evidence,'_V3_ASSESSED_BYTES',1000),('CFF',f.cff,'_V3_WRAPPER_BYTES',1000),('CORE',v3,'CORE_BYTES',1000)])
def test_r2s_capacity_preserves_checkpoint(root,monkeypatch,stage,mod,key,limit):
    items=[small()]
    with store.RunStore(root) as s:
        with start(s,items,monkeypatch) as w:
            record(w,items,monkeypatch);path=next((root/RID/'checkpoints').glob('*.json'));old=path.read_bytes()
            # Test-only lower cap to drive failure at a particular stage.
            with monkeypatch.context() as fault:
                fault.setattr(mod,key,limit)
                with pytest.raises(v3.CapacityError,match='V3_CAPACITY_LIMIT') as ex:publish(w,items)
                assert ex.value.stage==stage
            assert path.read_bytes()==old and not (root/RID/'run_manifest.json').exists()
            j=store._unseal((root/RID/'journal.json').read_bytes(),v3.MANIFEST_BYTES);assert j['blocked_capacity_stage']==stage
            with pytest.raises(store.StoreError):w.dispatch_intent(items[0][2]['hosts'][0]['host_id'])
        monkeypatch.setattr(v3,'_clock',lambda:RECOVER)
        if stage=='RAW_EVIDENCE':
            with monkeypatch.context() as fault:
                fault.setattr(v3,'RAW_BYTES',limit)
                with pytest.raises(v3.CapacityError) as ex:s._recover_v3(RID)
                assert ex.value.stage==stage and path.read_bytes()==old and not (root/RID/'run_manifest.json').exists()
        result=s._recover_v3(RID);assert result.manifest['hosts'][0]['terminal']==items[0][1] and path.read_bytes()==old


@pytest.mark.parametrize('fault',['before_manifest','after_move','tamper','extra'])
def test_r2s_prepared_recovery(root,monkeypatch,fault):
    items=[small()]
    with store.RunStore(root) as s:
        with start(s,items,monkeypatch) as w:
            record(w,items,monkeypatch)
            write=store._write;rename=store._rename_noreplace
            def stopped_write(fd,name,raw,device,**kw):
                if name=='run_manifest.json':raise OSError('fixture interruption')
                return write(fd,name,raw,device,**kw)
            def stopped_rename(src,name,dst,target):
                rename(src,name,dst,target)
                if not name.startswith('.tmp-'):raise OSError('fixture interruption')
            with monkeypatch.context() as stop:
                if fault=='after_move':stop.setattr(store,'_rename_noreplace',stopped_rename)
                else:stop.setattr(store,'_write',stopped_write)
                with pytest.raises(store.StoreError):publish(w,items)
        run=root/RID;prepared=(run/'prepared.json').read_bytes();plan=store._unseal(prepared,v3.MANIFEST_BYTES)
        assert not (run/'run_manifest.json').exists()
        if fault=='tamper':
            cp=next((run/'checkpoints').glob('*.json'));cp.write_bytes(cp.read_bytes()+b' ')
        if fault=='extra':
            path=run/'rogue.json';path.write_bytes(b'{}');path.chmod(0o600)
        monkeypatch.setattr(v3,'_clock',lambda:RECOVER)
        if fault in ('tamper','extra'):
            with pytest.raises(store.StoreError):s._recover_v3(RID)
            assert not (run/'run_manifest.json').exists()
        else:
            result=s._recover_v3(RID);assert result.manifest==plan['manifest'] and not result.manifest['recovery']
            assert result.manifest['recorded_at']==f.FIN and (run/'prepared.json').read_bytes()==prepared and s._open_v3(RID)==result


@pytest.mark.parametrize('defect',['intent','time','missing','foreign','noncanonical','terminal','flag','stale_rules','unsafe_checkpoint'])
def test_r2s_reject_before_checkpoint(root,monkeypatch,defect):
    item=small();ff,r,d,ds,p=copy.deepcopy(item);hid=d['hosts'][0]['host_id']
    with store.RunStore(root) as s:
        with start(s,[item],monkeypatch) as w:
            if defect!='intent':w.dispatch_intent(hid)
            monkeypatch.setattr(v3,'_clock',lambda:f.FIN)
            if defect=='time':d['run']['finished_at']='2025-01-01T00:00:00Z'
            if defect=='missing':ds.pop(v3.PRODUCER_SLOTS[bridge.CERT])
            if defect=='foreign':ds[v3.PRODUCER_SLOTS[bridge.POLICY]]=b'{}'
            if defect=='noncanonical':ds[v3.HANDOFF]+=b' '
            if defect=='terminal':r['platform']['collection_ids']=[]
            if defect=='flag':r['collectors'][0]['requested']=not r['collectors'][0]['requested']
            if defect=='stale_rules':(root/RID/v2.FROZEN_FILE).write_bytes(f.RULE_BYTES+b' ')
            if defect=='unsafe_checkpoint':(root/RID/'checkpoints').chmod(0o755)
            with pytest.raises(store.StoreError):w.record_host(d,attempted=True,terminal=r,details=ds)
            assert not list((root/RID/'checkpoints').glob('*.json')) and not (root/RID/'run_manifest.json').exists()


@pytest.mark.parametrize('defect',['mode','hardlink','symlink','coherent_reindex','profile','duplicate_stage'])
def test_r2s_read_rejects_actual_tamper(root,monkeypatch,defect):
    items=[small()]
    with store.RunStore(root) as s:
        with start(s,items,monkeypatch) as w:record(w,items,monkeypatch);result=publish(w,items)
        run=root/RID;path=run/'cff_projection.json'
        if defect=='mode':path.chmod(0o644)
        elif defect=='hardlink':(run/'extra-link').hardlink_to(path)
        elif defect=='symlink':path.unlink();path.symlink_to('evidence.json')
        elif defect=='duplicate_stage':
            plan=store._unseal((run/'prepared.json').read_bytes(),v3.MANIFEST_BYTES);other=run/plan['stage']/'cff_projection.json';other.write_bytes(path.read_bytes());other.chmod(0o600)
        else:
            plan=store._unseal((run/'prepared.json').read_bytes(),v3.MANIFEST_BYTES);manifest=plan['manifest']
            if defect=='profile':manifest['capacity_profile']='OTHER_PROFILE'
            else:
                raw=path.read_bytes()+b' ';path.write_bytes(raw);entry=next(e for e in manifest['artifacts'] if e['path']==path.name);entry.update(size=len(raw),sha256=hashlib.sha256(raw).hexdigest())
            (run/'prepared.json').write_bytes(store._seal(plan,v3.MANIFEST_BYTES));(run/'run_manifest.json').write_bytes(store._json_bytes(manifest,v3.MANIFEST_BYTES))
        with pytest.raises(store.StoreError):s._open_v3(RID)


def test_r2s_exact_accounting_boundaries():
    # Accounting-only tests, not claimed as legal maximum producer fixtures.
    assert v3._checkpoint_budget(9*v3.CHECKPOINT_BYTES,v3.CHECKPOINT_BYTES)==v3.CHECKPOINT_TOTAL
    with pytest.raises(store.StoreError):v3._checkpoint_budget(0,v3.CHECKPOINT_BYTES+1)
    with pytest.raises(store.StoreError):v3._checkpoint_budget(v3.CHECKPOINT_TOTAL,1)
    for stage,cap in [('RAW_EVIDENCE',v3.RAW_BYTES),('ASSESSED_EVIDENCE',v3.ASSESSED_BYTES),('CFF',v3.CFF_BYTES),('CORE',v3.CORE_BYTES)]:
        v3._budget(cap,cap,stage)
        with pytest.raises(v3.CapacityError) as ex:v3._budget(cap+1,cap,stage)
        assert ex.value.stage==stage


def test_r2s_intent_durability(root,monkeypatch):
    items=[small()];hid=items[0][2]['hosts'][0]['host_id']
    with store.RunStore(root) as s:
        with start(s,items,monkeypatch) as w:
            original=store._write
            def fail(fd,name,raw,device,**kw):
                original(fd,name,raw,device,**kw)
                if name=='journal.json':raise OSError('injected durability uncertainty')
            with monkeypatch.context() as fault:
                fault.setattr(store,'_write',fail)
                with pytest.raises(store.StoreError):w.dispatch_intent(hid)
            with pytest.raises(store.StoreError):w.dispatch_intent(hid)
        monkeypatch.setattr(v3,'_clock',lambda:RECOVER)
        r=s._recover_v3(RID);assert r.manifest['hosts'][0]['attempt_status']=='UNKNOWN' and r.manifest['hosts'][0]['attempted'] is None


@pytest.mark.parametrize('cap',[v3.CHECKPOINT_BYTES,v3.MANIFEST_BYTES])
def test_r2s_actual_seal_file_boundary(root,cap):
    # Actual exact/+1 serialization and pinned file-size guard, not a claim
    # that an arbitrary maximum-sized JSON object is valid host Evidence.
    empty={'fixture':[]};base=len(store._seal(empty,cap));n,rem=divmod(cap-base+1,4099)
    body={'fixture':['x'*4096]*n}
    if rem:
        assert rem>=3
        body['fixture'].append('y'*(rem-3))
    sealed=store._seal(body,cap);assert len(sealed)==cap
    with pytest.raises(store.StoreError,match='SIZE_LIMIT'):
        store._seal({'fixture':body['fixture']+['']},cap)
    # Precisely +1 actual seal: increase the final bounded literal by one.
    last=body['fixture'][-1];assert len(last)<4096
    bigger={'fixture':body['fixture'][:-1]+[last+'z']}
    with pytest.raises(store.StoreError,match='SIZE_LIMIT'):store._seal(bigger,cap)
    fd=store._root(root)
    try:
        import os
        device=os.fstat(fd).st_dev
        store._write(fd,'exact.json',sealed,device);assert store._read(fd,'exact.json',device,cap)==sealed
        too_large=root/'plus-one.json';too_large.write_bytes(sealed+b' ');too_large.chmod(0o600)
        with pytest.raises(store.StoreError,match='ARTIFACT_SIZE'):store._read(fd,'plus-one.json',device,cap)
    finally:os.close(fd)


@pytest.mark.parametrize('defect',['flag','duplicate_host','future_start','public_selector','foreign_identity','bad_rules'])
def test_r2s_reservation_rejects_before_write(root,monkeypatch,defect):
    item=small();n=item[1]['target_id'];monkeypatch.setattr(v3,'_clock',lambda:f.TIME)
    args=dict(run_id=RID,expected_hosts=[dict(target_id=n,inventory_authority_id=None,identity_key=n)],
        requested_flags={n:dict(item[0])},limits=LIMITS,profile='extended',producer_rules_raw=f.RULE_BYTES,started_at=f.TIME)
    if defect=='flag':args['requested_flags'][n][bridge.TLS]=True
    if defect=='duplicate_host':args['expected_hosts']*=2
    if defect=='future_start':args['started_at']=f.FIN
    if defect=='foreign_identity':args['expected_hosts'][0]['inventory_authority_id']='fixture-authority'
    if defect=='bad_rules':args['producer_rules_raw']=b'{}'
    with store.RunStore(root) as s:
        with pytest.raises(store.StoreError):
            if defect=='public_selector':s.begin(**args,run_kind='SYNTHETIC',source=v2.SOURCE,evidence_schema_version='1.1.0',recorded_at=f.TIME,batch_contract=v3.CONTRACT)
            else:s._begin_v3(**args)
        assert not (root/RID).exists()


def test_r2s_manifest_schema_closed(root,monkeypatch):
    import jsonschema
    items=[small()]
    with store.RunStore(root) as s:
        with start(s,items,monkeypatch) as w:record(w,items,monkeypatch);result=publish(w,items)
    new=v3.manifest_schema_v3();old=store.manifest_schema()
    assert json.loads((f.ROOT/'schemas/run-manifest-1.0.0.schema.json').read_bytes())==old
    assert json.loads((f.ROOT/'schemas/run-manifest-1.1.0.schema.json').read_bytes())==new
    jsonschema.Draft202012Validator.check_schema(new);validator=jsonschema.Draft202012Validator(new)
    assert validator.is_valid(result.manifest) and not jsonschema.Draft202012Validator(old).is_valid(result.manifest)
    for mutate in (lambda m:m.update(extra=True),lambda m:m.update(capacity_profile='other'),lambda m:m.update(manifest_version='1.0.0'),
        lambda m:m['hosts'][0].update(unknown=True),lambda m:m['artifacts'][0].update(path='../outside'),
        lambda m:m['requirements'].update(cff=False),lambda m:m['hosts'][0].update(attempted=None)):
        altered=copy.deepcopy(result.manifest);mutate(altered);assert not validator.is_valid(altered)


def test_r2s_capacity_journal_failure(root,monkeypatch):
    items=[small()]
    with store.RunStore(root) as s:
        with start(s,items,monkeypatch) as w:
            record(w,items,monkeypatch);run=root/RID;cp=next((run/'checkpoints').glob('*.json'));raw=cp.read_bytes();j=(run/'journal.json').read_bytes();original=store._write
            def failed(fd,name,body,device,**kw):
                if name=='journal.json':raise OSError('fixture blocked journal write')
                return original(fd,name,body,device,**kw)
            with monkeypatch.context() as fault:
                fault.setattr(v3,'RAW_BYTES',1000);fault.setattr(store,'_write',failed)
                with pytest.raises(store.StoreError,match='STORE_IO') as ex:publish(w,items)
                assert not isinstance(ex.value,v3.CapacityError)
            assert (run/'journal.json').read_bytes()==j and cp.read_bytes()==raw and not (run/'run_manifest.json').exists()
            with pytest.raises(store.StoreError):w.dispatch_intent(items[0][2]['hosts'][0]['host_id'])


@pytest.mark.parametrize('secret',[b'{"password":"fixture-only"}',b'{"fixture":"-----BEGIN PRIVATE KEY-----"}'])
def test_r2s_secret_refused(root,monkeypatch,secret):
    item=small();_,row,doc,details,_=item;details=dict(details);details[v3.HANDOFF]=secret
    with store.RunStore(root) as s:
        with start(s,[item],monkeypatch) as w:
            w.dispatch_intent(doc['hosts'][0]['host_id']);monkeypatch.setattr(v3,'_clock',lambda:f.FIN)
            with pytest.raises(store.StoreError,match='FORBIDDEN_FIELD'):w.record_host(doc,attempted=True,terminal=row,details=details)
            assert not list((root/RID/'checkpoints').glob('*.json'))


def test_r2s_connection_receipts_and_lifecycle_downgrade(root,monkeypatch):
    from types import SimpleNamespace
    items=[small(0)]
    for i,connection in enumerate(('CONNECTION_FAILED','CONNECTION_TIMEOUT','CONNECTION_FAILED'),1):
        n='fixture-%02d.example.invalid'%i;ff={x:x==bridge.CERT_FLAG for x in bridge.FLAGS}
        raw=bridge.wire_bytes(dict(handoff_version=1,run_id=RID,target_id=n,connection=connection,records=[]))
        p=bridge.normalize_handoff(bridge.read_wire(raw),RID,n,ff,f.TIME,f.rules,staged_cert=True)
        row=batch._host(n,True,[p.outcomes[x] for x in batch._COLLECTORS],p.special);row['platform']=p.outcomes[bridge.PLATFORM]
        if i==3:
            # Exercise the actual lifecycle conversion, without dispatching a worker.
            ctx=SimpleNamespace(_targets=[n],_decisions={n:{'requested_flags':ff}})
            ledger=batch._ProducerLedger(ctx,SimpleNamespace(bridge=bridge),{n:(bridge.CERT_FLAG,)})
            ledger.rows[n]=row;ledger.started[n]='fixture-task';ledger.worker_failed(n,'CONTROLLER_WORKER_FAILED')
            row=ledger.finish()[0];assert row['host_state']=='ERROR' and row['platform']['state']=='ERROR'
        items.append((ff,row,fragment(row,p.document),{v3.HANDOFF:raw},p))
    n='fixture-04.example.invalid';ff=items[1][0];row=batch._blank(n,ff,'STOPPED');row['platform']=batch._outcome(bridge.PLATFORM,True,'NOT_SCANNED','STOPPED')
    items.append((ff,row,fragment(row),{},None));actual(root,items,monkeypatch)


def test_r2s_duplicate_checkpoint_immutable(root,monkeypatch):
    items=[small()]
    with store.RunStore(root) as s:
        with start(s,items,monkeypatch) as w:
            record(w,items,monkeypatch);cp=next((root/RID/'checkpoints').glob('*.json'));old=cp.read_bytes()
            _,r,d,ds,_=items[0]
            with pytest.raises(store.StoreError,match='TERMINAL_EXISTS'):w.record_host(d,attempted=True,terminal=r,details=ds)
            assert cp.read_bytes()==old and not (root/RID/'run_manifest.json').exists()


# C4a: actual offline V3 API / recovery. No transport or fake Store objects.
def _c4a_snapshot(path):
    import stat
    # Atime can legitimately change on read; namespace, content, mode,
    # identity and modification timestamps must not.
    return {str(p.relative_to(path)): (p.lstat().st_ino, p.lstat().st_mode,
            p.lstat().st_mtime_ns, p.lstat().st_ctime_ns,
            p.read_bytes() if stat.S_ISREG(p.lstat().st_mode) else None)
            for p in path.rglob('*')}


def _c4a_publish(s, monkeypatch, modes=('complete',)):
    items = [small(i) if mode == 'complete' else blank(i, mode)
             for i, mode in enumerate(modes)]
    with start(s, items, monkeypatch) as w:
        record(w, items, monkeypatch)
        return publish(w, items), items


def _c4a_prepare(s, monkeypatch):
    items = [small()]
    with start(s, items, monkeypatch) as w:
        record(w, items, monkeypatch)
        write = store._write
        def stop(fd, name, raw, device, **kw):
            if name == 'run_manifest.json':
                raise store.StoreError('DURABILITY_UNCONFIRMED')
            return write(fd, name, raw, device, **kw)
        with monkeypatch.context() as fault:
            fault.setattr(store, '_write', stop)
            with pytest.raises(store.StoreError, match='DURABILITY_UNCONFIRMED'):
                publish(w, items)
    monkeypatch.setattr(v3, '_clock', lambda: RECOVER)
    return items


@pytest.mark.parametrize('modes', [('complete',), ('complete', 'connection', 'worker'), ('disabled',)])
def test_c4a_actual_verified_snapshot(root, monkeypatch, modes):
    with store.RunStore(root) as s:
        result, items = _c4a_publish(s, monkeypatch, modes)
        check(root, result, items)
        before = _c4a_snapshot(root)
        assert s.open_v3(RID) == result == s._open_v3(RID)
        assert _c4a_snapshot(root) == before
        for action in (s.open, s.recover, s.recover_v3, s._recover_v3):
            with pytest.raises(store.StoreError):
                action(RID)
        # A returned snapshot is not mutable Store authority.
        changed = s.open_v3(RID)
        changed.manifest['run_state'] = 'bogus'
        changed.artifacts.clear()
        assert s.open_v3(RID) == result and _c4a_snapshot(root) == before


@pytest.mark.parametrize('prepared', [False, True])
@pytest.mark.parametrize('private', [False, True])
def test_c4a_actual_explicit_recovery(root, monkeypatch, prepared, private):
    with store.RunStore(root) as s:
        run = root / RID
        if prepared:
            items = _c4a_prepare(s, monkeypatch)
            original_plan = (run / 'prepared.json').read_bytes()
            expected = store._unseal(original_plan, v3.MANIFEST_BYTES)['manifest']
        else:
            items = [small(0), small(1), small(2)]
            with start(s, items, monkeypatch) as w:
                for item in items[:2]:
                    w.dispatch_intent(item[2]['hosts'][0]['host_id'])
                monkeypatch.setattr(v3, '_clock', lambda: f.FIN)
                _, row, doc, details, _ = items[0]
                w.record_host(doc, attempted=True, terminal=row, details=details)
            monkeypatch.setattr(v3, '_clock', lambda: RECOVER)
        before = _c4a_snapshot(run)
        with pytest.raises(store.StoreError):
            s.recover(RID)
        assert _c4a_snapshot(run) == before
        result = (s._recover_v3 if private else s.recover_v3)(RID)
        assert result == s.open_v3(RID) == s._open_v3(RID)
        assert (run / v2.FROZEN_FILE).read_bytes() == f.RULE_BYTES
        for path, value in before.items():
            if path.startswith('checkpoints/') or path in ('journal.json', v2.FROZEN_FILE):
                assert _c4a_snapshot(run)[path] == value
        if prepared:
            assert result.manifest == expected and not result.manifest['recovery']
            assert (run / 'prepared.json').read_bytes() == original_plan
            check(root, result, items)
        else:
            assert result.manifest['recovery'] and result.assessed is None
            by_target = {h['target_id']: h for h in result.manifest['hosts']}
            assert by_target[items[0][1]['target_id']]['terminal'] == items[0][1]
            assert by_target[items[1][1]['target_id']]['attempt_status'] == 'UNKNOWN'
            assert by_target[items[2][1]['target_id']]['attempt_status'] == 'NOT_ATTEMPTED'
            assert not {'batch_manifest.json', 'assessed_evidence.json', 'cff_projection.json',
                        'assessment_rules.json'} & set(result.artifacts)
        before = _c4a_snapshot(run)
        with pytest.raises(store.StoreError, match='ALREADY_PUBLISHED'):
            s.recover_v3(RID)
        assert _c4a_snapshot(run) == before


@pytest.mark.parametrize('operation', ['open', 'recover'])
@pytest.mark.parametrize('defect', ['root', 'run', 'lock'])
def test_c4a_identity_after_lock(root, monkeypatch, operation, defect):
    import os
    with store.RunStore(root) as s:
        if operation == 'open':
            _c4a_publish(s, monkeypatch, ('disabled',))
        else:
            with start(s, [blank(0, 'disabled')], monkeypatch):
                pass
        run = root / RID
        alt = root.parent / 'other-root'; alt.mkdir(mode=0o700)
        old_flock = store._flock
        def drift(fd, **kw):
            old_flock(fd, **kw)
            if defect == 'root':
                other = os.open(alt, os.O_RDONLY | os.O_DIRECTORY)
                try: os.dup2(other, s._fd)
                finally: os.close(other)
            elif defect == 'run':
                run.rename(root / 'detached'); run.mkdir(mode=0o700)
            else:
                (run / '.writer.lock').rename(run / 'detached-lock')
                (run / '.writer.lock').touch(mode=0o600)
        monkeypatch.setattr(store, '_flock', drift)
        with pytest.raises(store.StoreError, match='IDENTITY_CHANGED'):
            (s.open_v3 if operation == 'open' else s.recover_v3)(RID)
        if operation == 'recover':
            assert not (run / 'run_manifest.json').exists()
            assert not (root / 'detached' / 'run_manifest.json').exists()
            assert not (alt / RID / 'run_manifest.json').exists()


def test_c4a_actual_lock_contention(root, monkeypatch):
    with store.RunStore(root) as s, store.RunStore(root) as other:
        result, _ = _c4a_publish(s, monkeypatch, ('disabled',))
        with s._locked_run(RID, shared=True):
            assert other.open_v3(RID) == result
            with pytest.raises(store.StoreError, match='RUN_BUSY'):
                other.recover_v3(RID)
        with s._locked_run(RID, shared=False):
            for action in (other.open_v3, other.recover_v3):
                with pytest.raises(store.StoreError, match='RUN_BUSY'):
                    action(RID)


@pytest.mark.parametrize('defect', ['run', 'lock', 'stage', 'extra'])
def test_c4a_read_rechecks_before_delivery(root, monkeypatch, defect):
    with store.RunStore(root) as s:
        _c4a_publish(s, monkeypatch, ('disabled',))
        run = root / RID
        plan = store._unseal((run / 'prepared.json').read_bytes(), v3.MANIFEST_BYTES)
        replay = v3.Writer._replay
        def drift(self, *args, **kw):
            result = replay(self, *args, **kw)
            if defect == 'run':
                run.rename(root / 'detached'); run.mkdir(mode=0o700)
            elif defect == 'lock':
                (run / '.writer.lock').rename(run / 'detached-lock')
                (run / '.writer.lock').touch(mode=0o600)
            elif defect == 'stage':
                (run / plan['stage']).rename(run / 'detached-stage')
                (run / plan['stage']).mkdir(mode=0o700)
            else:
                (run / 'index.html').touch(mode=0o600)
            return result
        monkeypatch.setattr(v3.Writer, '_replay', drift)
        with pytest.raises(store.StoreError):
            s.open_v3(RID)


@pytest.mark.parametrize('defect', ['derived', 'foreign', 'details', 'stage-link',
                                  'temp-link', 'checkpoint-temp-link', 'rules', 'checkpoint'])
def test_c4a_unprepared_rejection_before_staging(root, monkeypatch, defect):
    with store.RunStore(root) as s:
        with start(s, [small()], monkeypatch) as w:
            record(w, [small()], monkeypatch)
        run = root / RID
        if defect == 'derived': (run / 'portal-v5').mkdir(mode=0o700)
        elif defect == 'foreign': (run / 'foreign.json').touch(mode=0o600)
        elif defect == 'details': (run / 'details').mkdir(mode=0o700)
        elif defect == 'stage-link': (run / ('.stage-' + 'a'*32)).symlink_to('checkpoints')
        elif defect == 'temp-link': (run / ('.tmp-' + 'a'*32)).symlink_to('journal.json')
        elif defect == 'checkpoint-temp-link':
            (run / 'checkpoints' / ('.tmp-' + 'a'*32)).symlink_to('../journal.json')
        elif defect == 'rules': (run / v2.FROZEN_FILE).write_bytes(f.RULE_BYTES + b' ')
        else:
            cp = next((run / 'checkpoints').glob('*.json')); cp.write_bytes(cp.read_bytes()+b' ')
        before = _c4a_snapshot(run)
        monkeypatch.setattr(v3, '_clock', lambda: RECOVER)
        with pytest.raises(store.StoreError):
            s.recover_v3(RID)
        assert _c4a_snapshot(run) == before and not (run / 'run_manifest.json').exists()


@pytest.mark.parametrize('prepared', [False, True])
@pytest.mark.parametrize('defect', ['run', 'lock', 'stage', 'rules', 'checkpoint', 'foreign', 'marker', 'core', 'plan', 'journal'])
def test_c4a_marker_boundary_rechecks(root, monkeypatch, prepared, defect):
    with store.RunStore(root) as s:
        if prepared:
            _c4a_prepare(s, monkeypatch)
        else:
            items = [small()]
            with start(s, items, monkeypatch) as w:
                record(w, items, monkeypatch)
            monkeypatch.setattr(v3, '_clock', lambda: RECOVER)
        run = root / RID
        write = store._write
        triggered = []
        def at_marker(fd, name, raw, device, **kw):
            if name == 'run_manifest.json':
                check = kw['before_publish']
                def drift():
                    triggered.append(True)
                    if defect == 'run':
                        run.rename(root / 'detached'); run.mkdir(mode=0o700)
                    elif defect == 'lock':
                        (run / '.writer.lock').rename(run / 'detached-lock')
                        (run / '.writer.lock').touch(mode=0o600)
                    elif defect == 'stage':
                        plan = store._unseal((run / 'prepared.json').read_bytes(), v3.MANIFEST_BYTES)
                        (run / plan['stage']).rename(run / 'detached-stage')
                        (run / plan['stage']).mkdir(mode=0o700)
                    elif defect == 'rules': (run / v2.FROZEN_FILE).write_bytes(f.RULE_BYTES + b' ')
                    elif defect == 'checkpoint':
                        cp = next((run / 'checkpoints').glob('*.json')); cp.write_bytes(cp.read_bytes()+b' ')
                    elif defect == 'foreign': (run / 'portal.css').touch(mode=0o600)
                    elif defect == 'core':
                        path = run / 'evidence.json'; path.write_bytes(path.read_bytes()+b' ')
                    elif defect == 'plan': (run / 'prepared.json').write_bytes(b'{}')
                    elif defect == 'journal': (run / 'journal.json').write_bytes(b'{}')
                    else:
                        (run / 'run_manifest.json').write_bytes(b'foreign marker')
                        (run / 'run_manifest.json').chmod(0o600)
                    check()
                kw['before_publish'] = drift
            return write(fd, name, raw, device, **kw)
        monkeypatch.setattr(store, '_write', at_marker)
        with pytest.raises(store.StoreError):
            s.recover_v3(RID)
        assert triggered == [True]
        if defect == 'marker':
            assert (run / 'run_manifest.json').read_bytes() == b'foreign marker'
        else:
            assert not (run / 'run_manifest.json').exists()
        assert not (root / 'detached' / 'run_manifest.json').exists()


@pytest.mark.parametrize('defect', ['missing-core', 'tamper-core', 'unsafe-mode', 'hardlink',
                                  'foreign', 'bad-journal', 'bad-plan', 'old-version',
                                  'capacity', 'checkpoint-capacity'])
def test_c4a_actual_read_closed_namespace(root, monkeypatch, defect):
    with store.RunStore(root) as s:
        result, _ = _c4a_publish(s, monkeypatch)
        run = root / RID; path = run / 'evidence.json'
        if defect == 'missing-core': path.unlink()
        elif defect == 'tamper-core': path.write_bytes(path.read_bytes()+b' ')
        elif defect == 'unsafe-mode': path.chmod(0o644)
        elif defect == 'hardlink': (run / 'extra-link').hardlink_to(path)
        elif defect == 'foreign': (run / 'portal.css').touch(mode=0o600)
        elif defect == 'bad-journal': (run / 'journal.json').write_bytes(b'{}')
        elif defect == 'bad-plan': (run / 'prepared.json').write_bytes(b'{}')
        elif defect == 'old-version':
            altered = copy.deepcopy(result.manifest); altered['manifest_version'] = '1.0.0'
            (run / 'run_manifest.json').write_bytes(store._json_bytes(altered, v3.MANIFEST_BYTES))
        elif defect == 'capacity':
            # Actual safe sparse oversized file; fail before consuming bytes.
            with path.open('r+b') as stream: stream.truncate(v3.RAW_BYTES+1)
        else:
            cp = next((run / 'checkpoints').glob('*.json'))
            with cp.open('r+b') as stream: stream.truncate(v3.CHECKPOINT_BYTES+1)
        with pytest.raises(store.StoreError):
            s.open_v3(RID)


def test_c4a_actual_old_v2_version_isolation(root):
    import test_run_store_v2_certificate as old
    args, doc, terminal_rows, rc, details = old.fixture(('complete',))
    with store.RunStore(root) as s:
        with s.begin(**args) as w:
            old.record(w, doc, terminal_rows, details)
        run = root / old.RID; before = _c4a_snapshot(run)
        with pytest.raises(store.StoreError):
            s.recover_v3(old.RID)
        assert _c4a_snapshot(run) == before
        result = s.recover(old.RID)
        assert s.open(old.RID) == result
        before = _c4a_snapshot(run)
        with pytest.raises(store.StoreError):
            s.open_v3(old.RID)
        assert _c4a_snapshot(run) == before


def test_c4a_post_marker_durability_uncertain(root, monkeypatch):
    with store.RunStore(root) as s:
        items = [small()]
        with start(s, items, monkeypatch) as w:
            record(w, items, monkeypatch)
        monkeypatch.setattr(v3, '_clock', lambda: RECOVER)
        write = store._write
        def uncertain(fd, name, raw, device, **kw):
            write(fd, name, raw, device, **kw)
            if name == 'run_manifest.json':
                raise store.StoreError('DURABILITY_UNCONFIRMED')
        with monkeypatch.context() as fault:
            fault.setattr(store, '_write', uncertain)
            with pytest.raises(store.StoreError, match='DURABILITY_UNCONFIRMED'):
                s.recover_v3(RID)
        assert s.open_v3(RID).manifest['recovery']
        before = _c4a_snapshot(root/RID)
        with pytest.raises(store.StoreError, match='ALREADY_PUBLISHED'):
            s.recover_v3(RID)
        assert _c4a_snapshot(root/RID) == before


@pytest.mark.parametrize('defect', ['run', 'lock', 'foreign'])
def test_c4a_unprepared_recheck_after_derive(root, monkeypatch, defect):
    with store.RunStore(root) as s:
        items = [small()]
        with start(s, items, monkeypatch) as w:
            record(w, items, monkeypatch)
        monkeypatch.setattr(v3, '_clock', lambda: RECOVER)
        run = root / RID; derive = v3.Writer._derive
        def drift(self, *args, **kw):
            result = derive(self, *args, **kw)
            if defect == 'run':
                run.rename(root / 'detached'); run.mkdir(mode=0o700)
            elif defect == 'lock':
                (run / '.writer.lock').rename(run / 'detached-lock')
                (run / '.writer.lock').touch(mode=0o600)
            else: (run / 'index.html').touch(mode=0o600)
            return result
        monkeypatch.setattr(v3.Writer, '_derive', drift)
        with pytest.raises(store.StoreError):
            s.recover_v3(RID)
        for d in (run, root / 'detached'):
            assert not list(d.glob('.stage-*'))
            assert not (d / 'prepared.json').exists() and not (d / 'run_manifest.json').exists()


def test_c4a_pinned_root_not_reopened(root, monkeypatch):
    with store.RunStore(root) as s:
        result, _ = _c4a_publish(s, monkeypatch, ('disabled',))
        moved = root.parent / 'moved-root'; root.rename(moved); root.mkdir(mode=0o700)
        before = _c4a_snapshot(moved)
        assert s.open_v3(RID) == result and _c4a_snapshot(moved) == before
        with store.RunStore(root) as different:
            with pytest.raises(store.StoreError, match='RUN_NOT_FOUND'):
                different.open_v3(RID)


@pytest.mark.parametrize('kind', ['native', 'legacy'])
def test_c4a_actual_old_v1_legacy_version_isolation(root, kind):
    target = 'old-fixture.example.invalid'
    args = dict(run_id=RID, expected_hosts=[dict(target_id=target,
                inventory_authority_id=None, identity_key=target)], recorded_at=f.FIN,
                started_at=f.TIME, run_kind='SYNTHETIC', evidence_schema_version='1.1.0',
                source=dict(v2.SOURCE), limits=LIMITS, profile='extended',
                requested_flags={target: {key: False for key in store.NATIVE_COLLECTORS}},
                batch_contract=store.NATIVE_BATCH_CONTRACT)
    if kind == 'legacy':
        raw = b'{"fixture":"legacy"}'
        source = dict(source_kind='LEGACY_IMPORT', producer_id='legacy-ol-run-summary',
                      producer_version=None, origin_ref='fixture-source',
                      input_sha256=hashlib.sha256(raw).hexdigest())
        args.pop('batch_contract')
        args.update(run_kind='LEGACY_IMPORT', evidence_schema_version='1.0.0',
                    source=source, started_at=None, limits=None, profile=None,
                    requested_flags=None, legacy_raw=raw,
                    legacy_provenance=dict(format_version='1.0.0', source=source,
                        original_run_id='old-fixture', original_generated_at=f.TIME,
                        diagnostics=[dict(reason_code='LEGACY_REPORT_MISSING', count=1)]))
    with store.RunStore(root) as s:
        with s.begin(**args):
            pass
        before = _c4a_snapshot(root/RID)
        with pytest.raises(store.StoreError): s.recover_v3(RID)
        assert _c4a_snapshot(root/RID) == before
        recovered = s.recover(RID)
        assert recovered.manifest['manifest_version'] == '1.0.0'
        assert s.open(RID) == recovered
        before = _c4a_snapshot(root/RID)
        with pytest.raises(store.StoreError): s.open_v3(RID)
        assert _c4a_snapshot(root/RID) == before


@pytest.mark.parametrize('kind', ['regular', 'directory', 'symlink'])
def test_c4a_refuse_any_existing_marker(root, monkeypatch, kind):
    with store.RunStore(root) as s:
        with start(s, [blank(0, 'disabled')], monkeypatch):
            pass
        marker = root / RID / 'run_manifest.json'
        if kind == 'directory': marker.mkdir(mode=0o700)
        elif kind == 'symlink': marker.symlink_to('journal.json')
        else:
            marker.write_bytes(b'invalid marker'); marker.chmod(0o600)
        before = _c4a_snapshot(root/RID)
        with pytest.raises(store.StoreError, match='ALREADY_PUBLISHED'):
            s.recover_v3(RID)
        assert _c4a_snapshot(root/RID) == before
