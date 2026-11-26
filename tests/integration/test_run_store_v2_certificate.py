"""C1 actual private Store round trips; original anonymous typed bridge only."""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import assessment, batch_execution as batch, cert_assets as ca, evidence, platform
from tools import run_store as store, run_store_v2 as v2, scan_collectors as bridge

RID = 'c1-certificate-fixture'
START = '2026-01-01T00:00:00Z'
OBS = '2026-01-01T00:00:01Z'
END = '2026-01-01T00:00:02Z'
RULES_RAW = (ROOT / 'config/assessment_rules.yml').read_bytes()
RULES = assessment.load_rules(RULES_RAW)
LIMITS = dict(max_hosts=10, forks=2, serial=2, ssh_timeout_s=15, command_timeout_s=30)
TARGETS = ('host-a.example.invalid', 'host-b.example.invalid', 'host-c.example.invalid')


def digest(s):
    return hashlib.sha256(s.encode('ascii')).hexdigest()


def flags(active=True):
    return {f: active and f == bridge.CERT_FLAG for f in batch._COLLECTORS}


def platform_snapshot():
    yes = dict(state='OK', exists=True, isreg=True, islnk=False, executable=True)
    return dict(facts_state='OK', facts=dict(distribution='OracleLinux', os_family='RedHat',
                architecture='x86_64', distribution_version='9.10', distribution_major_version='9'),
                tools={k: [dict(yes) for _ in range(n)] for k, n in platform.TOOL_SLOTS.items()}, rpms={})


def cert_snapshot(partial=False, large=False):
    def cert(n):
        c = dict(fingerprint=digest('public-fixture-' + str(n)), public_key_algorithm='rsaEncryption',
                 public_key_bits=2048, signature_inner='sha256WithRSAEncryption',
                 signature_outer='sha256WithRSAEncryption', issuer='CN=Fixture issuer',
                 subject='CN=Fixture certificate', not_before=START, not_after='2027-01-01T00:00:00Z')
        if partial and n == 1: c['not_after'] = None
        c['gaps'] = ca.metadata_gaps(c)
        return c
    def source(n, numbers):
        blocks = []
        for number in numbers:
            c = cert(number)
            blocks.append(dict(rc=0, reason='METADATA_GAP' if c['gaps'] else 'OK', certificate=c))
        return dict(source_id='src-' + digest('source' + str(n)), target_id='src-' + digest('target' + str(n)),
                    format='PEM', gaps=[], blocks=blocks)
    sources = sorted([source(0, [0, 1, 0]), source(1, [0])] if not large else
                     [source(i, [2*i, 2*i+1]) for i in range(8)], key=lambda r: r['source_id'])
    return {k: dict(attempted=True, rc=0, entries=len(sources) if i == 0 else 0, directories=0,
                    skipped=0, root_target_id='src-' + digest(ca.ROOT_PATHS[k]), gaps=[],
                    sources=sources if i == 0 else []) for i,k in enumerate(ca.ROOTS)}


def envelope(target, mode='complete', *, large=False):
    if mode == 'connection':
        return dict(handoff_version=1, run_id=RID, target_id=target, connection='CONNECTION_FAILED', records=[])
    rows = [dict(producer_id=bridge.PLATFORM, observed_at=START, reason_code='COMMAND_OK', rc=0,
                 cleanup_confirmed=True, snapshot=platform_snapshot())]
    if mode == 'error':
        rows.append(dict(producer_id=bridge.CERT, observed_at=OBS, reason_code='COMMAND_FAILED', rc=1,
                         cleanup_confirmed=True, snapshot=None))
    else:
        rows.append(dict(producer_id=bridge.CERT, observed_at=OBS, reason_code='COMMAND_OK', rc=0,
                         cleanup_confirmed=True, snapshot=dict(system_python_available=True,
                         roots=cert_snapshot(mode == 'partial', large))))
    return dict(handoff_version=1, run_id=RID, target_id=target, connection='CONNECTED', records=rows)


def fixture(modes=('complete',), *, large=False):
    names = TARGETS[:len(modes)]
    rows, projections, companions, details = [], {}, {}, {}
    ff = {n: flags(mode != 'disabled') for n,mode in zip(names, modes)}
    for n,mode in zip(names,modes):
        if mode in ('disabled', 'stopped', 'worker'):
            reason = {'disabled':'NO_EXECUTABLE_COLLECTORS', 'stopped':'STOPPED', 'worker':'CONTROLLER_WORKER_FAILED'}[mode]
            row = batch._blank(n, ff[n], reason, mode == 'worker')
            row['platform'] = batch._outcome(bridge.PLATFORM, any(ff[n].values()),
                'ERROR' if mode == 'worker' else 'NOT_SCANNED',
                'OUTCOME_UNKNOWN' if mode == 'worker' else 'DISABLED' if mode == 'disabled' else 'STOPPED')
            ds = []
        else:
            env = bridge.read_wire(bridge.wire_bytes(envelope(n, mode, large=large)))
            p = bridge.normalize_handoff(env, RID, n, ff[n], START, RULES)
            row = batch._host(n, True, [p.outcomes[f] for f in batch._COLLECTORS], p.special)
            row['platform'] = p.outcomes[bridge.PLATFORM]
            projections[n], companions[n] = p, p.companions
            ds = [(v2.HANDOFF, env)] + [(slot, p.companions[producer]) for slot,producer in
                 ((v2.PLATFORM,bridge.PLATFORM),(v2.CERTIFICATE,bridge.CERT)) if producer in p.companions]
        rows.append(row)
        hid = bridge.host_record(RID,n)['host_id']
        details[hid] = [dict(host_id=hid, slot=slot, value=value) for slot,value in ds]
    state,reason,rc = batch._run_state(rows, 'CONTROLLER_WORKER_FAILED' if any(m in ('worker', 'stopped') for m in modes) else None)
    doc = bridge.document(RID, START, [bridge.host_record(RID,r['target_id'],r['host_state'],r['reason_code'])
                                      for r in rows], state, END)
    doc['run']['coverage_reason'] = reason
    for p in projections.values():
        doc = bridge._append(doc,p.document)
    terminal = dict(batch_manifest_version=2,target_ids=sorted(names),target_count=len(names),limits=LIMITS,
                    profile='baseline',run_state=state,reason_code=reason,hosts=rows)
    batch.validate_producer_manifest(terminal,rc)
    bridge.validate_bindings(terminal,doc,companions,projections)
    doc = json.loads(evidence.canonical_bytes(doc))
    args = dict(run_id=RID,run_kind='SYNTHETIC',evidence_schema_version='1.1.0',source=dict(v2.SOURCE),
                started_at=START,recorded_at=END,expected_hosts=[dict(target_id=n,inventory_authority_id=None,
                identity_key=n) for n in names],limits=LIMITS,profile='baseline',requested_flags=ff,
                batch_contract=v2.CONTRACT,producer_rules_raw=RULES_RAW)
    return args,doc,terminal,rc,details


@pytest.fixture
def root(tmp_path):
    p=tmp_path/'reports';p.mkdir(mode=0o700);return p


def row_for(doc, terminal, hid):
    name=next(h['target_id'] for h in doc['hosts'] if h['host_id']==hid)
    return next(r for r in terminal['hosts'] if r['target_id']==name)


def record(w, doc, terminal, details, *, ids=None):
    for hid in ids if ids is not None else doc['run']['expected_host_ids']:
        row=row_for(doc,terminal,hid)
        if row['attempted']: w.dispatch_intent(hid)
        w.record_host(store.host_fragment(doc,hid),attempted=row['attempted'],terminal=row,details=details[hid])


def reject(code, fn, *args, **kwargs):
    with pytest.raises(store.StoreError) as exc: fn(*args, **kwargs)
    if code is not None: assert exc.value.code == code


def finalize(w, doc, terminal, rc, **kwargs):
    return w.finalize(doc,batch_raw=bridge.wire_bytes(terminal),batch_rc=rc,**kwargs)


def check_result(result, doc, terminal, details):
    assert result.document == doc
    assert result.manifest['batch_contract']==v2.CONTRACT
    assert result.artifacts[v2.RULES_FILE]==RULES_RAW
    assert result.manifest['producer_rules_sha256']==hashlib.sha256(RULES_RAW).hexdigest()
    assert result.manifest['producer_rules_version']==RULES['rule_version']
    assert result.manifest['rule_version'] is result.manifest['rules_sha256'] is None
    assert result.assessed is None
    for hid,ds in details.items():
        row=row_for(doc,terminal,hid)
        pids=set(row['platform']['collection_ids'])
        cids=set(next(c['collection_ids'] for c in row['collectors'] if c['collector_id']==bridge.CERT_FLAG))
        for d in ds:
            slot=d['slot'];path=f'details/{hid}/{slot}.json'
            expected=ca.canonical(d['value']) if slot==v2.CERTIFICATE else bridge.wire_bytes(d['value'])
            assert result.artifacts[path]==expected
            refs={v2.HANDOFF:pids|cids,v2.PLATFORM:pids,v2.CERTIFICATE:cids}[slot]
            entry=next(a for a in result.manifest['artifacts'] if a['path']==path)
            es=[e for e in doc['evidence'] if e['host_id']==hid and e['collection_id'] in refs]
            assert entry['collection_ids']==sorted(refs)
            assert entry['evidence_ids']==sorted(e['evidence_id'] for e in es)
            assert entry['asset_ids']==sorted({e['asset_id'] for e in es if e['asset_id'] is not None})
            assert entry['size']==len(expected) and entry['sha256']==hashlib.sha256(expected).hexdigest()
            assert entry['required'] is True and entry['format_version']=='1.0.0'
            if slot==v2.CERTIFICATE:
                ca.validate_cert_details(doc,d['value'],RULES)
                assert len(d['value']['occurrences'])>=4


@pytest.mark.parametrize('modes', [('complete','complete'),('complete','partial'),('complete','disabled'),
                                   ('complete','connection'),('complete','error'),('complete','stopped'),
                                   ('complete','worker'),('disabled',)])
def test_actual_roundtrip(root,modes):
    args,doc,terminal,rc,ds=fixture(modes)
    with store.RunStore(root) as s:
        with s.begin(**args) as w:
            assert (root/RID/v2.FROZEN_FILE).read_bytes()==RULES_RAW
            assert (root/RID/v2.FROZEN_FILE).stat().st_mode & 0o777==0o600
            record(w,doc,terminal,ds)
            result=finalize(w,doc,terminal,rc)
        check_result(result,doc,terminal,ds)
        assert s.open(RID)==result
        reject('ALREADY_PUBLISHED',s.recover,RID)
    if modes == ('complete','complete'):
        retained=[json.loads(data) for name,data in result.artifacts.items()
                  if name.endswith('/'+v2.CERTIFICATE+'.json')]
        assert len(retained)==2
        occurrences=[o for d in retained for o in d['occurrences']]
        assert len(occurrences)==8 and len({o['host_id'] for o in occurrences})==2
        assert len({o['fingerprint'] for o in occurrences})==2
        assert len({o['asset_id'] for o in occurrences})==4
        assert len({o['detail_sha256'] for o in occurrences})==8
        assert {o['block_index'] for o in occurrences}=={1,2,3}
        for d in retained:
            for r in d['snapshot'].values():
                for src in r['sources']:
                    for b in src['blocks']:
                        cert=b['certificate']
                        assert cert['not_before']==START and cert['not_after']=='2027-01-01T00:00:00Z'
                        assert cert['issuer']=='CN=Fixture issuer' and cert['subject']=='CN=Fixture certificate'
                        assert cert['public_key_bits']==2048 and cert['signature_inner']==cert['signature_outer']
        roles={e['observation_key'].rsplit('-',1)[-1] for e in result.document['evidence']
               if e['source']['producer_id']==bridge.CERT and e['asset_id'] is not None}
        assert roles=={'certificate','key','signature'}
    missing={x['path'] for x in result.manifest['missing_artifacts']}
    for h in doc['hosts']:
        hid=h['host_id']
        if args['requested_flags'][h['target_id']][bridge.CERT_FLAG]:
            assert {f'details/{hid}/{slot}.json' for slot in v2.SLOTS}-{f'details/{hid}/{d["slot"]}.json' for d in ds[hid]} <= missing


def test_actual_recovery_unprepared(root):
    args,doc,terminal,rc,ds=fixture(('complete','complete','complete'))
    ids=doc['run']['expected_host_ids']
    with store.RunStore(root) as s:
        with s.begin(**args) as w:
            record(w,doc,terminal,ds,ids=ids[:1]);w.dispatch_intent(ids[1])
        result=s.recover(RID)
        assert result.manifest['recovery'] is True
        assert result.manifest['recorded_at']==END and result.manifest['finished_at'] is None
        assert result.manifest['reason_code']=='RECOVERY_INCOMPLETE'
        assert [r['attempt_status'] for r in result.manifest['hosts']]==['ATTEMPTED','UNKNOWN','NOT_ATTEMPTED']
        assert result.artifacts[v2.RULES_FILE]==RULES_RAW
        assert s.open(RID)==result
        assert len(result.manifest['missing_artifacts'])==7


def test_actual_prepared_recovery(root,monkeypatch):
    args,doc,terminal,rc,ds=fixture()
    with store.RunStore(root) as s:
        with s.begin(**args) as w:
            record(w,doc,terminal,ds)
            original=store._write
            def stop(parent,name,raw,device,**kw):
                if name=='run_manifest.json': raise store.StoreError('DURABILITY_UNCONFIRMED')
                return original(parent,name,raw,device,**kw)
            with monkeypatch.context() as mp:
                mp.setattr(store,'_write',stop)
                reject('DURABILITY_UNCONFIRMED',finalize,w,doc,terminal,rc)
        assert not (root/RID/'run_manifest.json').exists()
        result=s.recover(RID)
        check_result(result,doc,terminal,ds)
        assert s.open(RID)==result


@pytest.mark.parametrize('defect', ['selector','native','schema','source','flag','active-profile',
                                    'host-identity','host-limit','implicit-id','missing-rules',
                                    'bad-rules','oversize-rules','old-rules','wrong-requirements','cff'])
def test_begin_rejects_before_reservation(root,defect):
    args,doc,terminal,rc,ds=fixture(('disabled',))
    if defect=='selector': args['batch_contract']='B04_PRODUCER_UNKNOWN'
    elif defect=='native': args['run_kind']='NATIVE_SCAN'
    elif defect=='schema': args['evidence_schema_version']='1.0.0'
    elif defect=='source': args['source']['origin_ref']='other-source'
    elif defect=='flag': args['requested_flags'][TARGETS[0]][bridge.SSL]=True
    elif defect=='active-profile': args['profile']='active'
    elif defect=='host-identity': args['expected_hosts'][0]['identity_key']='other'
    elif defect=='host-limit': args['limits']={**LIMITS,'max_hosts':11}
    elif defect=='implicit-id': del args['run_id']
    elif defect=='missing-rules': del args['producer_rules_raw']
    elif defect=='bad-rules': args['producer_rules_raw']=b'{}'
    elif defect=='oversize-rules': args['producer_rules_raw']=b' '*65537
    elif defect=='old-rules': args['batch_contract']=store.NATIVE_BATCH_CONTRACT
    elif defect=='wrong-requirements':
        args['requested_flags'][TARGETS[0]][bridge.CERT_FLAG]=True
        args['requirements']={'assessment':False,'cff':False,'details':[]}
    elif defect=='cff': args['requirements']={'assessment':True,'cff':True,'details':[]}
    with store.RunStore(root) as s: reject(None,s.begin,**args)
    assert not list(root.iterdir())


@pytest.mark.parametrize('defect', ['missing-handoff','missing-platform','missing-cert','duplicate-slot',
    'unknown-slot','foreign-host','raw-path','wrong-producer','wrong-source','wrong-scope','wrong-time',
    'wrong-rc','duplicate-ref','omitted-ref','foreign-ref','wrong-companion','wrong-hash','wrong-role',
    'wrong-root','oversize-cert','oversize-wire','bad-shape'])
def test_record_rejects_bad_binding(root,defect):
    args,doc,terminal,rc,ds=fixture()
    hid=doc['run']['expected_host_ids'][0]
    row=deepcopy(terminal['hosts'][0]); fragment=store.host_fragment(doc,hid)
    details=deepcopy(ds[hid]); index={d['slot']:d for d in details}
    cert=index[v2.CERTIFICATE]['value']; env=index[v2.HANDOFF]['value']
    cert_out=next(c for c in row['collectors'] if c['collector_id']==bridge.CERT_FLAG)
    if defect.startswith('missing-'):
        slot={'missing-handoff':v2.HANDOFF,'missing-platform':v2.PLATFORM,'missing-cert':v2.CERTIFICATE}[defect]
        details.remove(index[slot])
    elif defect=='duplicate-slot': details.append(deepcopy(details[0]))
    elif defect=='unknown-slot': details[0]['slot']='certificate-inventory'
    elif defect=='foreign-host': details[0]['host_id']=bridge.host_record(RID,TARGETS[1])['host_id']
    elif defect=='raw-path': details[0]['slot']='../other.json'
    elif defect=='wrong-producer': env['records'][1]['producer_id']=bridge.POLICY
    elif defect=='wrong-source': cert['source']['origin_ref']='other-source'
    elif defect=='wrong-scope': env['records'][1]['snapshot']['roots']['foreign']=deepcopy(cert['snapshot'][ca.ROOTS[0]])
    elif defect=='wrong-time': env['records'][1]['observed_at']='2026-01-01T00:01:00Z'
    elif defect=='wrong-rc': cert_out['rc']=1
    elif defect=='duplicate-ref': cert_out['collection_ids']+=cert_out['collection_ids'][:1]
    elif defect=='omitted-ref': cert_out['collection_ids'].pop()
    elif defect=='foreign-ref': cert_out['collection_ids'][0]='c-'+'0'*64;cert_out['collection_ids'].sort()
    elif defect=='wrong-companion': index[v2.PLATFORM]['value']['platform_status']='OUT_OF_SCOPE'
    elif defect=='wrong-hash': cert['occurrences'][0]['detail_sha256']='0'*64
    elif defect=='wrong-role': cert['occurrences'][0]['evidence_ids'].pop()
    elif defect=='wrong-root': cert['occurrences'][0]['root']='foreign'
    elif defect=='oversize-cert': index[v2.CERTIFICATE]['value']=['x'*4096]*512
    elif defect=='oversize-wire': index[v2.HANDOFF]['value']=['x'*4096]*256
    elif defect=='bad-shape': details[0]['path']='foreign.json'
    with store.RunStore(root) as s, s.begin(**args) as w:
        w.dispatch_intent(hid)
        reject(None,w.record_host,fragment,attempted=True,terminal=row,details=details)
        assert not (root/RID/'checkpoints'/f'{hid}.json').exists()
        assert not (root/RID/'prepared.json').exists()


def test_record_time_and_evidence_replay(root):
    args,doc,terminal,rc,ds=fixture();hid=doc['run']['expected_host_ids'][0]
    with store.RunStore(root) as s, s.begin(**args) as w:
        w.dispatch_intent(hid)
        altered=deepcopy(doc);altered['run']['finished_at']=OBS
        reject('PRODUCER_TIME_MISMATCH',w.record_host,altered,attempted=True,terminal=terminal['hosts'][0],details=ds[hid])
        altered=deepcopy(doc)
        # Alter a closed, schema-valid observation without changing its IDs.
        c=next(c for c in altered['collections'] if c['collector_id']==bridge.CERT)
        c['source']['origin_ref']='other-source'
        for e in altered['evidence']:
            if e['collection_id']==c['collection_id']: e['source']['origin_ref']='other-source'
        evidence.validate_document(altered)
        reject('INVALID_PRODUCER_BINDING',w.record_host,altered,attempted=True,terminal=terminal['hosts'][0],details=ds[hid])
        w.record_host(doc,attempted=True,terminal=terminal['hosts'][0],details=ds[hid])
        assert finalize(w,doc,terminal,rc).document==doc


@pytest.mark.parametrize('defect',['changed-rules','missing-rules','symlink','mode','frozen-journal'])
def test_frozen_material_rechecked_before_intent_and_recovery(root,defect):
    args,doc,terminal,rc,ds=fixture();hid=doc['run']['expected_host_ids'][0]
    with store.RunStore(root) as s:
        with s.begin(**args) as w:
            f=root/RID/v2.FROZEN_FILE
            if defect=='changed-rules': f.write_bytes(RULES_RAW+b'\n')
            elif defect=='missing-rules': f.unlink()
            elif defect=='symlink':
                other=root/'foreign';other.write_bytes(RULES_RAW);other.chmod(0o600);f.unlink();f.symlink_to(other)
            elif defect=='mode': f.chmod(0o644)
            elif defect=='frozen-journal':
                j=root/RID/'journal.json';body=store._unseal(j.read_bytes(),store.MAX_MANIFEST)
                body['scope']['producer_rules_sha256']='0'*64;j.write_bytes(store._seal(body,store.MAX_MANIFEST))
            reject(None,w.dispatch_intent,hid)
        reject(None,s.recover,RID)
        assert not (root/RID/'run_manifest.json').exists()


def test_assessment_exact_rules_pair_and_no_cff(root):
    args,doc,terminal,rc,ds=fixture();hid=doc['run']['expected_host_ids'][0]
    args['requirements']={'assessment':True,'cff':False,'details':[dict(host_id=hid,slot=k) for k in sorted(v2.SLOTS)]}
    assessed=assessment.evaluate_document(doc,RULES)
    with store.RunStore(root) as s:
        with s.begin(**args) as w:
            record(w,doc,terminal,ds)
            reject('PRODUCER_RULES_MISMATCH',finalize,w,doc,terminal,rc,assessed=assessed,rules_raw=RULES_RAW+b'\n')
            reject('UNVERIFIED_PRODUCER_FORMAT',finalize,w,doc,terminal,rc,assessed=assessed,rules_raw=RULES_RAW,cff={})
            reject('INVALID_TERMINAL_MANIFEST',finalize,w,doc,terminal,6)
            pub=finalize(w,doc,terminal,rc,assessed=assessed,rules_raw=RULES_RAW)
        assert pub.assessed==json.loads(evidence.canonical_bytes(assessed))
        assert pub.artifacts['assessment_rules.json']==pub.artifacts[v2.RULES_FILE]==RULES_RAW
        assert s.open(RID)==pub


def reindex(path,manifest,relative,raw):
    (path/relative).write_bytes(raw)
    for a in manifest['artifacts']:
        if a['path']==relative: a.update(size=len(raw),sha256=hashlib.sha256(raw).hexdigest());break
    else: raise AssertionError(relative)


@pytest.mark.parametrize('defect',['old-marker','old-slot','missing-rule-entry','changed-rule-bytes',
    'changed-companion-reindexed','changed-handoff-reindexed','hidden-detail','hidden-core','wrong-ref',
    'wrong-version','checkpoint-missing','checkpoint-changed','frozen-changed','unsafe-mode','hardlink','symlink'])
def test_reader_rejects_coherent_reindex_and_unsafe_artifacts(root,defect):
    args,doc,terminal,rc,ds=fixture();hid=doc['run']['expected_host_ids'][0]
    with store.RunStore(root) as s:
        with s.begin(**args) as w:
            record(w,doc,terminal,ds);pub=finalize(w,doc,terminal,rc)
        path=root/RID;manifest=deepcopy(pub.manifest);marker=path/'run_manifest.json'
        cp=f'details/{hid}/{v2.CERTIFICATE}.json';hp=f'details/{hid}/{v2.HANDOFF}.json'
        if defect=='old-marker':
            manifest['batch_contract']=store.NATIVE_BATCH_CONTRACT
            for k in v2.SCOPE_FIELDS.split(): del manifest[k]
        elif defect=='old-slot':
            next(a for a in manifest['artifacts'] if a['path']==cp)['slot']='certificate-inventory'
        elif defect=='missing-rule-entry': manifest['artifacts']=[a for a in manifest['artifacts'] if a['kind']!=v2.RULES_KIND]
        elif defect=='changed-rule-bytes': reindex(path,manifest,v2.RULES_FILE,RULES_RAW+b'\n')
        elif defect=='changed-companion-reindexed':
            value=json.loads(pub.artifacts[cp]);value['occurrences'][0]['detail_sha256']='0'*64
            reindex(path,manifest,cp,ca.canonical(value))
        elif defect=='changed-handoff-reindexed':
            value=json.loads(pub.artifacts[hp]);value['records'][1]['observed_at']=END
            reindex(path,manifest,hp,bridge.wire_bytes(value))
        elif defect=='hidden-detail':
            f=path/f'details/{hid}/unknown.json';f.write_bytes(b'{}');f.chmod(0o600)
        elif defect=='hidden-core':
            f=path/'cff_projection.json';f.write_bytes(b'{}');f.chmod(0o600)
        elif defect=='wrong-ref': next(a for a in manifest['artifacts'] if a['path']==cp)['evidence_ids'].pop()
        elif defect=='wrong-version': next(a for a in manifest['artifacts'] if a['path']==cp)['format_version']='1.1.0'
        elif defect=='checkpoint-missing': (path/'checkpoints'/f'{hid}.json').unlink()
        elif defect=='checkpoint-changed':
            f=path/'checkpoints'/f'{hid}.json';body=store._unseal(f.read_bytes(),store.MAX_CHECKPOINT)
            body['details'].pop();f.write_bytes(store._seal(body,store.MAX_CHECKPOINT))
        elif defect=='frozen-changed': (path/v2.FROZEN_FILE).write_bytes(RULES_RAW+b'\n')
        elif defect=='unsafe-mode': (path/cp).chmod(0o644)
        elif defect=='hardlink':
            # Root-only foreign uid changes are intentionally not required.
            # Use a real extra hard link to violate the same safe-file predicate.
            os.link(path/cp,path/'foreign-link')
        elif defect=='symlink':
            other=path/'foreign';(path/cp).rename(other);(path/cp).symlink_to(other)
        marker.write_bytes(store._json_bytes(manifest));before=marker.read_bytes()
        reject(None,s.open,RID)
        assert marker.read_bytes()==before


def test_actual_multiblock_certificate_projection_and_original_bound(root):
    # Size proof, not fabricated producer data: project() embeds snapshot at
    # most MAX_PROJECTION, MAX_BLOCKS occurrences with at most three e-IDs,
    # and three root records. Even overcounting every root as full is safe.
    # Fixed C1 source and ID alphabets need no additional JSON escaping.
    common=dict(run_id='x'*64,host_id='h-'+'0'*64,observed_at='x'*40,
        source=dict(source_kind='SYNTHETIC',producer_id=ca.COLLECTOR,producer_version=ca.VERSION,
                    origin_ref='i1a-synthetic',input_sha256='0'*64))
    root_name=max(ca.ROOTS,key=len)
    size_record=dict(**common,root=root_name,collection_id='c-'+'0'*64,evidence_ids=['e-'+'0'*64]*3)
    occurrence=dict(**size_record,asset_id='a-'+'0'*64,source_id='src-'+'0'*64,
        target_id='src-'+'0'*64,block_index=ca.MAX_BLOCKS,fingerprint='0'*64,
        detail_ref='cert-'+'0'*64,detail_sha256='0'*64)
    root_record=dict(size_record,detail_sha256='0'*64,evidence_ids=['e-'+'0'*64]*(3*ca.MAX_BLOCKS+1))
    upper=len(ca.canonical(dict(**common,detail_format=ca.FORMAT,detail_version=ca.VERSION,snapshot={},
        occurrences=[occurrence]*ca.MAX_BLOCKS,roots=[root_record]*len(ca.ROOTS))))-2+ca.MAX_PROJECTION
    assert ca.MAX_PROJECTION==256*1024 and ca.MAX_BLOCKS==256 and len(ca.ROOTS)==3
    assert upper<store.MAX_DETAIL
    print('conservative_original_companion_bound='+str(upper))
    args,doc,terminal,rc,ds=fixture(large=True);hid=doc['run']['expected_host_ids'][0]
    comp=next(d['value'] for d in ds[hid] if d['slot']==v2.CERTIFICATE)
    assert len(comp['occurrences'])==16
    assert len(ca.canonical(comp))<=ca.MAX_DETAILS==v2.SLOTS[v2.CERTIFICATE]
    assert store.MAX_DETAIL==1024*1024 and store.MAX_CHECKPOINT==40*1024*1024
    with store.RunStore(root) as s:
        with s.begin(**args) as w:
            record(w,doc,terminal,ds);pub=finalize(w,doc,terminal,rc)
        assert s.open(RID)==pub
        path=f'details/{hid}/{v2.CERTIFICATE}.json'
        assert pub.artifacts[path]==ca.canonical(comp)
        print('actual_large_companion_bytes='+str(len(pub.artifacts[path])))


@pytest.mark.parametrize('defect',['frozen','checkpoint','prepared-hidden','prepared-companion'])
def test_recover_rechecks_private_material(root,monkeypatch,defect):
    args,doc,terminal,rc,ds=fixture();hid=doc['run']['expected_host_ids'][0]
    with store.RunStore(root) as s:
        with s.begin(**args) as w:
            record(w,doc,terminal,ds)
            if defect.startswith('prepared-'):
                original=store._rename_noreplace
                def stop(*a,**kw): raise store.StoreError('DURABILITY_UNCONFIRMED')
                with monkeypatch.context() as mp:
                    mp.setattr(store,'_rename_noreplace',stop)
                    # Stop only after the prepare marker, not a preliminary _write.
                    def stop_move(src_fd,src,dest_fd,dest):
                        if src.startswith('.tmp-'): return original(src_fd,src,dest_fd,dest)
                        return stop()
                    mp.setattr(store,'_rename_noreplace',stop_move)
                    reject('DURABILITY_UNCONFIRMED',finalize,w,doc,terminal,rc)
        path=root/RID
        if defect=='frozen': (path/v2.FROZEN_FILE).write_bytes(RULES_RAW+b'\n')
        elif defect=='checkpoint':
            cp=path/'checkpoints'/f'{hid}.json';body=store._unseal(cp.read_bytes(),store.MAX_CHECKPOINT)
            body['details'][0]['value']['records'][1]['observed_at']=END
            cp.write_bytes(store._seal(body,store.MAX_CHECKPOINT))
        else:
            pending=path/'prepared.json';body=store._unseal(pending.read_bytes(),store.MAX_MANIFEST)
            stage=path/body['stage']
            if defect=='prepared-hidden':
                f=stage/'unknown.json';f.write_bytes(b'{}');f.chmod(0o600)
            else:
                cp=f'details/{hid}/{v2.CERTIFICATE}.json';value=json.loads((stage/cp).read_bytes())
                value['occurrences'][0]['detail_sha256']='0'*64
                reindex(stage,body['manifest'],cp,ca.canonical(value))
                pending.write_bytes(store._seal(body,store.MAX_MANIFEST))
        reject(None,s.recover,RID)
        assert not (path/'run_manifest.json').exists()


@pytest.mark.parametrize('contract',[None,store.S1_BATCH_CONTRACT,store.NATIVE_BATCH_CONTRACT])
def test_old_contract_rejects_new_frozen_and_published_slots(root,contract):
    args,doc,terminal,rc,ds=fixture(('disabled',));args.pop('producer_rules_raw')
    args['batch_contract']=contract
    if contract!=store.NATIVE_BATCH_CONTRACT:
        args['requested_flags']={TARGETS[0]:dict.fromkeys(store.COLLECTORS,False)}
    with store.RunStore(root) as s:
        with s.begin(**args): pass
        pub=s.recover(RID);assert s.open(RID)==pub
        path=root/RID
        f=path/v2.FROZEN_FILE;f.write_bytes(RULES_RAW);f.chmod(0o600)
        reject('BATCH_CONTRACT',s.open,RID);f.unlink()
        f=path/v2.RULES_FILE;f.write_bytes(RULES_RAW);f.chmod(0o600)
        reject('BATCH_CONTRACT',s.open,RID);f.unlink()
        assert s.open(RID)==pub


def test_recovery_retains_exact_caller_rule_bytes(root):
    args,doc,terminal,rc,ds=fixture();args['producer_rules_raw']=RULES_RAW+b'\n'
    with store.RunStore(root) as s:
        with s.begin(**args) as w: record(w,doc,terminal,ds)
        pub=s.recover(RID)
        assert pub.artifacts[v2.RULES_FILE]==args['producer_rules_raw']!=RULES_RAW
        assert pub.manifest['producer_rules_sha256']==hashlib.sha256(args['producer_rules_raw']).hexdigest()
        assert s.open(RID)==pub


def test_actual_foreign_owner_v2_artifact(root):
    # Optional anonymous fixture provisioned by an already privileged test
    # harness. The actual Store and pytest process remain non-root, no chown.
    foreign=ROOT.parent/'foreign-owner.fixture'
    if not foreign.is_file():
        pytest.skip('non-root runner has no provisioned foreign-owner fixture')
    st=foreign.stat()
    assert st.st_uid!=os.geteuid() and st.st_mode & 0o777==0o600 and st.st_nlink==1
    if st.st_dev!=root.stat().st_dev:
        pytest.skip('foreign-owner fixture and private Store differ in filesystem')
    args,doc,terminal,rc,ds=fixture();hid=doc['run']['expected_host_ids'][0]
    with store.RunStore(root) as s:
        with s.begin(**args) as w:
            record(w,doc,terminal,ds);pub=finalize(w,doc,terminal,rc)
        path=root/RID/f'details/{hid}/{v2.CERTIFICATE}.json'
        path.unlink();foreign.rename(path)
        try:
            assert path.stat().st_uid==st.st_uid
            reject('UNSAFE_FILE',s.open,RID)
        finally:
            path.rename(foreign)


# C2: actual verified C1 publications, not manufactured PublishedRun positives.
def _c2_open(root, modes, *, assessed=False, recovery=False):
    args, doc, terminal, rc, ds = fixture(modes)
    if assessed:
        args['requirements'] = {'assessment': True, 'cff': False, 'details': [
            dict(host_id=hid, slot=slot) for hid in doc['run']['expected_host_ids']
            if args['requested_flags'][row_for(doc, terminal, hid)['target_id']][bridge.CERT_FLAG]
            for slot in sorted(v2.SLOTS)]}
    with store.RunStore(root) as s:
        with s.begin(**args) as w:
            if recovery:
                ids = doc['run']['expected_host_ids']
                record(w, doc, terminal, ds, ids=ids[:1]); w.dispatch_intent(ids[1])
            else:
                record(w, doc, terminal, ds)
                finalize(w, doc, terminal, rc, **(dict(assessed=assessment.evaluate_document(doc, RULES),
                    rules_raw=RULES_RAW) if assessed else {}))
        if recovery:
            s.recover(RID)
        return s.open(RID)


def _c2_tree(root):
    return {str(p.relative_to(root)): (p.stat().st_ino, p.stat().st_mode, p.stat().st_mtime_ns,
            p.read_bytes() if p.is_file() else None) for p in root.rglob('*')}


def _c2_html(raw):
    from html.parser import HTMLParser
    from urllib.parse import urlsplit

    class Page(HTMLParser):
        def __init__(self):
            super().__init__(); self.ids = set(); self.links = []
        def handle_starttag(self, tag, attrs):
            attrs = dict(attrs)
            assert tag not in {'script', 'iframe', 'object', 'embed', 'base', 'form'}
            assert not any(k.startswith('on') or k in ('src', 'srcset', 'action', 'style') for k in attrs)
            if 'id' in attrs:
                assert attrs['id'] not in self.ids
                self.ids.add(attrs['id'])
            if 'href' in attrs:
                href = attrs['href']; u = urlsplit(href)
                assert not u.scheme and not u.netloc and not u.query and not u.path.startswith('/')
                assert '\\' not in href and '%' not in href
                self.links.append(href)
    p = Page(); p.feed(raw.decode('utf-8'))
    assert all(h[1:] in p.ids for h in p.links if h.startswith('#'))
    return p


@pytest.mark.parametrize('assessed', [False, True])
def test_c2_actual_multihost_exact_joins_and_html(root, assessed, monkeypatch):
    from tools import portal_asset_indexes as ai, portal_indexes as crypto
    pub = _c2_open(root, ('complete', 'complete'), assessed=assessed)
    before = _c2_tree(root); original = deepcopy(pub)
    # The Store has already verified the retained handoff and rules. C2 must
    # not replay them or create a second algorithm classification/assessment.
    def forbidden(*a, **kw):
        raise AssertionError('C2 replayed the producer or assessment')
    monkeypatch.setattr(ca, 'validate_cert_details', forbidden)
    monkeypatch.setattr(assessment, 'evaluate_document', forbidden)
    p, pages = ai.render_asset_indexes(pub)
    assert (p, pages) == ai.render_asset_indexes(pub)
    assert pub == original and _c2_tree(root) == before
    assert set(pages) == {'certificates.html', 'services.html'}
    html = _c2_html(pages['certificates.html']); _c2_html(pages['services.html'])
    assert p['assessed'] is assessed
    ix = p['certificates']; groups = ix['groups']
    assert len(groups) == 2 and len(ix['asset_ids']) == 4
    assert len(ix['recorded_occurrence_ids']) == len(ix['verified_occurrence_ids']) == 8
    assert ix['recorded_occurrence_ids'] == ix['verified_occurrence_ids']
    assert ix['counts']['verified_occurrence_ids'] == 8
    oracle = {}
    for h in pub.manifest['hosts']:
        hid = h['host_id']; d = json.loads(pub.artifacts[f'details/{hid}/{v2.CERTIFICATE}.json'])
        for item in d['occurrences']:
            src = next(s for s in d['snapshot'][item['root']]['sources'] if s['source_id'] == item['source_id'])
            block = src['blocks'][item['block_index'] - 1]; cert = block['certificate']
            raw = json.dumps(dict(record={k: v for k, v in item.items() if k not in ('detail_ref', 'detail_sha256')},
                block=block, format=src['format']), sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode('ascii')
            assert hashlib.sha256(raw).hexdigest() == item['detail_sha256']
            key = (hid, item['root'], item['source_id'], item['block_index'])
            assert key not in oracle; oracle[key] = (item, cert, src)
    assert len(oracle) == 8
    for oid, r in p['occurrences'].items():
        item, cert, src = oracle.pop((r['host_id'], r['root'], r['source_id'], r['block_index']))
        assert {k: r[k] for k in item if k != 'run_id'} == {k: v for k, v in item.items() if k != 'run_id'}
        expected_id = 'occ-' + hashlib.sha256(json.dumps([r['host_id'], r['collection_id'], r['asset_id'],
            r['source_id'], r['block_index'], r['detail_sha256']], separators=(',', ':')).encode()).hexdigest()
        assert oid == expected_id and oid in html.ids
        assert r['detail_state'] == 'VERIFIED_COMPANION' and r['target_id'] == src['target_id']
        assert r['path'] is r['vhost'] is None
        assert r['certificate_metadata'] == {k: v for k, v in cert.items() if k not in ('fingerprint', 'gaps')}
        assert r['metadata_gaps'] == cert['gaps']
        assert set(r['role_evidence_ids']) == {'certificate', 'public-key', 'signature'}
        assert sorted(r['role_evidence_ids'].values()) == r['evidence_ids']
        for eid in r['evidence_ids']:
            assert p['evidence'][eid]['href'] in html.links
        assert r['target_id'].encode() in pages['certificates.html']
    assert not oracle
    ci, cpages = crypto.render_crypto_indexes(pub)
    alg_ids = _c2_html(cpages['algorithms.html']).ids
    by_algorithm = {g['id']: set(g['evidence_ids']) for g in ci['algorithms']['groups']}
    for g in groups:
        assert g['id'] in html.ids and g['service_group_ids'] == []
        assert g['verified_occurrence_count'] == len(g['recorded_occurrence_ids'])
        assert g['detail_state'] == 'VERIFIED_COMPANION' and g['validity_state'] == 'RECORDED'
        assert g['public_key_bits'] == 2048 and g['public_key_bits_evidence_ids'] == []
        assert g['issuer'] == 'CN=Fixture issuer' and g['subject'] == 'CN=Fixture certificate'
        assert g['validity_occurrence_ids'] == g['verified_occurrence_ids']
        assert {k: len(g[k]) for k in ('host_ids', 'asset_ids', 'evidence_ids', 'claim_ids')} == {
            k: g['counts'][k] for k in ('host_ids', 'asset_ids', 'evidence_ids', 'claim_ids')}
        expected = {k: ids & set(g['evidence_ids']) for k, ids in by_algorithm.items() if ids & set(g['evidence_ids'])}
        assert {link['group_id']: set(link['evidence_ids']) for link in g['algorithm_links']} == expected
        assert all(link['href'] in html.links and link['group_id'] in alg_ids for link in g['algorithm_links'])
        assert all(p[t][ref]['href'] in html.links for k, t in [('host_ids', 'hosts'), ('asset_ids', 'assets'),
                    ('evidence_ids', 'evidence'), ('claim_ids', 'claims')] for ref in g[k])
        if not assessed:
            assert not g['claim_ids']
    assert _c2_tree(root) == before


@pytest.mark.parametrize('mode', ['partial', 'disabled', 'connection', 'error', 'stopped', 'worker'])
def test_c2_actual_coverage_and_missing(root, mode):
    from tools import portal_asset_indexes as ai
    pub = _c2_open(root, ('complete', mode)); before = _c2_tree(root)
    p, pages = ai.render_asset_indexes(pub)
    assert _c2_tree(root) == before
    host = next(h for h in pub.manifest['hosts'] if h['target_id'] == TARGETS[1])
    row = next(r for r in p['coverage'] if r['host_id'] == host['host_id'] and r['slot'] == 'system_certs')
    if mode == 'partial':
        assert row['detail_slot_state'] == 'VERIFIED_COMPANION'
        g = next(g for g in p['certificates']['groups'] if g['fingerprint'] == digest('public-fixture-1'))
        assert g['metadata_fields']['not_after']['state'] == 'PARTIAL'
        assert len(g['validity_occurrence_ids']) == 1 and g['validity_state'] == 'PARTIAL'
        assert 'NOT_AFTER_UNKNOWN' in g['metadata_gaps']
        assert p['certificates']['counts']['verified_occurrence_ids'] == 8
    else:
        assert row['detail_slot_state'] == ('NOT_REQUIRED' if mode == 'disabled' else 'REQUIRED_DETAIL_MISSING')
        assert p['certificates']['counts']['verified_occurrence_ids'] == 4
        assert not any(r['host_id'] == host['host_id'] for r in p['occurrences'].values())
    assert row['detail_slot_state'].encode() in pages['certificates.html']


def test_c2_actual_recovery(root):
    from tools import portal_asset_indexes as ai
    pub = _c2_open(root, ('complete', 'complete', 'complete'), recovery=True)
    p, pages = ai.render_asset_indexes(pub)
    rows = [r for r in p['coverage'] if r['slot'] == 'system_certs']
    assert sorted(r['detail_slot_state'] for r in rows) == ['REQUIRED_DETAIL_MISSING'] * 2 + ['VERIFIED_COMPANION']
    assert p['certificates']['counts']['verified_occurrence_ids'] == 4
    assert b'REQUIRED_DETAIL_MISSING' in pages['certificates.html']


@pytest.mark.parametrize('variant', ['conflict', 'disjoint-dates'])
def test_c2_actual_conflicts_and_escape(root, monkeypatch, variant):
    from tools import portal_asset_indexes as ai
    original = envelope
    def varied(target, mode='complete', *, large=False):
        env = original(target, mode, large=large)
        for value in env['records'][1]['snapshot']['roots'].values():
            for src in value['sources']:
                for block in src['blocks']:
                    cert = block['certificate']
                    if variant == 'conflict':
                        if target == TARGETS[1]:
                            cert.update(issuer='CN=<img src=x onerror=alert(1)> & issuer',
                                subject='CN=Other fixture', public_key_bits=4096,
                                signature_outer='sha384WithRSAEncryption',
                                not_before='2028-01-01T00:00:00Z')
                    elif target == TARGETS[0]:
                        cert['not_after'] = None
                    else:
                        cert['not_before'] = None
                    cert['gaps'] = ca.metadata_gaps(cert)
                    block['reason'] = 'METADATA_GAP' if cert['gaps'] else 'OK'
        return env
    monkeypatch.setattr(sys.modules[__name__], 'envelope', varied)
    pub = _c2_open(root, ('complete', 'complete'))
    p, pages = ai.render_asset_indexes(pub); _c2_html(pages['certificates.html'])
    assert len(p['certificates']['verified_occurrence_ids']) == 8
    for g in p['certificates']['groups']:
        fields = g['metadata_fields']
        assert g['validity_occurrence_ids'] == []
        if variant == 'conflict':
            assert g['validity_state'] == g['signature_metadata_state'] == 'CONFLICT'
            assert {'VALIDITY_CONFLICT', 'SIGNATURE_CONFLICT'} <= set(g['metadata_gaps'])
            assert all(fields[k]['state'] == 'CONFLICT' and fields[k]['value'] is None
                       for k in ('issuer', 'subject', 'public_key_bits', 'not_before', 'signature_outer'))
            assert all('signature' not in r['role_evidence_ids'] for r in p['occurrences'].values()
                       if 'SIGNATURE_CONFLICT' in r['metadata_gaps'])
        else:
            assert g['validity_state'] == 'PARTIAL'
            assert fields['not_before']['state'] == fields['not_after']['state'] == 'PARTIAL'
            assert g['not_before'] is None and g['not_after'] is None
            assert fields['not_before']['value'] and fields['not_after']['value']
            assert not (set(fields['not_before']['occurrence_ids']) & set(fields['not_after']['occurrence_ids']))
    if variant == 'conflict':
        html = pages['certificates.html']
        assert b'&lt;img src=x onerror=alert(1)&gt; &amp; issuer' in html and b'<img' not in html


@pytest.mark.parametrize('defect', ['marker', 'slot', 'bytes', 'foreign-host', 'omit', 'repeat',
                                    'ref', 'role', 'hash', 'root', 'terminal', 'wrong-version'])
def test_c2_reject_changed_verified_input(root, defect):
    from tools import portal_asset_indexes as ai
    pub = deepcopy(_c2_open(root, ('complete', 'complete')))
    hid = pub.manifest['expected_host_ids'][0]
    path = f'details/{hid}/{v2.CERTIFICATE}.json'
    entry = next(a for a in pub.manifest['artifacts'] if a['path'] == path)
    if defect == 'marker':
        pub.manifest['batch_contract'] = store.NATIVE_BATCH_CONTRACT
    elif defect == 'slot':
        entry['slot'] = 'certificate-inventory'
    elif defect == 'bytes':
        pub.artifacts[path] += b' '
    elif defect == 'ref':
        entry['evidence_ids'].pop()
    elif defect == 'terminal':
        h = next(h for h in pub.manifest['hosts'] if h['host_id'] == hid)
        next(c for c in h['terminal']['collectors'] if c['collector_id'] == bridge.CERT_FLAG)['collection_ids'].pop()
    elif defect == 'wrong-version':
        entry['format_version'] = '1.1.0'
    else:
        value = json.loads(pub.artifacts[path]); item = value['occurrences'][0]
        if defect == 'foreign-host': item['host_id'] = pub.manifest['expected_host_ids'][1]
        elif defect == 'omit': value['occurrences'].pop()
        elif defect == 'repeat': value['occurrences'].append(deepcopy(item))
        elif defect == 'role': item['evidence_ids'].pop()
        elif defect == 'hash': item['detail_sha256'] = '0' * 64
        elif defect == 'root': value['roots'][0]['detail_sha256'] = '0' * 64
        raw = ca.canonical(value); pub.artifacts[path] = raw
        entry.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    reject('INVALID_ASSET_INDEX_COMPANION', ai.render_asset_indexes, pub)


@pytest.mark.parametrize('cap', ['_MAX_JSON', '_MAX_HTML', '_MAX_MEMBERSHIPS'])
def test_c2_bounds_fail_closed(root, monkeypatch, cap):
    from tools import portal_asset_indexes as ai
    pub = _c2_open(root, ('complete',)); before = _c2_tree(root)
    monkeypatch.setattr(ai, cap, 1)
    reject('ASSET_INDEX_SIZE_LIMIT', ai.render_asset_indexes, pub)
    assert _c2_tree(root) == before
