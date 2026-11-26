"""R2-P: fixed anonymous native-shaped fixtures, no actual worker/transport.
Reuses the R1 capacity probe (#57 comment 7201003647) and actual validators.
Capacity-only JSON stress values are not claimed as legal Evidence/CFF.
"""
import copy
import hashlib
import json
import multiprocessing
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from tools import scan_collectors as bridge, batch_execution as batch, evidence, assessment, cff, platform, openssl_runtime as ssl, crypto_policy as policy, ssh_posture as ssh, cert_assets as cert
from ansible_collections.security.compliance_pqc_readiness.plugins.modules import pqc_openssl_acquire as ossl, pqc_ssh_acquire as sshacq, pqc_cert_acquire as certacq

TIME='2026-01-01T00:00:00Z'; FIN='2026-01-01T00:00:05Z'; RUN='c3a-capacity-fixture'
ALL={f:f not in (bridge.NGINX,bridge.TLS) for f in bridge.FLAGS}
MIB=1024*1024
RULE_BYTES=(ROOT/'config/assessment_rules.yml').read_bytes()
rules=assessment.load_rules(RULE_BYTES)
SLOTS={bridge.PLATFORM:MIB,bridge.OPENSSL:MIB,bridge.POLICY:MIB,bridge.SSH:2*MIB,bridge.CERT:2*MIB}

# Same anonymous fixture constructors as the original tests.
def _platform_snapshot(distribution='OracleLinux'):
    return dict(facts_state='OK', facts=dict(distribution=distribution, os_family='RedHat',
        distribution_version='9.9', distribution_major_version='9', architecture='x86_64'),
        tools={k: [dict(state='OK', exists=True, isreg=True, islnk=False, executable=True) for _ in range(n)]
               for k, n in platform.TOOL_SLOTS.items()},
        rpms={k: dict(state='COLLECTED', reason='OK', rows=[[k, '9.9', '1', 'x86_64']]) for k in platform.PACKAGES}
        if distribution == 'OracleLinux' else {})


def _policy_snapshot():
    rows = {s: policy.result('UNKNOWN', 'SOURCE_ABSENT') for s in policy.SCOPES}
    rows['profile-config'] = policy.result('COLLECTED', 'OK', [['profile', 'DEFAULT']])
    rows['profile-show'] = policy.result('COLLECTED', 'OK', [['profile', 'DEFAULT']], rc=0)
    rows['kernel-fips'] = policy.result('COLLECTED', 'OK', [['fips-enabled', False]])
    rows['local-overrides'] = policy.result('COLLECTED', 'OK', [['entry-count', 0]])
    return rows


def _ssh_typed(flags, *, config=None, keys=None, status='UNVERIFIED'):
    if status!='UNVERIFIED':
        return bridge._gap_snapshot(bridge.SSH,flags,status)
    acquired={'config': config if config is not None else bridge._ssh_slot('UNKNOWN','SOURCE_MISSING'),
              'keys': keys if keys is not None else bridge._ssh_slot('COLLECTED','OK')}
    slots={}; halted=False
    for stage in (*ssh.BASE_SLOTS,'native-0'):
        gap=bridge._ssh_fixed_gap(flags,stage,halted)
        slots[stage]=gap if gap is not None else acquired[stage]
        if gap is None:
            halted=acquired[stage]['reason'] in ('TIMEOUT','EXECUTION_ERROR')
    return dict(flags={f:flags[f] for f in (bridge.SSHD,bridge.KEYS)},platform_status=status,
                context_refs=['global-default'],slots=slots)


def _cert_payload(size):
    roots = {k: certacq.empty() for k in certacq.ROOTS}
    for k in roots:
        roots[k]['root_target_id'] = certacq.source_id(certacq.ROOTS[k])
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
        sid = certacq.source_id(certacq.ROOTS['system-tls-certs'] + '/fixture-%03d.pem' % i)
        row['sources'].append(dict(source_id=sid, target_id=sid, format='PEM', gaps=[], blocks=blocks))
    row['sources'].sort(key=lambda x: x['source_id'])
    payload = dict(system_python_available=True, roots=roots)
    remaining = size - len(certacq.canonical(payload))
    assert remaining >= 0
    for c in certs:
        for k in ('subject', 'issuer'):
            n = min(remaining, 512 - len(c[k]))
            c[k] += 'a' * n
            remaining -= n
    assert remaining == 0 and len(certacq.canonical(payload)) == size
    return payload


def _ssh_slot(size):
    src = sshacq.digest('src', ['ssh-config-v1', ['etc', 'ssh'], 'sshd_config'])
    main = dict(kind='SOURCE', order=0, source_ref=src, line=0, context_ref='global-default',
                source_kind='MAIN', parent_ref=None, include_line=None, depth=0)
    rows = [main] + [dict(kind='DIRECTIVE', order=i, source_ref=src, line=i, context_ref='global-default',
                          setting='ciphers', operator='EXACT', values=['a']) for i in range(1, 10)]
    slot = sshacq.result('COLLECTED', 'OK', rows=rows)
    remaining = size - len(sshacq.canonical(slot))
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
    assert remaining == 0 and len(sshacq.canonical(slot)) == size
    return slot


def _snapshots(expanded=False):
    plat=_platform_snapshot(); pol=_policy_snapshot(); cert_payload=_cert_payload(196608)
    # Actual O2 parser and stage receipt validation over fixed anonymous raw literals.
    provider_names=[f'p{i:03d}' for i in range(256)]
    outputs={
     'rpm-openssl': b'openssl\t3.5.5\t1\tx86_64\n',
     'rpm-openssl-libs': b'openssl-libs\t3.5.5\t1\tx86_64\n',
     'version': b'OpenSSL 3.5.5 (Library: OpenSSL 3.5.5)\n',
     'providers': ('Providers:\n'+''.join(f'  {p}\n    version: 3.5.5\n    status: active\n' for p in provider_names)).encode('ascii'),
     'kem': ('KEM Algorithms:\n'+''.join(f'KEMfixture{i:03d} @ {p}\n' for i,p in enumerate(provider_names))).encode('ascii'),
     'signature': ('Signature Algorithms:\n'+''.join(f'SIGfixture{i:03d} @ {p}\n' for i,p in enumerate(provider_names))).encode('ascii'),
     'tls-groups': (':'.join(f'TLSfixture{i:03d}' for i in range(256))+'\n').encode('ascii'),
    }
    ssl_slots={}
    for stage, raw in outputs.items():
        s=ossl._parse(stage,0,raw,b''); assert s['state']=='COLLECTED', (stage,s['state'],s['reason']); assert len(raw)<=ossl.OUTPUT_BYTES
        receipt=ossl._receipt(stage,'COMMAND_OK',0,True,s); ossl.validate_receipt(receipt,stage)
        ssl_slots[stage]=s
    ssl_snapshot={'flags':{f:ALL[f] for f in ssl.FLAGS},'platform_status':'UNVERIFIED','slots':ssl_slots}
    # 512 typed config rows (including main SOURCE) within both raw-file and typed limits.
    src=sshacq.digest('src',['ssh-config-v1',['etc','ssh'],'sshd_config'])
    config_rows=[dict(kind='SOURCE',order=0,source_ref=src,line=0,context_ref='global-default',source_kind='MAIN',parent_ref=None,include_line=None,depth=0)]
    config_rows.extend(dict(kind='DIRECTIVE',order=i,source_ref=src,line=i,context_ref='global-default',setting='ciphers',operator='EXACT',values=['aes128-ctr']) for i in range(1,512))
    config=_ssh_slot(262144) if expanded else sshacq.result('COLLECTED','OK',rows=config_rows)
    assert len(b'Ciphers aes128-ctr\n'*511)<=sshacq.LIMIT
    keys=sshacq.result('COLLECTED','OK',rows=[dict(source_ref='key-'+f'{i:064x}',key_type='ssh-ed25519',bits=256,fingerprint_sha256=f'{i:064x}',grammar='KNOWN') for i in range(32)])
    ssh_snapshot=_ssh_typed(ALL,config=config,keys=keys)
    for stage,s in [('config',config),('keys',keys)]:
        sshacq.validate_receipt(sshacq._receipt(stage,'COMMAND_OK',0,True,s),stage)
    certacq.validate_receipt(dict(format=1,stage='system',reason_code='COMMAND_OK',rc=0,cleanup_confirmed=True,payload=cert_payload),'system')
    snap={bridge.PLATFORM:plat,bridge.OPENSSL:ssl_snapshot,bridge.POLICY:pol,bridge.SSH:ssh_snapshot,bridge.CERT:cert_payload}
    return snap


def _replay(args):
    i,snap=args
    n=f'fixture-{i:02d}.example.invalid'
    env=dict(handoff_version=1,run_id=RUN,target_id=n,connection='CONNECTED',records=[dict(producer_id=p,observed_at=TIME,reason_code='COMMAND_OK',rc=0,cleanup_confirmed=True,snapshot=snap[p]) for p in bridge.requested(ALL)])
    wire=bridge.wire_bytes(env); payload,structure=bridge._cert_handoff_budget(env)
    p=bridge.normalize_handoff(bridge.read_wire(wire),RUN,n,ALL,TIME,rules,staged_openssl=True,staged_policy=True,staged_ssh=True,staged_cert=True)
    row=batch._host(n,True,[p.outcomes[f] for f in batch._COLLECTORS],p.special); row['platform']=p.outcomes[bridge.PLATFORM]
    refs=sum(len(r['collection_ids']) for r in [row['platform'],*row['collectors']]); assert refs<=294
    sizes={k:len((cert.canonical if k==bridge.CERT else ssh.canonical if k==bridge.SSH else bridge.wire_bytes)(v)) for k,v in p.companions.items()}
    assert set(sizes)==set(bridge.PRODUCERS)
    assert all(0<size<=SLOTS[k] for k,size in sizes.items())
    print('HOST_REPLAY_OK',i,'wire',len(wire),'payload',payload,'structure',structure,'refs',refs,'evidence',len(p.document['evidence']),'companion_sizes',json.dumps(sizes,sort_keys=True),flush=True)
    return n,p,row,len(wire),refs,sizes


@pytest.fixture(scope='module')
def replayed():
    snap=_snapshots()
    # Ten actual distinct normalizations, four bounded local test processes.
    with ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context('fork')) as pool:
        rows=list(pool.map(_replay, [(i,snap) for i in range(10)]))
    assert len({r[0] for r in rows})==10
    assert all(r[3]==348632 and r[4]==293 and len(r[1].document['evidence'])==2892 for r in rows)
    return rows


def _aggregate(selected):
    rows=[]; projections={}; companions={}; hosts=[]; total_wire=0
    limits=dict(max_hosts=10,forks=2,serial=2,ssh_timeout_s=15,command_timeout_s=30)
    for n,p,row,size,refs,sizes in selected:
        total_wire+=size; rows.append(row); projections[n]=p; companions[n]=p.companions
        hosts.append(bridge.host_record(RUN,n,row['host_state'],row['reason_code']))
    state,reason,rc=batch._run_state(rows)
    manifest=dict(batch_manifest_version=2,target_ids=sorted(projections),target_count=len(rows),limits=limits,profile='extended',run_state=state,reason_code=reason,hosts=rows)
    batch.validate_producer_manifest(manifest,rc)
    doc=bridge.document(RUN,TIME,hosts,state,FIN);doc['run']['coverage_reason']=reason
    for p in projections.values():
        for k in ('collections','assets','evidence'):doc[k].extend(p.document[k])
    print('AGGREGATE_WIRE',total_wire,'cap',10*bridge.MAX_WIRE,'TERMINAL_RC',rc,'state',state,flush=True)
    assert total_wire<=10*bridge.MAX_WIRE
    bridge.validate_bindings(manifest,doc,companions,projections)
    print('BINDINGS_OK',flush=True)
    return doc,manifest,rc


def _json(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode('utf-8')


def _nodes(value):
    if type(value) is dict:
        return 1+sum(_nodes(v) for v in value.values())
    if type(value) is list:
        return 1+sum(_nodes(v) for v in value)
    return 1


def _check_projection(doc,selected,manifest,rc):
    count=len(selected)
    raw=evidence._canonical_v3_raw(doc)
    assert raw==evidence.canonical_bytes(doc)
    assert len(doc['evidence'])==count*2892
    if count==7:
        assert len(raw)==21303720 and sum(x[3] for x in selected)==2440424
    assert rc==5 and manifest['run_state']=='PARTIAL'
    with pytest.raises(cff.ProjectionError,match='PROJECTION_LIMIT'):
        cff.project_cff(doc,rules)
    assessed=assessment._evaluate_v3_raw(doc,rules)
    assessed_raw=evidence._canonical_v3_assessed(assessed)
    print('ASSESSED_METRICS',count,len(assessed_raw),{k:len(assessed[k]) for k in evidence.REGISTRIES},flush=True)
    result=cff._project_v3_assessed(assessed,rules)
    assert result['evidence_document_sha256']==hashlib.sha256(assessed_raw).hexdigest()
    assert [p['host_id'] for p in result['per_host']]==sorted(doc['run']['expected_host_ids'])
    # Exact replay from raw, with the same global assessment and digest.
    wire=cff._canonical_v3_raw_projection(result,doc,rules)
    assert wire==_json(result) and len(wire)<=128*MIB
    import jsonschema
    schema=json.loads((ROOT/'schemas/cff-projection-1.0.0.schema.json').read_bytes())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema,format_checker=jsonschema.FormatChecker()).validate(result)
    metrics=[(p['host_id'],len(_json(p)),_nodes(p)) for p in result['per_host']]
    assert all(size<=32*MIB and nodes<=2000000 for _,size,nodes in metrics)
    wrapper_nodes=_nodes(result)
    assert wrapper_nodes==4+sum(n for _,_,n in metrics)<=8000000
    detail_bytes=sum(item[3]+sum(item[5].values()) for item in selected)
    # All six slots, original terminal and rules. Store wrapper/seals are
    # R2-S, so this is actual payload/core estimate, not Store admission.
    core=len(raw)+len(assessed_raw)+len(wire)+detail_bytes+len(_json(manifest))+len(RULE_BYTES)
    print('V3_METRICS',json.dumps(dict(hosts=count,raw=len(raw),assessed=len(assessed_raw),cff=len(wire),
        rows_raw={k:len(doc[k]) for k in evidence.REGISTRIES},rows_assessed={k:len(assessed[k]) for k in evidence.REGISTRIES},
        raw_nodes=_nodes(doc),assessed_nodes=_nodes(assessed),wrapper_nodes=wrapper_nodes,entries=metrics,
        details=detail_bytes,terminal=len(_json(manifest)),rules=len(RULE_BYTES),core_estimate=core,rc=rc),sort_keys=True),flush=True)
    assert core<=256*MIB


@pytest.mark.parametrize('count',[7,10])
def test_original_and_ten_host_capacity(replayed,count):
    selected=replayed[:count]
    doc,manifest,rc=_aggregate(selected)
    _check_projection(doc,selected,manifest,rc)


def test_distinct_expanded_typed_ssh_envelope():
    # Original S2 exact slot is validator-legal, not a guarantee that every
    # such shape is obtainable from a real file.
    row=_replay((10,_snapshots(expanded=True)))
    assert row[3]>348632
    doc,manifest,rc=_aggregate([row])
    raw=evidence._canonical_v3_raw(doc)
    assessed=assessment._evaluate_v3_raw(doc,rules)
    projected=cff._project_v3_assessed(assessed,rules)
    wire=cff._canonical_v3_raw_projection(projected,doc,rules)
    print('EXPANDED_METRICS',len(raw),len(evidence._canonical_v3_assessed(assessed)),len(wire),len(doc['evidence']),_nodes(projected),row[5],flush=True)


def _small():
    return bridge.document(RUN,TIME,[bridge.host_record(RUN,'small.example.invalid')],'PARTIAL',FIN)


def test_small_exact_legacy_and_closed_selection():
    doc=_small()
    old=evidence.canonical_bytes(doc)
    assert old==evidence._canonical_v3_raw(doc)
    assert evidence._parse_v3_raw(old)==evidence.parse_evidence_bytes(old)
    assessed=assessment.evaluate_document(doc,rules)
    assert assessment._evaluate_v3_raw(doc,rules)==assessed
    assert evidence._canonical_v3_assessed(assessed)==evidence.canonical_bytes(assessed)
    assert evidence._parse_v3_assessed(evidence.canonical_bytes(assessed))==assessed
    assert assessment._evaluate_v3_assessed(assessed,rules)==assessed
    projected=cff.project_cff(doc,rules)
    assert cff._project_v3_raw(doc,rules)==projected
    assert cff._canonical_v3_raw_projection(projected,doc,rules)==cff.canonical_projection_bytes(projected,doc,rules)
    assert cff._validate_v3_assessed_projection(projected,assessed,rules) is None
    with pytest.raises(TypeError):
        evidence.validate_document(doc,capacity_profile='B04_V3_CAPACITY_R2')
    with pytest.raises(ValueError,match='INVALID_CAPACITY_STAGE'):
        evidence._validate_document(doc,'RAW_EVIDENCE')
    with pytest.raises(evidence.EvidenceError):
        evidence._validate_v3_raw({**doc,'capacity_profile':'B04_V3_CAPACITY_R2'})
    legacy={**doc,'schema_version':'1.0.0'}
    evidence.validate_document(legacy)
    with pytest.raises(evidence.EvidenceError,match='INVALID_CAPACITY_PROFILE'):
        evidence._validate_v3_raw(legacy)
    stale=copy.deepcopy(assessed)
    stale['findings'][0]['rule_version']='9.9.9'
    with pytest.raises(assessment.AssessmentError,match='ASSESSMENT_CONFLICT'):
        assessment._evaluate_v3_assessed(stale,rules)
    for mutate in ('foreign','missing','duplicate','digest','pair'):
        bad=copy.deepcopy(projected)
        if mutate=='foreign': bad['per_host'][0]['host_id']='h-'+'0'*64
        elif mutate=='missing': bad['per_host']=[]
        elif mutate=='duplicate': bad['per_host'].append(bad['per_host'][0])
        elif mutate=='digest': bad['evidence_document_sha256']='0'*64
        else: bad['per_host'][0]['companion']['evidence_document_sha256']='0'*64
        with pytest.raises((cff.ProjectionError,evidence.V3CapacityError)):
            cff._validate_v3_raw_projection(bad,doc,rules)


def _byte_value(size):
    # Nested arrays keep each actual array <=20k and string <=512.
    n=(size-8)//515
    while True:
        groups=[['x'*512]*min(20000,n-i) for i in range(0,n,20000)]
        groups.append([''])
        current=len(_json(groups))
        if current>size:
            n-=1
            continue
        delta=size-current
        if delta<=512:
            groups[-1][0]='x'*delta
        else:
            groups[-1]=['x'*(delta-515 if delta>=515 else delta-3),'x'* (512 if delta>=515 else 0)]
        assert len(_json(groups))==size
        return groups


@pytest.mark.parametrize('stage,limit,single',[(evidence._V3Stage.RAW,64*MIB,False),
    (evidence._V3Stage.ASSESSED,96*MIB,False),(evidence._V3Stage.RAW,32*MIB,True)])
def test_evidence_actual_serializer_byte_edges(stage,limit,single):
    assert len(evidence._encode(_byte_value(limit),stage=stage,single_host=single))==limit
    with pytest.raises(evidence.V3CapacityError,match='V3_CAPACITY_LIMIT') as exc:
        evidence._encode(_byte_value(limit+1),stage=stage,single_host=single)
    assert exc.value.stage==stage.value


def test_cff_entry_and_wrapper_bytes_exact_plus_one():
    limit=32*MIB
    assert len(cff._json_metrics(_byte_value(limit),v3_entry=True)[0])==limit
    with pytest.raises(evidence.V3CapacityError):
        cff._json_metrics(_byte_value(limit+1),v3_entry=True)
    budget=cff._V3Wrapper('a'*64,cff.VERSION)
    bad=cff._V3Wrapper('a'*64,cff.VERSION)
    entry=_byte_value(limit)
    for _ in range(3):
        budget.add(entry); bad.add(entry)
    final=128*MIB-budget.size-1
    budget.add(_byte_value(final))
    assert budget.size==128*MIB
    with pytest.raises(evidence.V3CapacityError):
        bad.add(_byte_value(final+1))


def _node_value(n):
    remaining=n-1; groups=[]
    while remaining:
        count=min(20001,remaining); groups.append([None]*(count-1)); remaining-=count
    assert _nodes(groups)==n
    return groups


def test_node_array_and_wrapper_exact_plus_one():
    assert cff._json_metrics([None]*20000,v3_entry=True)[1]==20001
    with pytest.raises(evidence.V3CapacityError):
        cff._json_metrics([None]*20001,v3_entry=True)
    entry=_node_value(2000000)
    assert cff._json_metrics(entry,v3_entry=True)[1]==2000000
    with pytest.raises(evidence.V3CapacityError):
        cff._json_metrics(_node_value(2000001),v3_entry=True)
    budget=cff._V3Wrapper('a'*64,cff.VERSION); bad=cff._V3Wrapper('a'*64,cff.VERSION)
    for _ in range(3):
        budget.add(entry); bad.add(entry)
    budget.add(_node_value(1999996))
    assert budget.nodes==8000000
    with pytest.raises(evidence.V3CapacityError):
        bad.add(_node_value(1999997))


def test_per_host_and_aggregate_registry_edges():
    doc={k:[] for k in evidence.REGISTRIES}
    doc['hosts']=[{'host_id':str(i)} for i in range(10)]
    doc['evidence']=[row for i in range(10) for row in [{'host_id':str(i)}]*20000]
    groups=evidence._v3_groups(doc,evidence._V3Stage.RAW)
    assert sum(len(g['evidence']) for g in groups.values())==200000
    with pytest.raises(evidence.V3CapacityError):
        evidence._v3_groups({**doc,'evidence':doc['evidence']+[{'host_id':'0'}]},evidence._V3Stage.RAW)
    with pytest.raises(evidence.V3CapacityError):
        evidence._v3_groups({**doc,'evidence':[{'host_id':'0'}]*20001},evidence._V3Stage.RAW)
    with pytest.raises(evidence.V3CapacityError):
        evidence._v3_groups({**doc,'hosts':doc['hosts']+[{'host_id':'10'}]},evidence._V3Stage.RAW)


@pytest.mark.parametrize('stage,limit,parse',[
    (evidence._V3Stage.RAW,64*MIB,evidence._parse_v3_raw),
    (evidence._V3Stage.ASSESSED,96*MIB,evidence._parse_v3_assessed)])
def test_actual_parser_byte_edges(stage,limit,parse):
    doc=_small()
    if stage is evidence._V3Stage.ASSESSED:
        doc=assessment._evaluate_v3_raw(doc,rules)
    raw=_json(doc)
    # Valid JSON with trailing whitespace at the actual input byte budget.
    padded=raw+b' '*(limit-len(raw))
    assert len(padded)==limit and parse(padded)==doc
    with pytest.raises(evidence.V3CapacityError) as exc:
        parse(padded+b' ')
    assert exc.value.code=='V3_CAPACITY_LIMIT' and exc.value.stage==stage.value
    with pytest.raises(evidence.EvidenceError,match='SIZE_LIMIT'):
        evidence.parse_evidence_bytes(padded)


def test_nontrivial_shared_domain_exact(replayed):
    doc,_,_=_aggregate(replayed[:1])
    assert evidence.canonical_bytes(doc)==evidence._canonical_v3_raw(doc)
    old=assessment.evaluate_document(doc,rules)
    new=assessment._evaluate_v3_raw(doc,rules)
    assert evidence.canonical_bytes(old)==evidence._canonical_v3_assessed(new)
    pair=cff.project_cff(doc,rules)
    assert cff._canonical_v3_raw_projection(pair,doc,rules)==cff.canonical_projection_bytes(pair,doc,rules)


def test_row_materialization_stops_before_overflow():
    # Actual 32 MiB/128 MiB limits, no monkeypatch of capacity. The row guard
    # must stop on the first overflowing row, not materialize the rest.
    wrapper=cff._V3Wrapper('a'*64,cff.VERSION)
    row=_byte_value(16*MIB)
    visited=[]
    def project(i):
        visited.append(i)
        return row
    with pytest.raises(evidence.V3CapacityError) as exc:
        cff._V3Rows(wrapper).map(range(5),project)
    assert exc.value.stage=='CFF' and visited==[0,1,2]
