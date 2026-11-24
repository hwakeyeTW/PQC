"""Issue #18: pure certificate asset projection and retained details validation.

No discovery, certificate parsing, I/O, authorization or runtime inference here.
"""
import hashlib
import json
import re
from datetime import datetime

from tools import assessment, evidence as ev, platform

COLLECTOR = "pqc-cert-assets"
VERSION = "1.0.0"
FORMAT = "pqc-certificate-details"
ROOT_PATHS = {"system-tls-certs": "/etc/pki/tls/certs",
              "system-ca-anchors": "/etc/pki/ca-trust/source/anchors",
              "system-ssl-certs": "/etc/ssl/certs"}
ROOTS = tuple(ROOT_PATHS)
ROOT_TARGET_IDS = {"src-" + hashlib.sha256(p.encode("ascii")).hexdigest() for p in ROOT_PATHS.values()}
MAX_ENTRIES, MAX_SOURCES, MAX_BLOCKS = 512, 128, 256
MAX_PROJECTION = 256 * 1024
MAX_DETAILS = 2 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{64}\Z")
SOURCE_ID = re.compile(r"src-[0-9a-f]{64}\Z")
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+@-]{0,127}\Z")
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
SKIP = {"DISABLED_BY_USER", "DISABLED_BY_PROFILE", "NOT_ATTEMPTED", "PROFILE_NOT_VALIDATED",
        "PLATFORM_OUT_OF_SCOPE", "PLATFORM_UNKNOWN", "TOOL_UNAVAILABLE"}
GAPS = {"LIMIT_REACHED", "TIMEOUT", "READ_ERROR", "PERMISSION_DENIED", "UNSAFE_SOURCE",
        "SOURCE_CHANGED", "SOURCE_ABSENT", "DIRECTORY_LINK", "DEPTH_LIMIT", "NON_PUBLIC_BLOCK",
        "UNKNOWN_FORMAT", "INVALID_PEM", "UNSUPPORTED_TRUSTED_CERTIFICATE", "COMMAND_FAILED", "CLEANUP_FAILED", "PROJECTION_LIMIT"}
BLOCK_ERRORS = {"INVALID_PEM", "INVALID_DER", "LIMIT_REACHED", "COMMAND_FAILED", "TIMEOUT",
                "OUTPUT_LIMIT", "CLEANUP_FAILED", "FINGERPRINT_MISMATCH", "AMBIGUOUS_OUTPUT",
                "PERMISSION_DENIED", "TOOL_UNAVAILABLE", "SOURCE_CHANGED", "READ_ERROR", "UNSAFE_SOURCE",
                "SOURCE_ABSENT", "UNKNOWN_FORMAT", "PROJECTION_LIMIT"}
CERT_FIELDS = ("fingerprint", "public_key_algorithm", "public_key_bits", "signature_inner",
               "signature_outer", "issuer", "subject", "not_before", "not_after", "gaps")


def require(ok, code="CERT_INPUT"):
    if not ok:
        raise ev.EvidenceError(code, "$certificate_assets")


def shape(value, keys):
    require(type(value) is dict and value.keys() == set(keys))


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def match(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def canonical(value):
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError, OverflowError):
        raise ev.EvidenceError("CERT_INPUT", "$certificate_assets") from None


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def safe_dn(value):
    # RFC2253 rendered data, not a filename, HTML fragment or template.
    return (type(value) is str and 0 < len(value) <= 512 and value.isascii()
            and all(32 <= ord(c) < 127 for c in value)
            and not any(s in value.upper() for s in ("{{", "{%", "{#", "-----BEGIN", "PRIVATE KEY"))
            and re.search(r"\\(?:0[0-9a-fA-F]|1[0-9a-fA-F]|7[fF])", value) is None)


def valid_stamp(value):
    if not match(STAMP, value):
        return False
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
        return True
    except ValueError:
        return False


def metadata_gaps(cert):
    gaps = [k.upper() + "_UNKNOWN" for k in CERT_FIELDS[1:-1] if cert[k] is None]
    if cert["signature_inner"] is not None and cert["signature_outer"] is not None:
        if cert["signature_inner"] != cert["signature_outer"]:
            gaps.append("SIGNATURE_CONFLICT")
    if cert["not_before"] and cert["not_after"] and cert["not_before"] > cert["not_after"]:
        gaps.append("VALIDITY_CONFLICT")
    return sorted(gaps)


def validate_certificate(cert):
    shape(cert, CERT_FIELDS)
    require(match(SHA, cert["fingerprint"]))
    for k in ("public_key_algorithm", "signature_inner", "signature_outer"):
        require(cert[k] is None or match(TOKEN, cert[k]))
    require(cert["public_key_bits"] is None or integer(cert["public_key_bits"], 1, 1048576))
    for k in ("issuer", "subject"):
        require(cert[k] is None or safe_dn(cert[k]))
    for k in ("not_before", "not_after"):
        require(cert[k] is None or valid_stamp(cert[k]))
    require(cert["gaps"] == metadata_gaps(cert), "CERT_METADATA_GAPS")


def gap_list(value, allowed):
    require(type(value) is list and len(value) <= len(allowed))
    require(all(type(x) is str and x in allowed for x in value))
    require(value == sorted(set(value)))


def validate_snapshot(snapshot):
    shape(snapshot, ROOTS)
    # Validate closed shapes before canonical encoding; no arbitrary nested data.
    ids, fingerprints, target_blocks = set(), {}, {}
    entries = sources = blocks = 0
    for root in ROOTS:
        row = snapshot[root]
        shape(row, ("attempted", "rc", "entries", "directories", "skipped", "root_target_id", "gaps", "sources"))
        require(type(row["attempted"]) is bool and (row["rc"] is None or integer(row["rc"], -255, 255)))
        require(integer(row["entries"], 0, MAX_ENTRIES) and integer(row["skipped"], 0, row["entries"]) and integer(row["directories"], 0, row["entries"]))
        require(row["root_target_id"] is None or (match(SOURCE_ID, row["root_target_id"]) and row["root_target_id"] in ROOT_TARGET_IDS))
        entries += row["entries"]
        require(type(row["sources"]) is list and len(row["sources"]) <= MAX_SOURCES)
        sources += len(row["sources"])
        accounted = len(row["sources"]) + row["skipped"] + row["directories"]
        require(accounted <= row["entries"] and (row["gaps"] or accounted == row["entries"]))
        gap_list(row["gaps"], GAPS if row["attempted"] else SKIP)
        if not row["attempted"]:
            require(row["root_target_id"] is None and row["rc"] is None and row["entries"] == row["skipped"] == row["directories"] == 0 and not row["sources"]
                    and len(row["gaps"]) == 1)
        elif row["rc"] != 0:
            require(row["root_target_id"] is None and not row["sources"] and row["entries"] == row["skipped"] == row["directories"] == 0
                    and row["gaps"] in (["COMMAND_FAILED"], ["TIMEOUT"], ["CLEANUP_FAILED"]))
        if row["attempted"] and row["rc"] == 0 and not row["gaps"]:
            require(row["root_target_id"] is not None)
        for src in row["sources"]:
            shape(src, ("source_id", "target_id", "format", "gaps", "blocks"))
            require(match(SOURCE_ID, src["source_id"]) and src["source_id"] not in ids)
            ids.add(src["source_id"])
            require(src["target_id"] is None or match(SOURCE_ID, src["target_id"]))
            require(src["format"] in ("PEM", "DER", "UNKNOWN"))
            gap_list(src["gaps"], GAPS)
            require(type(src["blocks"]) is list and len(src["blocks"]) <= MAX_BLOCKS)
            blocks += len(src["blocks"])
            require(src["blocks"] or src["gaps"])
            require(src["format"] != "UNKNOWN" or not src["blocks"])
            require(src["format"] != "DER" or len(src["blocks"]) <= 1)
            for index, block in enumerate(src["blocks"], 1):
                shape(block, ("rc", "reason", "certificate"))
                rc, reason, cert = block["rc"], block["reason"], block["certificate"]
                require(rc is None or integer(rc, -255, 255))
                if cert is None:
                    require(type(reason) is str and reason in BLOCK_ERRORS)
                    require(rc != 0 or reason in ("FINGERPRINT_MISMATCH", "AMBIGUOUS_OUTPUT", "OUTPUT_LIMIT", "TIMEOUT", "CLEANUP_FAILED", "SOURCE_CHANGED", "READ_ERROR", "UNSAFE_SOURCE", "SOURCE_ABSENT", "PROJECTION_LIMIT", "UNKNOWN_FORMAT", "PERMISSION_DENIED", "LIMIT_REACHED"))
                else:
                    validate_certificate(cert)
                    require(rc == 0 and reason == ("METADATA_GAP" if cert["gaps"] else "OK"))
                    require(src["target_id"] is not None)
                    fp = cert["fingerprint"]
                    require(fp not in fingerprints or fingerprints[fp] == cert, "CERT_FINGERPRINT_CONFLICT")
                    fingerprints[fp] = cert
                    target_key = (src["target_id"], index)
                    require(target_key not in target_blocks or target_blocks[target_key] == fp, "CERT_TARGET_CONFLICT")
                    target_blocks[target_key] = fp
        require([s["source_id"] for s in row["sources"]] == sorted(s["source_id"] for s in row["sources"]))
    require(entries <= MAX_ENTRIES and sources <= MAX_SOURCES and blocks <= MAX_BLOCKS, "CERT_LIMIT")
    require(len(canonical(snapshot)) <= MAX_PROJECTION, "CERT_LIMIT")


def root_status(row):
    if not row["attempted"]:
        reason = row["gaps"][0]
        if reason in ("PLATFORM_UNKNOWN", "TOOL_UNAVAILABLE"):
            return "UNKNOWN", reason, 0
        return "NOT_SCANNED", reason if reason in ev.NOT_SCANNED_REASONS else "NOT_ATTEMPTED", 0
    gaps = set(row["gaps"])
    count = 0
    for src in row["sources"]:
        gaps.update(src["gaps"])
        for block in src["blocks"]:
            count += block["certificate"] is not None
            if block["reason"] != "OK":
                gaps.add(block["reason"])
    if not gaps:
        return "COLLECTED", "OK", count
    if count:
        return "PARTIAL", "INCOMPLETE_CERTIFICATES", count
    if gaps == {"PERMISSION_DENIED"}:
        return "PERMISSION_DENIED", "PERMISSION_DENIED", 0
    if gaps & {"LIMIT_REACHED", "DEPTH_LIMIT", "PROJECTION_LIMIT", "TIMEOUT", "OUTPUT_LIMIT",
               "READ_ERROR", "SOURCE_CHANGED", "COMMAND_FAILED", "CLEANUP_FAILED"}:
        return "ERROR", "INCOMPLETE_CERTIFICATES", 0
    return "UNKNOWN", "CERTIFICATES_UNAVAILABLE", 0


def source_record(source):
    shape(source, ("source_kind", "producer_id", "producer_version", "origin_ref", "input_sha256"))
    require(source["source_kind"] in ("NATIVE_COLLECTOR", "SYNTHETIC") and source["producer_id"] == COLLECTOR
            and source["producer_version"] == VERSION
            and match(re.compile(r"[a-z0-9][a-z0-9-]{0,127}\Z"), source["origin_ref"])
            and (source["input_sha256"] is None or match(SHA, source["input_sha256"])))


def project(document, host_id, source, observed_at, snapshot, rules):
    # Called after validation. Identity and actual refs are derived, not supplied by discovery.
    source_record(source)
    source = dict(source)
    ev.validate_document(document)
    require(document["schema_version"] == "1.1.0" and type(observed_at) is str and len(observed_at) <= 40)
    host = next((h for h in document["hosts"] if h["host_id"] == host_id), None)
    require(host is not None)
    validate_snapshot(snapshot)
    assessment.validate_rules(rules)
    rid = document["run"]["run_id"]
    assets, collections, evidence, root_records, occurrences = {}, [], [], [], []
    stable = host["identity_scope"] == "STABLE"
    common = dict(run_id=rid, host_id=host_id, source=source, observed_at=observed_at)
    for root in ROOTS:
        row = snapshot[root]
        cid = ev.collection_id(rid, host_id, COLLECTOR, root)
        state, reason, count = root_status(row)
        refs = []
        def emit(key, kind, data, aid=None, algorithm=None, detail_hash=None):
            eid = ev.evidence_id(rid, host_id, cid, key)
            record = dict(evidence_id=eid, host_id=host_id, collection_id=cid, asset_id=aid,
                          observation_key=key, evidence_kind=kind, data=data, algorithm=algorithm,
                          source=source, observed_at=observed_at)
            if detail_hash:
                record.update(evidence_ref="cert-" + detail_hash, raw_sha256=detail_hash)
            refs.append(eid)
            evidence.append(record)
            return eid
        for src in row["sources"]:
            for index, block in enumerate(src["blocks"], 1):
                cert = block["certificate"]
                if cert is None:
                    continue
                fp = cert["fingerprint"]
                aid = ev.asset_id(host_id, "certificate", fp, run_id=None if stable else rid)
                asset = assets.setdefault(aid, dict(asset_id=aid, host_id=host_id, asset_kind="certificate",
                    identity_scope="STABLE" if stable else "RUN_SCOPED", identity_key=fp, evidence_ids=[]))
                algorithms = [("certificate", None)]
                if cert["public_key_algorithm"] is not None:
                    algorithms.append(("public-key", assessment.classify_algorithm(cert["public_key_algorithm"], "CERT_PUBLIC_KEY", rules)))
                if cert["signature_inner"] is not None and cert["signature_inner"] == cert["signature_outer"]:
                    algorithms.append(("signature", assessment.classify_algorithm(cert["signature_inner"], "SIGNATURE", rules)))
                prefix = src["source_id"] + "-" + str(index) + "-"
                ids = sorted(ev.evidence_id(rid, host_id, cid, prefix + k) for k, _ in algorithms)
                record = dict(**common, collection_id=cid, asset_id=aid, root=root, source_id=src["source_id"],
                              target_id=src["target_id"], block_index=index, fingerprint=fp, evidence_ids=ids)
                dh = digest(dict(record=record, block=block, format=src["format"]))
                occurrences.append({**record, "detail_ref": "cert-" + dh, "detail_sha256": dh})
                for k, alg in algorithms:
                    eid = emit(prefix + k, "ASSET_METADATA", dict(name=fp, version=None), aid, alg, dh)
                    asset["evidence_ids"].append(eid)
        if state in ("COLLECTED", "PARTIAL"):
            emit("summary", "COLLECTION_SUMMARY", dict(scope=root, attempted=True, applicable=True,
                 coverage="COMPLETE" if state == "COLLECTED" else "PARTIAL", observation_count=count))
        collections.append(dict(collection_id=cid, host_id=host_id, collector_id=COLLECTOR,
            collector_version=VERSION, scope_key=root, collection_state=state, reason_code=reason,
            source=source, observed_at=observed_at, evidence_ids=sorted(refs)))
        record = dict(**common, root=root, collection_id=cid, evidence_ids=sorted(refs))
        root_records.append({**record, "detail_sha256": digest(dict(record=record, result=row))})
    for asset in assets.values():
        asset["evidence_ids"].sort()
    details = dict(detail_format=FORMAT, detail_version=VERSION, **common, snapshot=snapshot,
                   roots=root_records, occurrences=occurrences)
    # Deep copies prevent mutable aliases to caller data and bound the companion.
    raw = canonical(details)
    require(len(raw) <= MAX_DETAILS, "CERT_LIMIT")
    return dict(collections=collections, assets=list(assets.values()), evidence=evidence, details=json.loads(raw))


def build_cert_assets(document, host_id, *, source, observed_at, snapshot, rules,
                      requested, platform_snapshot, system_python_available):
    """Return additions plus mandatory private typed companion; no caller mutation."""
    require(type(requested) is bool and type(system_python_available) is bool)
    source_record(source)
    validate_snapshot(snapshot)
    shape(platform_snapshot, ("facts_state", "facts", "tools", "rpms"))
    require(platform_snapshot["facts_state"] in ("OK", "UNKNOWN", "ERROR", "PERMISSION_DENIED", "UNREACHABLE"))
    require(platform_snapshot["facts_state"] == "OK" or platform_snapshot["facts"] == {})
    data, _ = platform.normalize_platform(platform_snapshot["facts"], source_kind=source["source_kind"])
    tools = platform.normalize_tools(platform_snapshot["tools"])
    eligible = (platform_snapshot["facts_state"] == "OK" and data["platform_status"] == "UNVERIFIED"
                and all(tools[k][2]["available"] is True for k in ("openssl", "timeout"))
                and system_python_available)
    require(all(not r["attempted"] for r in snapshot.values()) if not requested or not eligible
            else all(r["attempted"] for r in snapshot.values()), "CERT_OUTSIDE_SCOPE")
    if not requested:
        require(all(r["gaps"][0] in ("DISABLED_BY_USER", "DISABLED_BY_PROFILE", "NOT_ATTEMPTED") for r in snapshot.values()), "CERT_OUTSIDE_SCOPE")
    elif not eligible:
        # The trusted profile caller can refuse dispatch before checking tools.
        expected = "PLATFORM_UNKNOWN" if platform_snapshot["facts_state"] != "OK" or data["platform_status"] == "UNKNOWN" else (
            "PLATFORM_OUT_OF_SCOPE" if data["platform_status"] == "OUT_OF_SCOPE" else "TOOL_UNAVAILABLE")
        require(all(r["gaps"][0] in (expected, "PROFILE_NOT_VALIDATED", "NOT_ATTEMPTED") for r in snapshot.values()), "CERT_OUTSIDE_SCOPE")
    result = project(document, host_id, source, observed_at, snapshot, rules)
    merged = {**document, **{k: document[k] + result[k] for k in ("collections", "assets", "evidence")}}
    ev.validate_document(merged)
    validate_cert_details(merged, result["details"], rules)
    return result


def strict_equal(a, b):
    if type(a) is not type(b):
        return False
    if type(b) is dict:
        return a.keys() == b.keys() and all(strict_equal(a[k], v) for k, v in b.items())
    if type(b) is list:
        return len(a) == len(b) and all(strict_equal(x, y) for x, y in zip(a, b))
    return a == b


def validate_cert_details(document, details, rules):
    """Reject mismatched, omitted, duplicated or tampered paired records and hashes."""
    shape(details, ("detail_format", "detail_version", "run_id", "host_id", "source", "observed_at",
                    "snapshot", "roots", "occurrences"))
    require(details["detail_format"] == FORMAT and details["detail_version"] == VERSION
            and details["run_id"] == document["run"]["run_id"], "CERT_DETAILS")
    require(type(details["roots"]) is list and len(details["roots"]) == len(ROOTS)
            and type(details["occurrences"]) is list and len(details["occurrences"]) <= MAX_BLOCKS, "CERT_DETAILS")
    expected = project(document, details["host_id"], details["source"], details["observed_at"], details["snapshot"], rules)
    require(strict_equal(details, expected["details"]), "CERT_DETAILS")
    actual_collections = {c["collection_id"]: c for c in document["collections"]
                          if c["collector_id"] == COLLECTOR and c["host_id"] == details["host_id"]}
    require(actual_collections == {c["collection_id"]: c for c in expected["collections"]}, "CERT_DETAILS")
    cids = set(actual_collections)
    actual_evidence = {e["evidence_id"]: e for e in document["evidence"] if e["collection_id"] in cids}
    require(actual_evidence == {e["evidence_id"]: e for e in expected["evidence"]}, "CERT_DETAILS")
    actual_assets = {a["asset_id"]: a for a in document["assets"]}
    for asset in expected["assets"]:
        actual = actual_assets.get(asset["asset_id"])
        require(actual is not None and all(actual[k] == asset[k] for k in asset if k != "evidence_ids")
                and set(actual["evidence_ids"]) & actual_evidence.keys() == set(asset["evidence_ids"]), "CERT_DETAILS")
