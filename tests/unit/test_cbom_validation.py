"""#26 A: pinned release validation, reference profile and fail-closed inputs."""
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import socket
import sys
import traceback
import urllib.request

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from tools import cbom_validation as cbom


PINS = {
    "bom-1.6.schema.json": (252625, "d52d4631b42c3c6370bc545e369611327ff6e1c8",
                            "3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93"),
    "spdx.schema.json": (14269, "d081ef979232166476cb25eb4e33edb1f6ba83da",
                         "baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e"),
    "jsf-0.82.schema.json": (8058, "f46bfb1e52731ad1280123ff3e2bd29bd18d4bc2",
                            "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae"),
    "LICENSE": (11341, "0808751c23d827d483dc3673d6e3f49514e49d1f",
                "6c29f22a4a7385285c6f579ec9f33c5e989f00739d6b257243a0b082ec9447ae"),
}
URI = "http://cyclonedx.org/schema/"
MINIMAL = {"bomFormat": "CycloneDX", "specVersion": "1.6"}
SECRET = "anonymous-test-secret-DO-NOT-ECHO"
BOM_LINK = "urn:cdx:12345678-1234-1234-1234-123456789abc/1#other"


def error(fn, code, schema="NOT_TESTED", refs="NOT_TESTED"):
    with pytest.raises(cbom.CBOMValidationError) as caught:
        fn()
    exc = caught.value
    assert (exc.code, exc.schema_status, exc.reference_status) == (code, schema, refs)
    assert str(exc) == code
    assert exc.__context__ is None
    assert SECRET not in repr(exc) + "".join(traceback.format_exception_only(type(exc), exc))


def component(ref, kind="library", **extra):
    return {"type": kind, "name": ref, "bom-ref": ref, **extra}


def crypto(ref, subtype, block, details):
    return component(ref, "cryptographic-asset", cryptoProperties={"assetType": subtype, block: details})


def graph():
    alg = crypto("sig", "algorithm", "algorithmProperties", {"primitive": "signature"})
    kem = crypto("kem", "algorithm", "algorithmProperties", {"primitive": "kem"})
    key = crypto("public-key", "related-crypto-material", "relatedCryptoMaterialProperties",
                 {"type": "public-key", "algorithmRef": "sig", "securedBy": {"algorithmRef": "kem"}})
    cert = crypto("cert", "certificate", "certificateProperties",
                  {"signatureAlgorithmRef": "sig", "subjectPublicKeyRef": "public-key",
                   "notValidBefore": "2025-01-01T00:00:00Z", "notValidAfter": "2027-01-01T00:00:00Z"})
    proto = crypto("tls", "protocol", "protocolProperties", {"type": "tls", "version": "1.3",
                   "cipherSuites": [{"name": "fixture-suite", "algorithms": ["kem", "sig"],
                                      "identifiers": ["not-a-bom-ref"]}],
                   "cryptoRefArray": ["cert", "public-key", "sig"]})
    ike = crypto("ike", "protocol", "protocolProperties", {"type": "ike",
                 "ikev2TransformTypes": {"encr": ["kem"], "prf": ["sig"], "integ": ["sig"],
                                        "ke": ["kem"], "auth": ["sig"], "esn": False}})
    lib = component("lib", components=[alg, kem], licenses=[{"license": {"id": "Apache-2.0", "bom-ref": "license"}}],
                    supplier={"bom-ref": "supplier", "name": "fixture",
                              "address": {"bom-ref": "address"}, "contact": [{"bom-ref": "contact"}]},
                    properties=[{"name": "unrelated-ref", "value": "not-a-bom-ref"}])
    return {**MINIMAL, "$schema": cbom.ROOT_URI,
            "metadata": {"component": component("host", "operating-system", components=[lib]),
                         "tools": {"components": [component("tool", "application")],
                                   "services": [{"name": "fixture-tool", "bom-ref": "tool-service"}]},
                         "authors": [{"bom-ref": "author"}],
                         "licenses": [{"expression": "MIT OR Apache-2.0", "bom-ref": "expression"}]},
            "components": [key, cert, proto, ike],
            "services": [{"name": "fixture-service", "bom-ref": "service",
                          "endpoints": ["https://example.invalid/fixture"],
                          "services": [{"name": "nested", "bom-ref": "nested-service"}]}],
            "dependencies": [{"ref": "host", "dependsOn": ["lib", "service"]},
                             {"ref": "lib", "provides": ["sig", "kem"]},
                             {"ref": "service", "dependsOn": ["tls", "cert", "nested-service"]}],
            "externalReferences": [{"type": "bom", "url": BOM_LINK}],
            "signature": {"algorithm": "RS256", "value": "AA"}}


def props(doc, index, key):
    return doc["components"][index]["cryptoProperties"][key]


def test_official_bytes_and_ref_closure():
    for name, (size, oid, sha) in PINS.items():
        data = (cbom._SCHEMA_DIR / name).read_bytes()
        assert len(data) == size
        assert hashlib.sha1(b"blob " + str(size).encode() + b"\0" + data).hexdigest() == oid
        assert hashlib.sha256(data).hexdigest() == sha
    schemas = cbom._pinned_documents()
    assert set(schemas) == {URI + name for name in PINS if name.endswith(".json")}

    def references(value):
        if isinstance(value, dict):
            if "$ref" in value and not value["$ref"].startswith("#"):
                yield value["$ref"]
            for item in value.values():
                yield from references(item)
        elif isinstance(value, list):
            for item in value:
                yield from references(item)

    for uri, schema in schemas.items():
        assert schema["$id"] == uri
        assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"
        expected = {"spdx.schema.json", "jsf-0.82.schema.json#/definitions/signature"} if uri == cbom.ROOT_URI else set()
        assert set(references(schema)) == expected
    assert cbom._validator().is_valid(MINIMAL)


def test_official_minimal_and_full_asset_graph():
    assert cbom.validate_cbom(MINIMAL) == cbom.ValidationResult()
    doc = graph()
    before = deepcopy(doc)
    assert cbom.validate_cbom(doc) == cbom.ValidationResult()
    raw = json.dumps(doc).encode()
    assert cbom.validate_cbom_bytes(raw) == cbom.ValidationResult()
    assert doc == before
    # Unknown observed values and optional missing links are not manufactured.
    for item in doc["components"]:
        details = item["cryptoProperties"]
        kind = details["assetType"]
        for field in list(details[cbom._CRYPTO_BLOCK[kind]]):
            del details[cbom._CRYPTO_BLOCK[kind]][field]
    assert cbom.validate_cbom(doc) == cbom.ValidationResult()


@pytest.mark.parametrize("mutate", [
    lambda d: d["components"][0].pop("name"),
    lambda d: d["components"][0].update(type="not-a-type"),
    lambda d: d["components"][0]["cryptoProperties"].update(assetType="not-a-type"),
    lambda d: d["components"][0].update({"$ref": "file:///" + SECRET}),
    lambda d: d.update({"$ref": "https://example.invalid/" + SECRET}),
    lambda d: d["metadata"]["component"]["components"][0]["licenses"][0]["license"].update(id=SECRET),
    lambda d: d["signature"].update(algorithm=SECRET),
    lambda d: d["signature"].pop("value"),
    lambda d: props(d, 1, "certificateProperties").update(notValidBefore=SECRET),
    lambda d: d["dependencies"][0].update(dependsOn=["lib", "lib"]),
    lambda d: props(d, 1, "certificateProperties").update(subjectPublicKeyRef=1),
], ids=["required", "component-enum", "crypto-enum", "nested-ref", "root-ref", "spdx",
        "jsf-uri", "jsf-required", "date-time", "schema-unique-items", "wrong-ref-json-type"])
def test_official_schema_negative(mutate):
    doc = graph()
    mutate(doc)
    error(lambda: cbom.validate_cbom(doc), "SCHEMA_INVALID", "FAIL")


# Each case is checked at the pure reference layer and again through the real
# official-schema entrypoint. The former is not a substitute for the latter.
REFERENCE_CASES = [
    ("duplicate-nested-component", lambda d: d["components"][0].update({"bom-ref": "lib"}), "REFERENCE_DUPLICATE"),
    ("duplicate-nested-service", lambda d: d["services"][0]["services"][0].update({"bom-ref": "host"}), "REFERENCE_DUPLICATE"),
    ("duplicate-license", lambda d: d["metadata"]["licenses"][0].update({"bom-ref": "license"}), "REFERENCE_DUPLICATE"),
    ("duplicate-address", lambda d: d["metadata"]["authors"][0].update({"bom-ref": "address"}), "REFERENCE_DUPLICATE"),
    ("duplicate-tools", lambda d: d["metadata"]["tools"]["services"][0].update({"bom-ref": "tool"}), "REFERENCE_DUPLICATE"),
    ("duplicate-dependency", lambda d: d["dependencies"].append({"ref": "lib", "dependsOn": ["host"]}), "REFERENCE_DUPLICATE"),
    ("dangling-source", lambda d: d["dependencies"][0].update(ref=SECRET), "REFERENCE_DANGLING"),
    ("dangling-depends", lambda d: d["dependencies"][0].update(dependsOn=[SECRET]), "REFERENCE_DANGLING"),
    ("dangling-provides", lambda d: d["dependencies"][1].update(provides=[SECRET]), "REFERENCE_DANGLING"),
    ("dependency-license", lambda d: d["dependencies"][0].update(dependsOn=["license"]), "REFERENCE_TYPE"),
    ("dependency-self", lambda d: d["dependencies"][0].update(dependsOn=["host"]), "REFERENCE_RELATION"),
    ("signature-library", lambda d: props(d, 1, "certificateProperties").update(signatureAlgorithmRef="lib"), "REFERENCE_TYPE"),
    ("signature-kem", lambda d: props(d, 1, "certificateProperties").update(signatureAlgorithmRef="kem"), "REFERENCE_TYPE"),
    ("public-key-algorithm", lambda d: props(d, 1, "certificateProperties").update(subjectPublicKeyRef="sig"), "REFERENCE_TYPE"),
    ("private-key", lambda d: props(d, 0, "relatedCryptoMaterialProperties").update(type="private-key"), "REFERENCE_TYPE"),
    ("key-algorithm", lambda d: props(d, 0, "relatedCryptoMaterialProperties").update(algorithmRef="cert"), "REFERENCE_TYPE"),
    ("secured-by", lambda d: props(d, 0, "relatedCryptoMaterialProperties")["securedBy"].update(algorithmRef="cert"), "REFERENCE_TYPE"),
    ("cipher-suite", lambda d: props(d, 2, "protocolProperties")["cipherSuites"][0].update(algorithms=["service"]), "REFERENCE_TYPE"),
    ("ike-transform", lambda d: props(d, 3, "protocolProperties")["ikev2TransformTypes"].update(ke=["lib"]), "REFERENCE_TYPE"),
    ("crypto-array", lambda d: props(d, 2, "protocolProperties").update(cryptoRefArray=["lib"]), "REFERENCE_TYPE"),
    ("crypto-self", lambda d: props(d, 2, "protocolProperties").update(cryptoRefArray=["tls"]), "REFERENCE_RELATION"),
    ("missing-crypto-type", lambda d: d["components"][0].pop("cryptoProperties"), "REFERENCE_TYPE"),
    ("library-with-crypto", lambda d: d["components"][0].update(type="library"), "REFERENCE_TYPE"),
    ("wrong-subtype-block", lambda d: d["components"][0]["cryptoProperties"].update(algorithmProperties={}), "REFERENCE_TYPE"),
    ("external-edge", lambda d: d["dependencies"][0].update(dependsOn=[BOM_LINK]), "REFERENCE_UNSUPPORTED"),
    ("external-definition", lambda d: d["components"][0].update({"bom-ref": BOM_LINK}), "REFERENCE_UNSUPPORTED"),
    ("whitespace-definition", lambda d: d["components"][0].update({"bom-ref": "key\u00a0id"}), "REFERENCE_UNSUPPORTED"),
    ("url-edge", lambda d: props(d, 1, "certificateProperties").update(subjectPublicKeyRef="https://example.invalid/" + SECRET), "REFERENCE_UNSUPPORTED"),
    ("raw-material", lambda d: props(d, 0, "relatedCryptoMaterialProperties").update(value=SECRET), "REFERENCE_UNSUPPORTED"),
    ("vulnerabilities", lambda d: d.update(vulnerabilities=[]), "REFERENCE_UNSUPPORTED"),
    ("pedigree", lambda d: d["components"][0].update(pedigree={}), "REFERENCE_UNSUPPORTED"),
    ("component-evidence", lambda d: d["components"][0].update(evidence={"occurrences": [{"location": "fixture", "bom-ref": "extra"}]}), "REFERENCE_UNSUPPORTED"),
    ("service-data", lambda d: d["services"][0].update(data=[]), "REFERENCE_UNSUPPORTED"),
]


@pytest.mark.parametrize("name,mutate,code", REFERENCE_CASES, ids=[r[0] for r in REFERENCE_CASES])
@pytest.mark.parametrize("layer", ["profile-unit", "official"], ids=["profile-unit", "official"])
def test_reference_profile(name, mutate, code, layer):
    doc = graph()
    mutate(doc)
    before = deepcopy(doc)
    fn = cbom._reference_integrity if layer == "profile-unit" else cbom.validate_cbom
    error(lambda: fn(doc), code, "PASS", "UNSUPPORTED" if code == "REFERENCE_UNSUPPORTED" else "FAIL")
    assert doc == before


def test_profile_unit_explicit_edges_and_ignored_strings():
    doc = graph()
    before = deepcopy(doc)
    cbom._reference_integrity(doc)
    assert doc == before
    # Ref-looking strings in metadata/properties/JSF/cipher identifiers are
    # not actual local definition or relation fields.
    assert doc["metadata"]["component"]["components"][0]["properties"][0]["value"] == "not-a-bom-ref"


@pytest.mark.parametrize("raw,code", [
    (b'{"bomFormat":"CycloneDX","specVersion":"1.6","x":NaN}', "INPUT_JSON"),
    (b'{"bomFormat":"CycloneDX","specVersion":"1.6","x":Infinity}', "INPUT_JSON"),
    (b'{"bomFormat":"CycloneDX","specVersion":"1.6","x":1e400}', "INPUT_JSON"),
    (b'{"bomFormat":"CycloneDX","specVersion":"1.6","x":{"a":1,"a":2}}', "INPUT_DUPLICATE_KEY"),
    (b'{"bomFormat":"CycloneDX","bomFormat":"CycloneDX","specVersion":"1.6"}', "INPUT_DUPLICATE_KEY"),
    (b'{"x":"\\ud800"}', "INPUT_JSON"),
    (b'{"x":"\xff"}', "INPUT_JSON"), (b'[]', "INPUT_JSON"),
    (b'{"x":"unterminated', "INPUT_JSON"), (b'{}{}', "INPUT_JSON"),
    (b'\xef\xbb\xbf{}', "INPUT_JSON"),
    (b'{' + b'"a":{' * 64 + b'}' * 65, "INPUT_DEPTH"),
])
def test_preflight_strict_bytes(raw, code):
    error(lambda: cbom.validate_cbom_bytes(raw), code)


@pytest.mark.parametrize("value", [float("nan"), math.inf, -math.inf, "\udfff", object(), (1, 2), {1: "x"}])
def test_preflight_typed_non_json(value):
    code = "INPUT_TYPE" if type(value) in (object, tuple, dict) else "INPUT_JSON"
    error(lambda: cbom.validate_cbom({**MINIMAL, "x": value}), code)


def test_preflight_depth_cycle_size_and_exact_compact_ascii_charge(monkeypatch):
    deep = {}
    cursor = deep
    for _ in range(64):
        cursor["a"] = {}
        cursor = cursor["a"]
    error(lambda: cbom.validate_cbom(deep), "INPUT_DEPTH")
    cycle = {}
    cycle["self"] = cycle
    error(lambda: cbom.validate_cbom(cycle), "INPUT_JSON")
    error(lambda: cbom.validate_cbom_bytes(b" " * (cbom.MAX_INPUT + 1)), "INPUT_LIMIT")
    data = {"value": ["\U0001f642\n\t\\\"", {"a": "\x00"}, 1, True, None, 1.25]}
    encoded = json.dumps(data, ensure_ascii=True, separators=(",", ":")).encode()
    monkeypatch.setattr(cbom, "MAX_INPUT", len(encoded))
    cbom._bound_tree(data)
    assert cbom._parse_bytes(encoded) == data
    monkeypatch.setattr(cbom, "MAX_INPUT", len(encoded) - 1)
    error(lambda: cbom._bound_tree(data), "INPUT_LIMIT")
    error(lambda: cbom._parse_bytes(encoded), "INPUT_LIMIT")
    # Braces/brackets inside escaped strings are not nesting levels.
    monkeypatch.setattr(cbom, "MAX_INPUT", 4096)
    nested = {"x": "[" * 100 + '\\"' + "{" * 100}
    assert cbom._parse_bytes(json.dumps(nested).encode()) == nested


@pytest.mark.parametrize("value", ["1.5", "1.7", 1.6, None])
def test_preflight_version(value):
    error(lambda: cbom.validate_cbom({**MINIMAL, "specVersion": value}), "FORMAT_VERSION")


@pytest.mark.parametrize("uri", ["file:///" + SECRET, "https://example.invalid/" + SECRET,
                                  URI + "spdx.schema.json", "", None, "https://cyclonedx.org/schema/bom-1.6.schema.json"])
def test_preflight_schema_uri_never_selects_validator(monkeypatch, uri):
    def forbidden():
        pytest.fail("invalid instance must not load schema")
    monkeypatch.setattr(cbom, "_validator", forbidden)
    error(lambda: cbom.validate_cbom({**MINIMAL, "$schema": uri}), "SCHEMA_URI")


def test_preflight_type_and_format():
    error(lambda: cbom.validate_cbom([]), "INPUT_TYPE")
    error(lambda: cbom.validate_cbom_bytes(bytearray(b"{}")), "INPUT_TYPE")
    error(lambda: cbom.validate_cbom({**MINIMAL, "bomFormat": "SPDX"}), "FORMAT_VERSION")


@pytest.mark.parametrize("kind", ["missing", "tampered", "symlink", "directory", "fifo"])
def test_preflight_pinned_material_refuses_unsafe_or_wrong_bytes(tmp_path, monkeypatch, kind):
    folder = tmp_path / "schemas" / "cyclonedx-1.6"
    folder.mkdir(parents=True)
    monkeypatch.setattr(cbom, "_SCHEMA_DIR", folder)
    first = folder / "bom-1.6.schema.json"
    if kind == "tampered":
        first.write_bytes(b"x" * PINS[first.name][0])
    elif kind == "symlink":
        first.symlink_to(tmp_path / "not-a-schema")
    elif kind == "directory":
        first.mkdir()
    elif kind == "fifo":
        import os
        os.mkfifo(first)
    expected = "SCHEMA_UNAVAILABLE" if kind in ("missing", "symlink") else "SCHEMA_INTEGRITY"
    error(lambda: cbom.validate_cbom(MINIMAL), expected)
    assert not (folder / "spdx.schema.json").exists()


def test_preflight_unknown_retrieval_and_registry_closure():
    from referencing.exceptions import NoSuchResource
    for uri in ("file:///" + SECRET, "https://example.invalid/" + SECRET, "http://example.invalid/schema"):
        with pytest.raises(NoSuchResource) as exc:
            cbom._deny_retrieve(uri)
        assert exc.value.ref == "unregistered"
    error(lambda: cbom._offline_registry({}), "SCHEMA_INTEGRITY")


def test_official_registry_network_traps_and_no_writes(tmp_path, monkeypatch):
    from referencing.exceptions import NoSuchResource
    before = {p.name: p.read_bytes() for p in cbom._SCHEMA_DIR.iterdir() if p.is_file()}
    called = []

    def forbidden(*args, **kwargs):
        called.append(True)
        raise AssertionError("network access forbidden")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    # The fixed resolver is directly exercised as well as the real JSF and SPDX refs.
    registry = cbom._offline_registry(cbom._pinned_documents())
    assert set(registry) == {URI + name for name in PINS if name.endswith(".json")}
    resolver = registry.resolver(cbom.ROOT_URI)
    assert resolver.lookup("spdx.schema.json").contents["$id"] == URI + "spdx.schema.json"
    assert resolver.lookup("jsf-0.82.schema.json#/definitions/signature").contents["title"] == "Signature"
    for uri in ("file:///" + SECRET, "https://example.invalid/" + SECRET, "http://example.invalid/schema"):
        with pytest.raises(NoSuchResource):
            registry.get_or_retrieve(uri)
    monkeypatch.chdir(tmp_path)
    assert cbom.validate_cbom(graph()) == cbom.ValidationResult()
    assert not called and not list(tmp_path.iterdir())
    after = {p.name: p.read_bytes() for p in cbom._SCHEMA_DIR.iterdir() if p.is_file()}
    assert before == after


def test_official_missing_format_dependency_is_not_pass(monkeypatch):
    from jsonschema import FormatChecker
    monkeypatch.delitem(FormatChecker.checkers, "uri")
    error(lambda: cbom.validate_cbom(MINIMAL), "SCHEMA_ENGINE_UNAVAILABLE")
