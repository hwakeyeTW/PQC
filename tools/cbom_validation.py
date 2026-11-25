"""Pinned CycloneDX 1.6 validation for the controller's V2.0 CBOM profile.

No generation, evidence inference, signature verification, I/O from instance
values, or publication. The only files read are the installed pinned schemas.
"""
import hashlib
import json
import math
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path


MAX_INPUT = 32 * 1024 * 1024
MAX_DEPTH = 64
_SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas" / "cyclonedx-1.6"
_BASE_URI = "http://cyclonedx.org/schema/"
ROOT_URI = _BASE_URI + "bom-1.6.schema.json"
_DRAFT_URI = "http://json-schema.org/draft-07/schema#"
# Immutable upstream release 1.6, 55343ba19dee1785acf1ce9191540d5fd7b590db.
_PINNED = (
    ("bom-1.6.schema.json", 252625,
     "3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93"),
    ("spdx.schema.json", 14269,
     "baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e"),
    ("jsf-0.82.schema.json", 8058,
     "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae"),
)
_FORMATS = ("uri", "iri-reference", "idn-email", "date-time")
_SURROGATE = re.compile(r"[\ud800-\udfff]")
_LOCAL_REF = re.compile(r"[^\x00-\x20\x7f]+\Z")
_EXTERNAL_REF = re.compile(r"(?:urn:cdx:|[a-z][a-z0-9+.-]*://|(?:https?|file|ftp|data):)", re.I)


@dataclass(frozen=True)
class ValidationResult:
    schema_status: str = "PASS"
    reference_status: str = "PASS"
    code: str = "OK"


class CBOMValidationError(ValueError):
    """Only fixed codes/statuses; never embed an instance or resolver exception."""

    def __init__(self, code, schema_status="NOT_TESTED", reference_status="NOT_TESTED"):
        self.code = code
        self.schema_status = schema_status
        self.reference_status = reference_status
        super().__init__(code)


def _fail(code):
    raise CBOMValidationError(code)


def _ref_fail(code, unsupported=False):
    raise CBOMValidationError(code, "PASS", "UNSUPPORTED" if unsupported else "FAIL")


def _scan_depth(raw):
    # Bound nesting before invoking the recursive stdlib JSON parser. Its
    # grammar validation remains authoritative, including mismatched braces.
    depth = 0
    quoted = escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            if depth > MAX_DEPTH:
                _fail("INPUT_DEPTH")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                _fail("INPUT_JSON")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("INPUT_DUPLICATE_KEY")
        result[key] = value
    return result


def _reject_constant(_value):
    _fail("INPUT_JSON")


def _parse_bytes(raw):
    if type(raw) is not bytes:
        _fail("INPUT_TYPE")
    if len(raw) > MAX_INPUT:
        _fail("INPUT_LIMIT")
    _scan_depth(raw)
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                              parse_constant=_reject_constant)
    except CBOMValidationError:
        raise
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        document = None
    # None is not a BOM. Raise outside the decoder's exception handler so
    # neither a JSONDecodeError document nor raw instance is chained.
    if type(document) is not dict:
        _fail("INPUT_JSON")
    return document


def _bound_tree(document):
    """Charge exact compact ASCII JSON size without building a second document.

    Only builtin JSON types. Shared subtrees are charged at every occurrence;
    a cycle is invalid. Containers, including the root, count toward depth.
    """
    if type(document) is not dict:
        _fail("INPUT_TYPE")
    remaining = MAX_INPUT
    active = set()

    def charge(n):
        nonlocal remaining
        remaining -= n
        if remaining < 0:
            _fail("INPUT_LIMIT")

    def string(value):
        if len(value) + 2 > remaining:
            _fail("INPUT_LIMIT")
        if _SURROGATE.search(value):
            _fail("INPUT_JSON")
        charge(2)
        # Each encoder allocation is bounded even for a very long string.
        for pos in range(0, len(value), 8192):
            charge(len(json.dumps(value[pos:pos + 8192], ensure_ascii=True)) - 2)

    def walk(value, depth):
        kind = type(value)
        if kind in (dict, list):
            if depth > MAX_DEPTH:
                _fail("INPUT_DEPTH")
            ident = id(value)
            if ident in active:
                _fail("INPUT_JSON")
            active.add(ident)
            charge(2 + max(0, len(value) - 1))
            if kind is dict:
                for key, item in value.items():
                    if type(key) is not str:
                        _fail("INPUT_TYPE")
                    string(key)
                    charge(1)
                    walk(item, depth + 1)
            else:
                for item in value:
                    walk(item, depth + 1)
            active.remove(ident)
        elif kind is str:
            string(value)
        elif value is None:
            charge(4)
        elif kind is bool:
            charge(4 if value else 5)
        elif kind is int:
            if value.bit_length() > 4 * remaining + 64:
                _fail("INPUT_LIMIT")
            try:
                encoded = str(value)
            except ValueError:
                encoded = None
            if encoded is None:
                _fail("INPUT_JSON")
            charge(len(encoded))
        elif kind is float:
            if not math.isfinite(value):
                _fail("INPUT_JSON")
            charge(len(json.dumps(value, allow_nan=False)))
        else:
            _fail("INPUT_TYPE")

    walk(document, 1)


def _pinned_documents():
    """Open only fixed local names, bounded regular files, no link following.

    The installed controller code/root is trusted; the schema directory and
    each final file are opened relative to pinned directory descriptors.
    """
    schemas = {}
    parent = directory = None
    problem = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        parent = os.open(_SCHEMA_DIR.parent, flags)
        directory = os.open(_SCHEMA_DIR.name, flags, dir_fd=parent)
        for name, size, sha256 in _PINNED:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_size != size:
                    _fail("SCHEMA_INTEGRITY")
                # Read at most size+1; a short read or changed content fails.
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    raw = stream.read(size + 1)
            finally:
                os.close(fd)
            if len(raw) != size or hashlib.sha256(raw).hexdigest() != sha256:
                _fail("SCHEMA_INTEGRITY")
            schema = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                                parse_constant=_reject_constant)
            uri = _BASE_URI + name
            if type(schema) is not dict or schema.get("$id") != uri or schema.get("$schema") != _DRAFT_URI:
                _fail("SCHEMA_INTEGRITY")
            schemas[uri] = schema
    except CBOMValidationError:
        raise
    except (OSError, AttributeError, NotImplementedError):
        problem = "SCHEMA_UNAVAILABLE"
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        problem = "SCHEMA_INTEGRITY"
    finally:
        if directory is not None:
            os.close(directory)
        if parent is not None:
            os.close(parent)
    if problem:
        _fail(problem)
    return schemas


def _deny_retrieve(_uri):
    from referencing.exceptions import NoSuchResource
    # Do not carry a caller-supplied URI in an exception or attempt a read.
    raise NoSuchResource(ref="unregistered")


def _offline_registry(schemas):
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7

    expected = {_BASE_URI + name for name, _, _ in _PINNED}
    if schemas.keys() != expected:
        _fail("SCHEMA_INTEGRITY")
    return Registry(retrieve=_deny_retrieve).with_resources(
        (uri, Resource(contents=schema, specification=DRAFT7)) for uri, schema in schemas.items())


def _validator():
    schemas = _pinned_documents()
    unavailable = False
    try:
        from jsonschema import Draft7Validator, FormatChecker
        from referencing import Registry, Resource  # noqa: F401 -- required engine API
        from referencing.jsonschema import DRAFT7  # noqa: F401
        # Format checking is necessary: the official JSF oneOf distinguishes
        # named algorithms from proprietary URI algorithms. Missing optional
        # format dependencies must not silently turn assertions off.
        checker = FormatChecker(formats=_FORMATS)
        if not checker.conforms("https://example.invalid/schema", "uri") or checker.conforms("RS256", "uri"):
            unavailable = True
    except Exception:
        unavailable = True
    if unavailable:
        _fail("SCHEMA_ENGINE_UNAVAILABLE")
    result = None
    try:
        for schema in schemas.values():
            Draft7Validator.check_schema(schema)
        result = Draft7Validator(schemas[ROOT_URI], registry=_offline_registry(schemas), format_checker=checker)
    except CBOMValidationError:
        raise
    except Exception:
        # SchemaError/referencing exceptions may contain raw schema/URI data.
        # A broken pinned installation is not an instance validation failure.
        pass
    if result is None:
        _fail("SCHEMA_ENGINE_ERROR")
    return result


# The supported profile is intentionally closed at the objects that can contain
# definitions or references. The remaining permitted leaf objects are validated
# by the official schema and have no local bom-ref definitions/relations.
_ROOT_KEYS = frozenset(("$schema", "bomFormat", "specVersion", "serialNumber", "version",
                        "metadata", "components", "services", "dependencies",
                        "externalReferences", "properties", "signature"))
_METADATA_KEYS = frozenset(("timestamp", "lifecycles", "tools", "manufacturer", "authors",
                            "component", "manufacture", "supplier", "licenses", "properties"))
_COMPONENT_KEYS = frozenset(("type", "mime-type", "bom-ref", "supplier", "manufacturer", "authors",
                             "author", "publisher", "group", "name", "version", "scope", "hashes",
                             "licenses", "copyright", "cpe", "purl", "omniborId", "swhid", "swid",
                             "modified", "externalReferences", "components", "cryptoProperties",
                             "properties", "tags", "signature"))
_SERVICE_KEYS = frozenset(("bom-ref", "provider", "group", "name", "version", "endpoints",
                           "authenticated", "x-trust-boundary", "trustZone", "licenses",
                           "externalReferences", "services", "properties", "tags", "signature"))
_CRYPTO_BLOCK = {"algorithm": "algorithmProperties", "certificate": "certificateProperties",
                 "related-crypto-material": "relatedCryptoMaterialProperties", "protocol": "protocolProperties"}


def _local_ref(value):
    # A declared local identity is opaque; never dereference its spelling.
    # BOM-Link and URL-looking identities/edges are not the local profile.
    if not value.isprintable() or not _LOCAL_REF.fullmatch(value) or _EXTERNAL_REF.match(value):
        _ref_fail("REFERENCE_UNSUPPORTED", unsupported=True)
    return value


def _supported(obj, keys):
    if obj.keys() - keys:
        _ref_fail("REFERENCE_UNSUPPORTED", unsupported=True)


def _reference_integrity(document):
    """Private post-schema pass; assumes official structural validation passed.

    Two passes: collect all global definitions, then check only schema-defined
    relation fields. Never search arbitrary strings/keys for 'ref'.
    """
    _supported(document, _ROOT_KEYS)
    definitions = {}
    endpoints = set()
    crypto_nodes = []

    def define(obj, kind, subtype=None, detail=None, endpoint=False):
        if "bom-ref" not in obj:
            return None
        ref = _local_ref(obj["bom-ref"])
        if ref in definitions:
            _ref_fail("REFERENCE_DUPLICATE")
        definitions[ref] = (kind, subtype, detail)
        if endpoint:
            endpoints.add(ref)
        return ref

    def contact(obj):
        define(obj, "contact")

    def organization(obj):
        define(obj, "organization")
        if "address" in obj:
            define(obj["address"], "address")
        for item in obj.get("contact", []):
            contact(item)

    def licenses(obj):
        for item in obj.get("licenses", []):
            if "license" in item:
                license = item["license"]
                # Licensing includes further organization/contact definitions;
                # this optional commercial model is outside the product profile.
                if "licensing" in license:
                    _ref_fail("REFERENCE_UNSUPPORTED", unsupported=True)
                define(license, "license")
            else:
                define(item, "license-expression")

    def organizations(obj, names):
        for name in names:
            if name in obj:
                organization(obj[name])
        for item in obj.get("authors", []):
            contact(item)

    def component(obj):
        _supported(obj, _COMPONENT_KEYS)
        kind = obj["type"]
        properties = obj.get("cryptoProperties")
        if kind == "cryptographic-asset":
            if properties is None:
                _ref_fail("REFERENCE_TYPE")
            subtype = properties["assetType"]
            block = _CRYPTO_BLOCK[subtype]
            if any(k in properties for k in _CRYPTO_BLOCK.values() if k != block):
                _ref_fail("REFERENCE_TYPE")
            details = properties.get(block, {})
            if subtype == "related-crypto-material" and "value" in details:
                # This discovery product never retains raw crypto material.
                _ref_fail("REFERENCE_UNSUPPORTED", unsupported=True)
            discriminator = (details.get("primitive") if subtype == "algorithm" else
                             details.get("type") if subtype == "related-crypto-material" else None)
            owner = define(obj, kind, subtype, discriminator, endpoint=True)
            crypto_nodes.append((owner, subtype, details))
        else:
            if properties is not None:
                _ref_fail("REFERENCE_TYPE")
            define(obj, kind, endpoint=True)
        organizations(obj, ("supplier", "manufacturer"))
        licenses(obj)
        for item in obj.get("components", []):
            component(item)

    def service(obj):
        _supported(obj, _SERVICE_KEYS)
        define(obj, "service", endpoint=True)
        organizations(obj, ("provider",))
        licenses(obj)
        for item in obj.get("services", []):
            service(item)

    metadata = document.get("metadata", {})
    _supported(metadata, _METADATA_KEYS)
    organizations(metadata, ("manufacturer", "manufacture", "supplier"))
    licenses(metadata)
    if "component" in metadata:
        component(metadata["component"])
    tools = metadata.get("tools", [])
    # Legacy metadata.tools arrays contain no ref definitions. Modern tools
    # may carry component/service trees with the same global namespace.
    if type(tools) is dict:
        for item in tools.get("components", []):
            component(item)
        for item in tools.get("services", []):
            service(item)
    for item in document.get("components", []):
        component(item)
    for item in document.get("services", []):
        service(item)

    def target(value, allowed, owner=None, detail=None):
        ref = _local_ref(value)
        row = definitions.get(ref)
        if row is None:
            _ref_fail("REFERENCE_DANGLING")
        if owner is not None and ref == owner:
            _ref_fail("REFERENCE_RELATION")
        if allowed == "endpoint":
            if ref not in endpoints:
                _ref_fail("REFERENCE_TYPE")
        elif row[0] != "cryptographic-asset" or (allowed != "crypto" and row[1] != allowed):
            _ref_fail("REFERENCE_TYPE")
        if detail is not None and row[2] != detail:
            _ref_fail("REFERENCE_TYPE")
        return ref

    def field(obj, key, allowed, owner, detail=None):
        if key in obj:
            target(obj[key], allowed, owner, detail)

    def array(obj, key, allowed, owner):
        for ref in obj.get(key, []):
            target(ref, allowed, owner)

    for owner, subtype, props in crypto_nodes:
        if subtype == "certificate":
            field(props, "signatureAlgorithmRef", "algorithm", owner, "signature")
            field(props, "subjectPublicKeyRef", "related-crypto-material", owner, "public-key")
        elif subtype == "related-crypto-material":
            field(props, "algorithmRef", "algorithm", owner)
            field(props.get("securedBy", {}), "algorithmRef", "algorithm", owner)
        elif subtype == "protocol":
            for suite in props.get("cipherSuites", []):
                array(suite, "algorithms", "algorithm", owner)
            transforms = props.get("ikev2TransformTypes", {})
            for key in ("encr", "prf", "integ", "ke", "auth"):
                array(transforms, key, "algorithm", owner)
            array(props, "cryptoRefArray", "crypto", owner)

    seen_dependencies = set()
    for row in document.get("dependencies", []):
        owner = target(row["ref"], "endpoint")
        if owner in seen_dependencies:
            _ref_fail("REFERENCE_DUPLICATE")
        seen_dependencies.add(owner)
        for key in ("dependsOn", "provides"):
            array(row, key, "endpoint", owner)


def validate_cbom(document):
    """Validate an unmodified JSON tree, raise fixed error or return both PASS.

    Schema validity is not evidence validity, signature authenticity, proof of
    observed usage, or a publication authorization. B/C own those contracts.
    """
    _bound_tree(document)
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.6":
        _fail("FORMAT_VERSION")
    if "$schema" in document and document["$schema"] != ROOT_URI:
        _fail("SCHEMA_URI")
    validator = _validator()
    valid = None
    try:
        valid = validator.is_valid(document)
    except Exception:
        # Do not return raw ValidationError or resolver exception/instance.
        pass
    if valid is None:
        _fail("SCHEMA_ENGINE_ERROR")
    if not valid:
        raise CBOMValidationError("SCHEMA_INVALID", "FAIL")
    _reference_integrity(document)
    return ValidationResult()


def validate_cbom_bytes(raw):
    """Strict UTF-8/duplicate-free bounded JSON bytes; no path or URI input."""
    return validate_cbom(_parse_bytes(raw))
