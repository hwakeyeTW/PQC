#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+

DOCUMENTATION = r'''
---
module: generate_cbom
short_description: Generate a CycloneDX v1.6 Cryptography Bill of Materials (CBOM)
description:
  - Accepts the pqc_crypto_report fact produced by the crypto_posture_snapshot role.
  - Transforms each discovered cryptographic asset into a CycloneDX v1.6 component
    with cryptoProperties (algorithms, certificates, protocols, key material).
  - Builds a dependency graph linking certificates to their algorithms, protocols
    to their cipher suites, and the host to all discovered crypto assets.
  - Output conforms to the CycloneDX v1.6 CBOM JSON schema (ECMA-424).
  - Read-only evaluation — does not modify any system state.
version_added: "0.3.0"
options:
  crypto_report:
    description: The pqc_crypto_report fact dictionary from the discovery role.
    type: dict
    required: true
  output_file:
    description: >
      Optional path to write the CBOM JSON output.
      If omitted, the CBOM is returned only in the module result.
    type: str
    required: false
author:
  - Red Hat Ansible Automation Platform
'''

EXAMPLES = r'''
- name: Generate CBOM from crypto posture
  generate_cbom:
    crypto_report: "{{ pqc_crypto_report }}"
  register: pqc_cbom

- name: Show CBOM component count
  ansible.builtin.debug:
    msg: "CBOM contains {{ pqc_cbom.cbom.components | length }} cryptographic components"

- name: Write CBOM to file
  generate_cbom:
    crypto_report: "{{ pqc_crypto_report }}"
    output_file: /tmp/cbom-{{ inventory_hostname }}.json
'''

RETURN = r'''
cbom:
  description: Complete CycloneDX v1.6 CBOM document
  returned: always
  type: dict
output_file:
  description: Path to the written output file (if requested)
  returned: when output_file is specified
  type: str
'''

import hashlib
import json
import os
import re
import uuid

from ansible.module_utils.basic import AnsibleModule

PQC_SAFE_ALGORITHMS = frozenset([
    'dilithium', 'ml-dsa', 'ml-kem', 'mlkem', 'kyber',
    'sphincs', 'slh-dsa', 'falcon', 'bike', 'hqc',
    'frodokem', 'classic-mceliece',
])

QUANTUM_VULNERABLE_KEY_ALGOS = frozenset([
    'rsa', 'ec', 'ecdsa', 'dsa', 'ed25519', 'ed448', 'dh', 'ecdh',
])

ALGORITHM_OID_MAP = {
    'sha256withrsaencryption': '1.2.840.113549.1.1.11',
    'sha384withrsaencryption': '1.2.840.113549.1.1.12',
    'sha512withrsaencryption': '1.2.840.113549.1.1.13',
    'sha1withrsaencryption': '1.2.840.113549.1.1.5',
    'md5withrsaencryption': '1.2.840.113549.1.1.4',
    'rsaencryption': '1.2.840.113549.1.1.1',
    'ecdsa-with-sha256': '1.2.840.10045.4.3.2',
    'ecdsa-with-sha384': '1.2.840.10045.4.3.3',
    'ecdsa-with-sha512': '1.2.840.10045.4.3.4',
    'id-ecpublickey': '1.2.840.10045.2.1',
    'ed25519': '1.3.101.112',
    'ed448': '1.3.101.113',
    'x25519': '1.3.101.110',
    'x448': '1.3.101.111',
    'dsa': '1.2.840.10040.4.1',
    'dsa-with-sha256': '2.16.840.1.101.3.4.3.2',
    'sha-256': '2.16.840.1.101.3.4.2.1',
    'sha-384': '2.16.840.1.101.3.4.2.2',
    'sha-512': '2.16.840.1.101.3.4.2.3',
    'sha-1': '1.3.14.3.2.26',
    'aes-128-gcm': '2.16.840.1.101.3.4.1.6',
    'aes-256-gcm': '2.16.840.1.101.3.4.1.46',
    'aes-128-cbc': '2.16.840.1.101.3.4.1.2',
    'aes-256-cbc': '2.16.840.1.101.3.4.1.42',
    'chacha20-poly1305': '1.2.840.113549.1.9.16.3.18',
    'ml-kem-768': '2.16.840.1.101.3.4.4.2',
    'ml-kem-1024': '2.16.840.1.101.3.4.4.3',
    'ml-dsa-65': '2.16.840.1.101.3.4.3.18',
    'ml-dsa-87': '2.16.840.1.101.3.4.3.19',
    'slh-dsa-sha2-128s': '2.16.840.1.101.3.4.3.20',
}

NIST_PQC_SECURITY_LEVELS = {
    'ml-kem-512': 1, 'mlkem512': 1,
    'ml-kem-768': 3, 'mlkem768': 3,
    'ml-kem-1024': 5, 'mlkem1024': 5,
    'ml-dsa-44': 2, 'ml-dsa-65': 3, 'ml-dsa-87': 5,
    'slh-dsa': 1, 'sphincs': 1,
    'falcon-512': 1, 'falcon-1024': 5,
    'kyber512': 1, 'kyber768': 3, 'kyber1024': 5,
    'bike': 1, 'hqc': 1, 'frodokem': 1, 'classic-mceliece': 5,
    'dilithium2': 2, 'dilithium3': 3, 'dilithium5': 5,
}

CLASSICAL_SECURITY_LEVELS = {
    'rsa-1024': 80, 'rsa-2048': 112, 'rsa-3072': 128, 'rsa-4096': 152,
    'rsaencryption-2048': 112, 'rsaencryption-3072': 128, 'rsaencryption-4096': 152,
    'ec-256': 128, 'ec-384': 192, 'ec-521': 256,
    'ecdsa-256': 128, 'ecdsa-384': 192, 'ecdsa-521': 256,
    'ed25519': 128, 'ed448': 224,
    'dsa-1024': 80, 'dsa-2048': 112, 'dsa-3072': 128,
    'dh-2048': 112, 'dh-3072': 128, 'dh-4096': 152,
    'aes-128': 128, 'aes-256': 256,
    'chacha20': 256,
    'sha-256': 128, 'sha-384': 192, 'sha-512': 256, 'sha-1': 80,
    'sha256withrsaencryption': 128, 'sha384withrsaencryption': 192,
    'sha512withrsaencryption': 256, 'sha1withrsaencryption': 80,
    'ecdsa-with-sha256': 128, 'ecdsa-with-sha384': 192, 'ecdsa-with-sha512': 256,
    'secp256r1': 128, 'secp384r1': 192, 'secp521r1': 256,
    'x25519': 128, 'x448': 224,
}


def _stable_ref(prefix, value):
    """Generate a deterministic bom-ref from a prefix and value."""
    digest = hashlib.sha256(f'{prefix}:{value}'.encode()).hexdigest()[:12]
    return f'{prefix}-{digest}'


def _is_pqc_safe(algorithm_string):
    lower = algorithm_string.lower()
    return any(pqc in lower for pqc in PQC_SAFE_ALGORITHMS)


def _lookup_oid(algo_name):
    return ALGORITHM_OID_MAP.get(algo_name.lower(), '')


def _nist_quantum_level(algo_name):
    lower = algo_name.lower()
    for pattern, level in NIST_PQC_SECURITY_LEVELS.items():
        if pattern in lower:
            return level
    return 0


def _classical_security_level(algo_name, key_size=0):
    lower = algo_name.lower()
    if key_size:
        composite = f'{lower}-{key_size}'
        if composite in CLASSICAL_SECURITY_LEVELS:
            return CLASSICAL_SECURITY_LEVELS[composite]
    for pattern, level in CLASSICAL_SECURITY_LEVELS.items():
        if pattern in lower:
            return level
    return 0


def _classify_primitive(algo_name):
    """Map an algorithm name to its CycloneDX cryptoPrimitive."""
    lower = algo_name.lower()
    if any(k in lower for k in ('ml-kem', 'mlkem', 'kyber', 'bike', 'hqc',
                                 'frodokem', 'classic-mceliece', 'sntrup')):
        return 'kem'
    if any(s in lower for s in ('sha256withrsa', 'sha384withrsa',
                                 'sha512withrsa', 'sha1withrsa',
                                 'md5withrsa', 'ecdsa-with-sha',
                                 'ml-dsa', 'dilithium', 'slh-dsa',
                                 'sphincs', 'falcon', 'ed25519', 'ed448',
                                 'dsa-with-sha', 'rsa-pss', 'rsassa-pss')):
        return 'signature'
    if any(k in lower for k in ('curve25519-sha256', 'curve448-sha512',
                                 'diffie-hellman', 'sntrup761x25519')):
        return 'key-agree'
    if any(e in lower for e in ('aes', 'chacha20', 'camellia', '3des')):
        return 'ae'
    if any(h in lower for h in ('sha-1', 'sha-256', 'sha-384', 'sha-512',
                                 'sha1', 'sha256', 'sha384', 'sha512',
                                 'md5')):
        return 'hash'
    if any(k in lower for k in ('rsa', 'ecpublickey')):
        return 'pke'
    if any(d in lower for d in ('dh', 'ecdh', 'x25519', 'x448',
                                  'secp256r1', 'secp384r1', 'secp521r1',
                                  'prime256v1', 'ffdhe')):
        return 'key-agree'
    if 'dsa' in lower:
        return 'signature'
    return 'unknown'


def _parse_algo_mode(algo_name):
    """Extract block cipher mode if present."""
    lower = algo_name.lower()
    for mode in ('gcm', 'cbc', 'ctr', 'ccm', 'ecb', 'cfb', 'ofb'):
        if mode in lower:
            return mode
    return None


def _parse_algo_size(algo_name, key_size=0):
    """Best-effort parameter set identifier from algorithm name or key_size."""
    if key_size:
        return str(key_size)
    match = re.search(r'(\d+)', algo_name)
    if match:
        return match.group(1)
    return ''


class CbomBuilder:
    """Accumulates CycloneDX v1.6 components and dependencies."""

    def __init__(self, host, collected_at):
        self._host = host
        self._collected_at = collected_at
        self._components = []
        self._dependencies = {}
        self._algo_cache = {}
        self._host_ref = _stable_ref('host', host)

    def _add_dependency(self, parent_ref, child_ref):
        self._dependencies.setdefault(parent_ref, set()).add(child_ref)

    def _get_or_create_algorithm(self, algo_name, key_size=0):
        """Return bom-ref for an algorithm, creating the component if new."""
        cache_key = (algo_name.lower(), key_size)
        if cache_key in self._algo_cache:
            return self._algo_cache[cache_key]

        ref = _stable_ref('algo', f'{algo_name.lower()}:{key_size}')
        primitive = _classify_primitive(algo_name)
        param_set = _parse_algo_size(algo_name, key_size)
        oid = _lookup_oid(algo_name)
        mode = _parse_algo_mode(algo_name)
        nist_ql = _nist_quantum_level(algo_name)
        classical_sl = _classical_security_level(algo_name, key_size)

        algo_props = {
            'primitive': primitive,
        }
        if param_set:
            algo_props['parameterSetIdentifier'] = param_set
        if mode:
            algo_props['mode'] = mode
        if classical_sl:
            algo_props['classicalSecurityLevel'] = classical_sl
        algo_props['nistQuantumSecurityLevel'] = nist_ql

        crypto_functions = []
        if primitive == 'signature':
            crypto_functions = ['sign', 'verify']
        elif primitive == 'pke':
            crypto_functions = ['encrypt', 'decrypt']
        elif primitive in ('ae', 'block-cipher', 'stream-cipher'):
            crypto_functions = ['encrypt', 'decrypt']
        elif primitive == 'hash':
            crypto_functions = ['digest']
        elif primitive in ('kem', 'key-agree'):
            crypto_functions = ['encapsulate', 'decapsulate']
        if crypto_functions:
            algo_props['cryptoFunctions'] = crypto_functions

        component = {
            'type': 'cryptographic-asset',
            'bom-ref': ref,
            'name': algo_name,
            'cryptoProperties': {
                'assetType': 'algorithm',
                'algorithmProperties': algo_props,
            },
        }
        if oid:
            component['cryptoProperties']['oid'] = oid

        self._components.append(component)
        self._algo_cache[cache_key] = ref
        return ref

    def add_certificate(self, cert_data, source_prefix):
        """Add a certificate and its linked algorithm + key material."""
        cert_path = cert_data.get('path', 'unknown')
        sig_algo = cert_data.get('signature_algorithm',
                                 cert_data.get('signature_algorithm', 'unknown'))
        pub_algo = cert_data.get('public_key_algorithm',
                                 cert_data.get('public_key_type', 'unknown'))
        pub_size = int(cert_data.get('public_key_size', 0) or 0)

        subject = cert_data.get('subject', 'unknown')
        if isinstance(subject, dict):
            subject = subject.get('commonName', str(subject))
        issuer = cert_data.get('issuer', 'unknown')
        if isinstance(issuer, dict):
            issuer = issuer.get('commonName', str(issuer))

        not_before = cert_data.get('not_before', '')
        not_after = cert_data.get('not_after', cert_data.get('expires', ''))

        sig_algo_ref = self._get_or_create_algorithm(sig_algo)

        key_algo_ref = self._get_or_create_algorithm(pub_algo, pub_size)
        key_ref = _stable_ref('key', f'{cert_path}:{pub_algo}:{pub_size}')
        key_component = {
            'type': 'cryptographic-asset',
            'bom-ref': key_ref,
            'name': f'{pub_algo} {pub_size}-bit' if pub_size else pub_algo,
            'cryptoProperties': {
                'assetType': 'related-crypto-material',
                'relatedCryptoMaterialProperties': {
                    'type': 'public-key',
                    'algorithmRef': key_algo_ref,
                    'state': 'active',
                },
            },
        }
        if pub_size:
            key_component['cryptoProperties'][
                'relatedCryptoMaterialProperties']['size'] = pub_size
        self._components.append(key_component)
        self._add_dependency(key_ref, key_algo_ref)

        cert_ref = _stable_ref(source_prefix, cert_path)
        cert_name = os.path.basename(cert_path) if cert_path != 'unknown' else subject
        cert_props = {
            'subjectName': str(subject),
            'issuerName': str(issuer),
            'signatureAlgorithmRef': sig_algo_ref,
            'subjectPublicKeyRef': key_ref,
            'certificateFormat': 'X.509',
        }
        if not_before:
            cert_props['notValidBefore'] = str(not_before)
        if not_after:
            cert_props['notValidAfter'] = str(not_after)

        cert_component = {
            'type': 'cryptographic-asset',
            'bom-ref': cert_ref,
            'name': cert_name,
            'cryptoProperties': {
                'assetType': 'certificate',
                'certificateProperties': cert_props,
            },
        }
        self._components.append(cert_component)
        self._add_dependency(cert_ref, sig_algo_ref)
        self._add_dependency(cert_ref, key_ref)
        self._add_dependency(self._host_ref, cert_ref)

    def add_ssh_host_key(self, key_data):
        """Add an SSH host key and its algorithm."""
        algo = key_data.get('algorithm', 'unknown')
        bits = int(key_data.get('bits', 0) or 0)
        key_path = key_data.get('path', 'unknown')

        algo_ref = self._get_or_create_algorithm(algo, bits)

        key_ref = _stable_ref('sshkey', key_path)
        key_component = {
            'type': 'cryptographic-asset',
            'bom-ref': key_ref,
            'name': f'SSH host key: {algo}',
            'cryptoProperties': {
                'assetType': 'related-crypto-material',
                'relatedCryptoMaterialProperties': {
                    'type': 'public-key',
                    'algorithmRef': algo_ref,
                    'state': 'active',
                    'format': 'SSH',
                },
            },
        }
        if bits:
            key_component['cryptoProperties'][
                'relatedCryptoMaterialProperties']['size'] = bits
        self._components.append(key_component)
        self._add_dependency(key_ref, algo_ref)
        self._add_dependency(self._host_ref, key_ref)

    def add_tls_service(self, svc_data):
        """Add a TLS service protocol and its algorithms."""
        port = svc_data.get('port', 0)
        protocol_version = svc_data.get('protocol', 'unknown')
        cipher = svc_data.get('cipher', 'unknown')
        kex = svc_data.get('key_exchange', 'unknown')
        peer_sig = svc_data.get('peer_signature', '')
        server_sig = svc_data.get('server_signature', '')

        version = ''
        match = re.search(r'(\d+\.?\d*)', str(protocol_version))
        if match:
            version = match.group(1)

        suite_algo_refs = []
        cipher_algo_ref = self._get_or_create_algorithm(cipher)
        suite_algo_refs.append(cipher_algo_ref)

        if kex and kex.lower() not in ('unknown', 'none', ''):
            kex_algo_ref = self._get_or_create_algorithm(kex)
            suite_algo_refs.append(kex_algo_ref)

        for sig in (peer_sig, server_sig):
            if sig and sig.lower() not in ('unknown', 'none', ''):
                sig_ref = self._get_or_create_algorithm(sig)
                suite_algo_refs.append(sig_ref)

        proto_ref = _stable_ref('tls', f'{self._host}:{port}')
        cipher_suite = {
            'name': cipher,
            'algorithms': list(dict.fromkeys(suite_algo_refs)),
        }

        proto_component = {
            'type': 'cryptographic-asset',
            'bom-ref': proto_ref,
            'name': f'TLS service on port {port}',
            'cryptoProperties': {
                'assetType': 'protocol',
                'protocolProperties': {
                    'type': 'tls',
                    'version': version,
                    'cipherSuites': [cipher_suite],
                },
            },
        }
        self._components.append(proto_component)
        for ref in suite_algo_refs:
            self._add_dependency(proto_ref, ref)
        self._add_dependency(self._host_ref, proto_ref)

    def add_sshd_protocol(self, crypto_lines):
        """Add SSH protocol with configured algorithms from sshd_config."""
        kex_algos = []
        ciphers = []
        macs = []

        for line in crypto_lines:
            stripped = line.strip()
            if stripped.startswith('KexAlgorithms'):
                kex_algos = stripped.split(None, 1)[-1].split(',')
            elif stripped.startswith('Ciphers'):
                ciphers = stripped.split(None, 1)[-1].split(',')
            elif stripped.startswith('MACs'):
                macs = stripped.split(None, 1)[-1].split(',')

        if not kex_algos and not ciphers and not macs:
            return

        proto_ref = _stable_ref('ssh', f'{self._host}:22')
        algo_refs = []

        for algo_name in kex_algos + ciphers + macs:
            algo_name = algo_name.strip()
            if algo_name:
                ref = self._get_or_create_algorithm(algo_name)
                algo_refs.append(ref)

        proto_component = {
            'type': 'cryptographic-asset',
            'bom-ref': proto_ref,
            'name': 'SSH service (sshd)',
            'cryptoProperties': {
                'assetType': 'protocol',
                'protocolProperties': {
                    'type': 'ssh',
                    'cryptoRefArray': list(dict.fromkeys(algo_refs)),
                },
            },
        }
        self._components.append(proto_component)
        for ref in algo_refs:
            self._add_dependency(proto_ref, ref)
        self._add_dependency(self._host_ref, proto_ref)

    def add_openssl_library(self, report):
        """Add OpenSSL as a library component with available TLS groups."""
        version_str = report.get('openssl_version', '')
        if not version_str:
            return

        match = re.search(r'OpenSSL\s+(\S+)', version_str)
        version = match.group(1) if match else version_str.strip()

        lib_ref = _stable_ref('lib', 'openssl')
        provides_refs = []

        tls_groups = report.get('openssl_tls1_3_groups', '')
        for line in tls_groups.splitlines():
            group_name = line.strip()
            if group_name and not group_name.startswith('TLS') and ':' not in group_name:
                ref = self._get_or_create_algorithm(group_name)
                provides_refs.append(ref)

        lib_component = {
            'type': 'library',
            'bom-ref': lib_ref,
            'name': 'OpenSSL',
            'version': version,
        }
        self._components.append(lib_component)
        self._add_dependency(self._host_ref, lib_ref)

        if provides_refs:
            self._dependencies.setdefault(lib_ref, set())
            for ref in provides_refs:
                self._dependencies[lib_ref].add(ref)

    def build(self):
        """Assemble the final CycloneDX v1.6 BOM document."""
        metadata = {
            'timestamp': self._collected_at,
            'lifecycles': [{'phase': 'operations'}],
            'component': {
                'type': 'device',
                'bom-ref': self._host_ref,
                'name': self._host,
            },
            'tools': {
                'components': [
                    {
                        'type': 'application',
                        'name': 'security.compliance_pqc_readiness',
                        'version': '0.3.0',
                    },
                ],
            },
        }

        policy_data = {}
        crypto_policy = {}
        for comp in self._components:
            if comp.get('type') == 'cryptographic-asset':
                cp = comp.get('cryptoProperties', {})
                if cp.get('assetType') == 'algorithm':
                    pass

        properties = []
        properties.append({
            'name': 'pqc:scanner:tier',
            'value': '1',
        })

        bom = {
            'bomFormat': 'CycloneDX',
            'specVersion': '1.6',
            'serialNumber': f'urn:uuid:{uuid.uuid4()}',
            'version': 1,
            'metadata': metadata,
            'components': self._components,
            'dependencies': self._build_dependencies(),
            'properties': properties,
        }

        return bom

    def _build_dependencies(self):
        deps = []
        all_refs = {self._host_ref}
        for comp in self._components:
            all_refs.add(comp['bom-ref'])

        for ref in all_refs:
            children = self._dependencies.get(ref, set())
            deps.append({
                'ref': ref,
                'dependsOn': sorted(children),
            })
        return deps

    def add_crypto_policy(self, policy_data):
        """Record RHEL crypto-policy as BOM metadata properties."""
        if not policy_data:
            return
        profile = policy_data.get('profile', '')
        fips = policy_data.get('fips_enabled', False)
        overrides = policy_data.get('local_overrides', [])

        props = self.build.__func__  # unused, handled inline in build
        self._policy_data = {
            'profile': profile,
            'fips_enabled': fips,
            'local_overrides': overrides,
        }


def transform_report(report):
    """Transform pqc_crypto_report into a CycloneDX v1.6 CBOM."""
    host = report.get('host', 'unknown')
    collected_at = report.get('collected_at', '')

    builder = CbomBuilder(host, collected_at)

    for cert in report.get('system_certificates', []):
        builder.add_certificate(cert, 'syscert')

    for cert in report.get('nginx_certificates', []):
        builder.add_certificate(cert, 'nginxcert')

    for key in report.get('ssh_host_keys', []):
        builder.add_ssh_host_key(key)

    for svc in report.get('tls_services', []):
        builder.add_tls_service(svc)

    sshd_lines = report.get('sshd_crypto_lines', [])
    if sshd_lines:
        builder.add_sshd_protocol(sshd_lines)

    builder.add_openssl_library(report)

    policy = report.get('crypto_policy', {})
    if policy:
        builder.add_crypto_policy(policy)

    bom = builder.build()

    if hasattr(builder, '_policy_data') and builder._policy_data:
        pd = builder._policy_data
        bom.setdefault('properties', [])
        bom['properties'].append({
            'name': 'rhel:crypto-policy:profile',
            'value': str(pd.get('profile', '')),
        })
        bom['properties'].append({
            'name': 'rhel:crypto-policy:fips-enabled',
            'value': str(pd.get('fips_enabled', False)).lower(),
        })
        if pd.get('local_overrides'):
            bom['properties'].append({
                'name': 'rhel:crypto-policy:local-overrides',
                'value': ','.join(str(o) for o in pd['local_overrides']),
            })

    return bom


def main():
    module = AnsibleModule(
        argument_spec=dict(
            crypto_report=dict(type='dict', required=True),
            output_file=dict(type='str', required=False, default=None),
        ),
        supports_check_mode=True,
    )

    report = module.params['crypto_report']
    output_file = module.params['output_file']

    cbom = transform_report(report)

    if output_file and not module.check_mode:
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        with open(output_file, 'w') as f:
            json.dump(cbom, f, indent=2)

    module.exit_json(
        changed=False,
        cbom=cbom,
        output_file=output_file or '',
    )


if __name__ == '__main__':
    main()
