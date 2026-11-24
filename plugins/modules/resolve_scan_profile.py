#!/usr/bin/python
# -*- coding: utf-8 -*-
"""V2.0 controller policy only: no collector, file, command or network dispatch."""

DOCUMENTATION = r'''
---
module: resolve_scan_profile
short_description: Resolve a read-only scan profile request without dispatch
version_added: "2.0.0"
description:
  - Validates a trusted version-one policy and a source-separated request.
  - All collectors remain NOT_SCANNED. Active is intent-only in V2.0.
  - The caller must load the fixed policy with strict duplicate detection and
    establish authorized target identities and flag provenance before calling.
  - The policy file uses the JSON subset of YAML for unambiguous strict loading.
options:
  policy:
    description: Trusted parsed V1 policy mapping, not a file path.
    type: raw
    required: true
  request:
    description:
      - Mapping containing optional profile, plan_only, run_flags,
        inventory_flags, target_ids, active_opt_in and active_endpoints.
      - No full hostvars or connection settings are accepted.
    type: raw
    required: true
author:
  - PQC contributors
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
'''

EXAMPLES = r'''
# Controller-only invocation; fixed_policy and normalized_request are supplied
# by a trusted caller. This task does not collect evidence or grant dispatch.
- name: Validate a controller-side policy request
  security.compliance_pqc_readiness.resolve_scan_profile:
    policy: "{{ fixed_policy }}"
    request: "{{ normalized_request }}"
  register: profile_result
'''

RETURN = r'''
profile_decision_version:
  description: Version of the internal decision contract.
  returned: always
  type: int
profile:
  description: Validated profile name, or null for an invalid selector.
  returned: always
  type: str
decision:
  description: VALIDATED, DENIED or DEFERRED, never a scan result.
  returned: always
  type: str
reason_code:
  description: Fixed non-sensitive reason code.
  returned: always
  type: str
plan_only:
  description: Whether the validated request is plan only.
  returned: always
  type: bool
requested_flags:
  description: Eight normalized requests; all false on denial.
  returned: always
  type: dict
per_collector:
  description: Eight NOT_SCANNED records; no collected evidence.
  returned: always
  type: list
  elements: dict
active_intent_validated:
  description: Whether Active intent shape was validated, not authorization.
  returned: always
  type: bool
active_dispatch_allowed:
  description: Always false in V2.0.
  returned: always
  type: bool
execution_allowed:
  description: Always false for this policy-only module.
  returned: always
  type: bool
'''

import ipaddress
import json
import re


FLAGS = tuple('pqc_collect_' + name for name in (
    'packages', 'openssl', 'sshd', 'ssh_host_keys', 'system_certs',
    'crypto_policy', 'nginx_certs', 'tls_services',
))
PROFILES = ('baseline', 'extended', 'active')
NGINX = 'pqc_collect_nginx_certs'
TLS = 'pqc_collect_tls_services'
CERTS = 'pqc_collect_system_certs'
CLASSES = {key: ('extended' if key == NGINX else 'active' if key == TLS else 'passive')
           for key in FLAGS}
REQUEST_FIELDS = frozenset(('profile', 'plan_only', 'run_flags', 'inventory_flags',
                            'target_ids', 'active_opt_in', 'active_endpoints'))
ENDPOINT_FIELDS = frozenset(('source_host', 'protocol', 'address', 'port', 'sni'))
MAX_ENDPOINTS = 200  # Shape bound only; not an execution/probe budget.
LABEL = re.compile(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z', re.ASCII)
IDENTITY = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}\Z', re.ASCII)


class PolicyError(ValueError):
    """Fixed reason only; never include untrusted input in the exception."""


def reject(code='INVALID_INPUT'):
    raise PolicyError(code)


def expected_policy():
    # Hard V1 ceilings and defaults, independent of caller-provided policy.
    # Active TLS's static default is false: only explicit endpoint intent can
    # request it. This is not a dispatch permission.
    return {
        'policy_version': 1,
        'collector_classes': dict(CLASSES),
        'profiles': {profile: {key: kind == 'passive' or
                               (kind == 'extended' and profile != 'baseline')
                               for key, kind in CLASSES.items()}
                     for profile in PROFILES},
    }


def exact(value, expected):
    """Exact recursive schema and scalar types (bool is not int)."""
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return (value.keys() == expected.keys() and
                all(exact(value[key], wanted) for key, wanted in expected.items()))
    return value == expected


def validate_policy(policy):
    if not exact(policy, expected_policy()):
        reject('INVALID_POLICY')


def load_policy(raw):
    """Strictly parse the fixed JSON-subset YAML text, not a path.

    The caller must use this or an equivalent duplicate-rejecting parser on
    trusted repository bytes. Already-decoded mappings cannot retain raw
    duplicate-key evidence; S1 does not claim to validate lost provenance.
    """
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                reject('INVALID_POLICY')
            result[key] = value
        return result

    if type(raw) is not str or len(raw) > 16384:
        reject('INVALID_POLICY')
    try:
        policy = json.loads(raw, object_pairs_hook=unique,
                            parse_constant=lambda _: reject('INVALID_POLICY'))
    except (ValueError, RecursionError):
        reject('INVALID_POLICY')
    validate_policy(policy)
    return policy


def bool_flag(value):
    if type(value) is bool:
        return value
    if type(value) is str and value.lower() in ('true', 'false'):
        return value.lower() == 'true'
    reject()


def flags(value):
    if type(value) is not dict or not value.keys() <= set(FLAGS):
        reject()
    return {key: bool_flag(flag) for key, flag in value.items()}


def target_identity(value):
    if type(value) is not str or not 1 <= len(value) <= 255 or not value.isascii():
        reject()
    if IDENTITY.fullmatch(value):
        return value
    # Exact IPv6 inventory identities may contain colons; no patterns/zones.
    if ':' in value and '%' not in value:
        try:
            if ipaddress.ip_address(value).version == 6:
                return value
        except ValueError:
            pass
    reject()


def target_set(value):
    if type(value) is not list:
        reject()
    result = set()
    for item in value:
        name = target_identity(item)
        if name in result:
            reject()
        result.add(name)
    return result


def dns_name(value):
    if type(value) is not str or not value.isascii() or not 1 <= len(value) <= 254:
        reject('ENDPOINT_INVALID')
    # A final root dot is legal DNS syntax; normalize it for duplicate checks.
    name = value[:-1] if value.endswith('.') else value
    if (not 1 <= len(name) <= 253 or
            not all(LABEL.fullmatch(part) for part in name.split('.')) or
            re.fullmatch(r'[0-9.\-]+', name)):
        reject('ENDPOINT_INVALID')
    return name.lower()


def endpoint_address(value):
    if type(value) is not str or not value.isascii() or not 1 <= len(value) <= 254 or '%' in value:
        reject('ENDPOINT_INVALID')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return dns_name(value)


def endpoint_protocols(value, targets):
    if type(value) is not list or not value or len(value) > MAX_ENDPOINTS:
        reject('ENDPOINT_INVALID')
    if not targets:
        reject('TARGET_NOT_AUTHORIZED')
    seen = set()
    protocols = set()
    for row in value:
        if type(row) is not dict or row.keys() != ENDPOINT_FIELDS:
            reject('ENDPOINT_INVALID')
        try:
            source = target_identity(row['source_host'])
        except PolicyError:
            reject('ENDPOINT_INVALID')
        if source not in targets:
            reject('TARGET_NOT_AUTHORIZED')
        protocol = row['protocol']
        port = row['port']
        if (type(protocol) is not str or protocol not in ('tls', 'ssh') or
                type(port) is not int or not 1 <= port <= 65535):
            reject('ENDPOINT_INVALID')
        address = endpoint_address(row['address'])
        sni = row['sni']
        if sni is not None:
            if protocol != 'tls':
                reject('ENDPOINT_INVALID')
            sni = dns_name(sni)
        key = (source, protocol, address, port, sni)
        if key in seen:
            reject('ENDPOINT_INVALID')
        seen.add(key)
        protocols.add(protocol)
    return protocols


def scope_for(key, profile):
    if key == TLS:
        return 'active'
    if key == NGINX or (key == CERTS and profile in ('extended', 'active')):
        return 'extended'
    return 'baseline'


def output(profile, plan_only, decision, reason, rows, active_validated=False):
    return {
        'profile_decision_version': 1, 'profile': profile, 'decision': decision,
        'reason_code': reason, 'plan_only': plan_only,
        'requested_flags': {row['id']: row['requested'] for row in rows},
        'per_collector': rows, 'active_intent_validated': active_validated,
        'active_dispatch_allowed': False, 'execution_allowed': False,
    }


def row_for(key, profile, requested, allowed, source, reason):
    return {'id': key, 'requested': requested, 'allowed_by_profile': allowed,
            'planned_scope': scope_for(key, profile), 'request_source': source,
            'collection_state': 'NOT_SCANNED', 'reason_code': reason}


def denied(profile, plan_only, reason, active_validated=False):
    # No caller values on errors. All eight requests cleared, zero dispatch.
    rows = [row_for(key, profile, False, False, 'PROFILE_DEFAULT', reason) for key in FLAGS]
    return output(profile, plan_only, 'DENIED', reason, rows, active_validated)


def resolve_scan_profile(policy, request):
    """Deterministically resolve data only. No IO, mutation or authorization.

    A DENIED result must be treated as failure; main() maps it to fail_json.
    The caller, not this resolver, authenticates target and flag provenance.
    """
    profile = None
    plan_only = False
    try:
        validate_policy(policy)
        if type(request) is not dict or not request.keys() <= REQUEST_FIELDS:
            reject()
        selected = request.get('profile', 'baseline')
        if type(selected) is not str or selected not in PROFILES:
            reject()
        profile = selected
        plan_only = request.get('plan_only', False)
        if type(plan_only) is not bool:
            plan_only = False
            reject()
        run = flags(request.get('run_flags', {}))
        inventory = flags(request.get('inventory_flags', {}))
        targets = target_set(request.get('target_ids', []))
        opt_in = bool_flag(request.get('active_opt_in', False))
        endpoints = request.get('active_endpoints', [])
        if type(endpoints) is not list:
            reject('ENDPOINT_INVALID')
        tls_intent = False
        if profile == 'active':
            if not opt_in:
                reject('ACTIVE_OPT_IN_REQUIRED')
            tls_intent = 'tls' in endpoint_protocols(endpoints, targets)
            # TLS rows and explicit flags must agree even when inventory narrows.
            if any(source[TLS] != tls_intent for source in (run, inventory) if TLS in source):
                reject('PROFILE_CONFLICT')
        elif opt_in or endpoints:
            reject('PROFILE_CONFLICT')

        rows = []
        for key in FLAGS:
            kind = CLASSES[key]
            allowed = (kind == 'passive' or (kind == 'extended' and profile != 'baseline') or
                       (kind == 'active' and profile == 'active'))
            # Explicit run expansion is invalid even if inventory says false.
            # Inventory expansion can only be safely narrowed by explicit run false.
            if not allowed and (run.get(key) is True or
                                (inventory.get(key) is True and run.get(key) is not False)):
                reject('PROFILE_CONFLICT')
            if run.get(key) is False:
                requested, source, reason = False, 'RUN', 'DISABLED_BY_USER'
            elif inventory.get(key) is False:
                requested, source, reason = False, 'NARROWED', 'NARROWED_BY_INVENTORY'
            else:
                if key in run:
                    requested, source = run[key], 'RUN'
                elif key in inventory:
                    requested, source = inventory[key], 'INVENTORY_EFFECTIVE'
                elif key == TLS and tls_intent:
                    requested, source = True, 'RUN'
                else:
                    requested, source = policy['profiles'][profile][key], 'PROFILE_DEFAULT'
                if not requested:
                    reason = 'DISABLED_BY_PROFILE'
                elif key == TLS:
                    reason = 'ACTIVE_NOT_AVAILABLE_V2_0'
                elif key in (CERTS, NGINX):
                    reason = 'ADAPTER_NOT_AVAILABLE'
                else:
                    reason = 'PLAN_ONLY' if plan_only else 'AWAITING_COLLECTOR'
            rows.append(row_for(key, profile, requested, allowed, source, reason))

        if profile == 'active':
            if not plan_only:
                return denied(profile, plan_only, 'ACTIVE_NOT_AVAILABLE_V2_0', True)
            return output(profile, plan_only, 'DEFERRED', 'ACTIVE_NOT_AVAILABLE_V2_0', rows, True)
        return output(profile, plan_only, 'VALIDATED',
                      'PLAN_ONLY' if plan_only else 'AWAITING_COLLECTOR', rows)
    except PolicyError as exc:
        return denied(profile, plan_only, str(exc))


def main():
    # Import Ansible only at the execution boundary. Raw values must reach the
    # strict resolver without Ansible's bool/string/int coercions. Hide the
    # invocation's complete policy/request (including nested endpoint data).
    from ansible.module_utils.basic import AnsibleModule

    class ResolverModule(AnsibleModule):
        # Ansible validates its outer argument envelope in __init__. Convert
        # those errors too, without emitting untrusted key names or values.
        def fail_json(self, msg, **kwargs):
            # Only this module's fixed contract can be returned. No framework
            # diagnostic, exception or raw invocation is copied.
            failure = kwargs.get('safe_decision')
            if failure is None:
                failure = denied(None, False, 'INVALID_INPUT')
            self.params = {}
            self.no_log_values.clear()
            super().fail_json(msg='Scan profile denied', changed=False,
                              invocation={'module_args': {}}, **failure)

    module = ResolverModule(argument_spec={
        'policy': {'type': 'raw', 'required': True, 'no_log': True},
        'request': {'type': 'raw', 'required': True, 'no_log': True},
    }, supports_check_mode=True)
    result = resolve_scan_profile(module.params['policy'], module.params['request'])
    if result['decision'] == 'DENIED':
        module.fail_json(msg='Scan profile denied', safe_decision=result)
    # Ansible's no_log sanitizer treats even fixed strings and policy_version
    # as secrets when they collide with raw input values. Drop all raw params
    # BEFORE clearing that sanitizer; only the closed, fixed result survives.
    module.params = {}
    module.no_log_values.clear()
    module.exit_json(changed=False, invocation={'module_args': {}}, **result)


if __name__ == '__main__':
    main()
