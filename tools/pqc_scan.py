"""Controller-only SCOPE-R1 launcher. No managed execution is implemented."""
import argparse
import ctypes
import ipaddress
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

try:
    import yaml
except ImportError:
    if __name__ == '__main__':
        print('INVENTORY_TOOL_MISSING', file=sys.stderr)
        sys.exit(3)
    raise

FLAGS = frozenset('pqc_collect_' + name for name in (
    'packages', 'openssl', 'sshd', 'ssh_host_keys', 'system_certs',
    'crypto_policy', 'nginx_certs', 'tls_services',
))
RUN_FIELDS = frozenset({
    'pqc_scan_hosts', 'pqc_scan_groups', 'pqc_max_hosts', 'pqc_run_id',
    'pqc_scan_profile', 'pqc_active_opt_in', 'pqc_active_endpoints',
})
RESERVED = frozenset({'all', 'ungrouped', 'pqc_runtime_targets'})
INTERNAL_FIELDS = frozenset({
    'scope_plan_version', 'plan_status', 'reason_code', 'target_ids', 'target_count',
    'plan_only', 'execution_allowed', 'active_dispatch_allowed', 'limits', 'run_id',
    'profile', 'run_flags', 'inventory_flags', 'active_opt_in', 'active_endpoints',
    'pqc_plan_only', 'pqc_execution_allowed', 'pqc_active_dispatch_allowed',
    'pqc_target_ids', 'pqc_runtime_targets', 'pqc_scope_plan', 'pqc_guard',
    'report_root', 'report_dir',
})
HOST = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\Z')
GROUP = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}\Z')
RUN_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z')
SCOPE_BYTES = 256 * 1024
OUT_BYTES = 32 * 1024 * 1024
ERR_BYTES = 1024 * 1024
FATAL_ENV = {
    'ANSIBLE_INVENTORY_ENABLED': 'script',
    'ANSIBLE_INVENTORY_ANY_UNPARSED_IS_FAILED': 'true',
    'ANSIBLE_INVENTORY_UNPARSED_FAILED': 'true',
}


class Denied(Exception):
    """Only constant, non-sensitive reason codes may cross the CLI boundary."""

    def __init__(self, code, reason):
        super().__init__(reason)
        self.code, self.reason = code, reason


def require(condition, code, reason):
    if not condition:
        raise Denied(code, reason)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Denied(2, 'INVALID_CLI')


class Once(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest) is not None:
            raise Denied(2, 'DUPLICATE_OPTION')
        setattr(namespace, self.dest, True if self.nargs == 0 else values)


def parse_cli(argv):
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument('-i', required=True, action=Once)
    parser.add_argument('--scope-file', action=Once)
    parser.add_argument('-e', action=Once)
    parser.add_argument('--host', action='append', default=[])
    parser.add_argument('--group', action='append', default=[])
    parser.add_argument('--plan-only', action=Once, nargs=0)
    parser.add_argument('--forks', action=Once)
    args = parser.parse_args(argv)
    require(args.plan_only is True, 2, 'LIVE_NOT_AVAILABLE')
    require(args.forks in (None, '1', '2'), 2, 'INVALID_FORKS')
    require(not (args.scope_file is not None and args.e is not None), 2, 'CONFLICTING_SCOPE')
    if args.e is not None:
        require(args.e.startswith('@') and len(args.e) > 1, 2, 'INVALID_EXTRA_VARS')
        args.scope_file = args.e[1:]
    require(not (args.scope_file is not None and (args.host or args.group)), 2, 'CONFLICTING_SCOPE')
    raw = read_scope(args.scope_file) if args.scope_file is not None else {
        'pqc_scan_hosts': args.host, 'pqc_scan_groups': args.group,
    }
    return args.i, parse_scope(raw, int(args.forks or '2'))


class ScopeLoader(yaml.SafeLoader):
    """Safe YAML, no aliases/anchors/tags/merge, with bounded composition."""
    yaml_implicit_resolvers = {
        key: [(tag, rx) for tag, rx in values
              if tag not in ('tag:yaml.org,2002:bool', 'tag:yaml.org,2002:int')]
        for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }

    def __init__(self, stream):
        super().__init__(stream)
        self.depth = self.nodes = 0

    def compose_node(self, parent, index):
        event = self.peek_event()
        require(not isinstance(event, yaml.AliasEvent) and event.anchor is None
                and event.tag is None, 2, 'UNSAFE_SCOPE_YAML')
        self.depth += 1
        self.nodes += 1
        require(self.depth <= 16 and self.nodes <= 8192, 2, 'SCOPE_COMPLEXITY')
        try:
            return super().compose_node(parent, index)
        finally:
            self.depth -= 1

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            require(type(key) is str and key != '<<', 2, 'INVALID_SCOPE_KEY')
            require(key not in result, 2, 'DUPLICATE_SCOPE_KEY')
            result[key] = self.construct_object(value_node, deep=deep)
        return result


ScopeLoader.add_implicit_resolver('tag:yaml.org,2002:bool',
                                  re.compile(r'^(?:true|false)$', re.I), list('tTfF'))
ScopeLoader.add_implicit_resolver('tag:yaml.org,2002:int',
                                  re.compile(r'^(?:0|-?[1-9][0-9]*)$'), list('-0123456789'))


def read_scope(path):
    try:
        # Nonblocking open avoids hanging on a FIFO; only a regular file is read.
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), 'rb') as stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 2, 'INVALID_SCOPE_FILE')
            data = stream.read(SCOPE_BYTES + 1)
        require(len(data) <= SCOPE_BYTES, 2, 'SCOPE_TOO_LARGE')
        text = data.decode('utf-8', errors='strict')
        require(not any(mark in text for mark in ('{{', '{%', '{#')), 2, 'UNSAFE_SCOPE_YAML')
        return yaml.load(text, Loader=ScopeLoader)
    except Denied:
        raise
    except (OSError, ValueError, yaml.YAMLError, RecursionError):
        raise Denied(2, 'INVALID_SCOPE_FILE') from None


def flag(value, code=2):
    if type(value) is bool:
        return value
    if type(value) is str and value.lower() in ('true', 'false'):
        return value.lower() == 'true'
    raise Denied(code, 'INVALID_COLLECTOR_FLAG')


def names(value, pattern, code, reason):
    require(type(value) is list and all(type(x) is str and pattern.fullmatch(x)
                                        for x in value), code, reason)
    return value


def parse_scope(raw, forks=2):
    require(type(raw) is dict and all(type(k) is str for k in raw), 2, 'INVALID_SCOPE')
    require(raw.keys() <= RUN_FIELDS | FLAGS, 2, 'UNSUPPORTED_SCOPE_FIELD')
    hosts = names(raw.get('pqc_scan_hosts', []), HOST, 4, 'UNSAFE_TARGET_NAME')
    groups = names(raw.get('pqc_scan_groups', []), GROUP, 4, 'UNSAFE_TARGET_NAME')
    require(hosts or groups, 4, 'EMPTY_SCOPE')
    require(not any(x.lower() in RESERVED for x in hosts + groups), 4, 'RESERVED_TARGET')
    require(not any(loopback(x) for x in hosts + groups), 4, 'LOCAL_TARGET')
    cap = raw.get('pqc_max_hosts', 10)
    require(type(cap) is int and 1 <= cap <= 10, 2, 'INVALID_MAX_HOSTS')
    require(type(forks) is int and 1 <= forks <= 2, 2, 'INVALID_FORKS')
    run_id = raw.get('pqc_run_id')
    require('pqc_run_id' not in raw or type(run_id) is str and RUN_ID.fullmatch(run_id),
            2, 'INVALID_RUN_ID')
    profile = raw.get('pqc_scan_profile')
    opt_in = raw.get('pqc_active_opt_in', False)
    endpoints = raw.get('pqc_active_endpoints', [])
    require(type(opt_in) is bool and type(endpoints) is list, 2, 'INVALID_ACTIVE_INTENT')
    require(profile != 'active' and not opt_in and not endpoints, 2, 'PROFILE_INTEGRATION_REQUIRED')
    require('pqc_scan_profile' not in raw or profile in ('baseline', 'extended'), 2, 'INVALID_PROFILE')
    return {'hosts': hosts, 'groups': groups, 'max_hosts': cap, 'forks': forks,
            'run_id': run_id, 'profile': profile, 'plan_only': True,
            'run_flags': {k: flag(raw[k]) for k in sorted(FLAGS & raw.keys())},
            'active_opt_in': False, 'active_endpoints': []}


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 3, 'DUPLICATE_INVENTORY_KEY')
            result[key] = value
        return result

    def nonfinite(_value):
        raise Denied(3, 'INVALID_INVENTORY_JSON')

    try:
        # parse_float also rejects finite syntax which overflows to infinity.
        def finite_float(value):
            number = float(value)
            if not -float('inf') < number < float('inf'):
                nonfinite(value)
            return number
        return json.loads(data.decode('utf-8', errors='strict'), object_pairs_hook=pairs,
                          parse_constant=nonfinite, parse_float=finite_float)
    except (ValueError, RecursionError):
        raise Denied(3, 'INVALID_INVENTORY_JSON') from None


def loopback(value):
    value = value.lower().rstrip('.')
    if value in {'localhost', 'localhost.localdomain', 'localhost4', 'localhost6',
                 'localhost4.localdomain4', 'localhost6.localdomain6', 'ip6-localhost', 'ip6-loopback'}:
        return True
    address = value.strip('[]').split('%', 1)[0]
    try:
        ip = ipaddress.ip_address(address)
        return ip.is_loopback or ip.is_unspecified or bool(
            getattr(ip, 'ipv4_mapped', None) and (ip.ipv4_mapped.is_loopback or ip.ipv4_mapped.is_unspecified))
    except ValueError:
        # Recognize alternate numeric IPv4 spellings without DNS or sockets.
        try:
            packed = socket.inet_aton(address)
            return packed[0] == 127 or packed == b'\0' * 4
        except OSError:
            return False


def resolve_targets(inventory, request):
    """Validate one native, non-exported effective inventory and fix literal scope."""
    require(type(inventory) is dict, 3, 'INVALID_INVENTORY_STRUCTURE')
    meta = inventory.get('_meta')
    require(type(meta) is dict and meta.keys() <= {'hostvars', 'profile'}
            and ('profile' not in meta or meta['profile'] == 'inventory_legacy'),
            3, 'INVALID_INVENTORY_STRUCTURE')
    hostvars = meta.get('hostvars')
    require(type(hostvars) is dict and all(type(v) is dict for v in hostvars.values()),
            3, 'INVALID_INVENTORY_STRUCTURE')
    require(all(HOST.fullmatch(h) for h in hostvars), 4, 'UNSAFE_TARGET_NAME')
    graph, members = {}, {}
    for group, value in inventory.items():
        if group == '_meta':
            continue
        require(GROUP.fullmatch(group) is not None, 4, 'UNSAFE_TARGET_NAME')
        require(type(value) is dict and value.keys() <= {'hosts', 'children', 'vars'}
                and type(value.get('vars', {})) is dict, 3, 'INVALID_INVENTORY_STRUCTURE')
        children = names(value.get('children', []), GROUP, 3, 'INVALID_INVENTORY_STRUCTURE')
        hosts = names(value.get('hosts', []), HOST, 3, 'INVALID_INVENTORY_STRUCTURE')
        require(len(set(children)) == len(children) and len(set(hosts)) == len(hosts),
                3, 'INVALID_INVENTORY_STRUCTURE')
        graph[group], members[group] = children, hosts
    require('all' in graph, 3, 'INVALID_INVENTORY_STRUCTURE')
    # Native --list omits empty group objects but retains their parent references.
    # Referenced-only groups are known empty; they can never contribute a host.
    for child in {c for children in graph.values() for c in children} - graph.keys():
        graph[child], members[child] = [], []
    known_hosts = {h for hosts in members.values() for h in hosts}
    # The native formatter also omits hostvars entries for hosts with no vars.
    require(hostvars.keys() <= known_hosts, 3, 'INCONSISTENT_INVENTORY_HOSTS')
    # Iterative DFS: reject cycles and groups not reachable from native all.
    done, visiting = set(), set()
    stack = [('all', False)]
    while stack:
        group, leaving = stack.pop()
        if leaving:
            visiting.remove(group)
            done.add(group)
        elif group not in done:
            require(group not in visiting, 3, 'INVENTORY_CYCLE')
            visiting.add(group)
            stack.append((group, True))
            stack.extend((child, False) for child in reversed(graph[group]))
    require(done == graph.keys(), 3, 'ORPHAN_INVENTORY_GROUP')
    ungrouped = set(members.get('ungrouped', []))
    require(not graph.get('ungrouped') and not ungrouped.intersection(
        h for g, hs in members.items() if g not in ('all', 'ungrouped') for h in hs),
        3, 'INCONSISTENT_INVENTORY_HOSTS')
    require(all(h in known_hosts for h in request['hosts'])
            and all(g in graph for g in request['groups']), 4, 'UNKNOWN_TARGET')
    selected = set(request['hosts'])
    seen, pending = set(), list(request['groups'])
    while pending:
        group = pending.pop()
        if group not in seen:
            require(group.lower() not in RESERVED, 4, 'RESERVED_TARGET')
            seen.add(group)
            selected.update(members[group])
            pending.extend(graph[group])
    require(selected, 4, 'EMPTY_SCOPE')
    require(len(selected) <= request['max_hosts'], 4, 'HOST_LIMIT_EXCEEDED')
    targets, inventory_flags, connection_status = sorted(selected), {}, {}
    for host in targets:
        require(host.lower() not in RESERVED and not loopback(host), 4, 'LOCAL_TARGET')
        values = hostvars.get(host, {})
        for key in ('ansible_connection', 'ansible_host', 'ansible_ssh_host'):
            if key in values:
                value = values[key]
                require(type(value) is str and value.strip() == value and bool(value)
                        and not re.search(r'[\x00-\x20\x7f{}]', value), 4, 'UNRESOLVED_CONNECTION')
                if key == 'ansible_connection':
                    require(value.lower().rsplit('.', 1)[-1] != 'local', 4, 'LOCAL_TARGET')
                else:
                    require(not loopback(value), 4, 'LOCAL_TARGET')
        require(not values.keys() & (RUN_FIELDS | INTERNAL_FIELDS)
                and not any(k.startswith('pqc_write_') or k.startswith('pqc_collect_') and k not in FLAGS
                            for k in values), 4, 'INVENTORY_SCOPE_CONFLICT')
        inventory_flags[host] = {k: flag(values[k], 4) for k in sorted(FLAGS & values.keys())}
        connection_status[host] = 'DECLARED' if 'ansible_connection' in values else 'UNKNOWN'
    return targets, inventory_flags, connection_status


def build_plan(inventory, request):
    targets, flags, connection_status = resolve_targets(inventory, request)
    plan = {'scope_plan_version': 1, 'plan_status': 'READY', 'reason_code': 'TARGET_PLAN_READY',
            'plan_only': True, 'execution_allowed': False, 'active_dispatch_allowed': False,
            'target_ids': targets, 'target_count': len(targets),
            'limits': {'max_hosts': request['max_hosts'], 'forks': request['forks'],
                       'serial': 2, 'ssh_timeout_s': 15, 'command_timeout_s': 30},
            'run_flags': request['run_flags'], 'inventory_flags': flags,
            'inventory_flags_source': 'INVENTORY_EFFECTIVE', 'connection_status': connection_status,
            'active_opt_in': False, 'active_endpoints': []}
    for key in ('profile', 'run_id'):
        if request[key] is not None:
            plan[key] = request[key]
    return plan


def inventory_source(raw):
    try:
        require(bool(raw) and not re.search(r'[\x00-\x1f\x7f,{}\[\]*?$`;&|<>\\]', raw),
                4, 'UNSAFE_INVENTORY_SOURCE')
        path = Path(raw).resolve(strict=True)
        require(not re.search(r'[\x00-\x1f\x7f,{}\[\]*?$`;&|<>\\]', str(path))
                and path.is_file() and os.access(path, os.X_OK), 4, 'UNSAFE_INVENTORY_SOURCE')
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), 'rb') as stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode) and stream.read(2) == b'#!',
                    4, 'UNSAFE_INVENTORY_SOURCE')
        return str(path)
    except (OSError, RuntimeError, ValueError):
        raise Denied(4, 'UNSAFE_INVENTORY_SOURCE') from None


def reap_group(pgid):
    while True:
        try:
            pid, _ = os.waitpid(-pgid, os.WNOHANG)
            if not pid:
                return
        except ChildProcessError:
            return


def group_exists(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        raise Denied(3, 'INVENTORY_CLEANUP_UNCONFIRMED') from None


def bounded_command(argv, env, timeout=30, out_cap=OUT_BYTES, err_cap=ERR_BYTES):
    """Bound pipes and time; Linux controller reaps adopted same-group children.

    Trusted installed tools/provider must not detach. Not an OS sandbox.
    Reserve cleanup time within the command deadline, never dispatch on failure.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    old = ctypes.c_int()
    require(sys.platform.startswith('linux') and libc.prctl(37, ctypes.byref(old), 0, 0, 0) == 0
            and libc.prctl(36, 1, 0, 0, 0) == 0, 3, 'INVENTORY_PROCESS_CONTROL')
    deadline = time.monotonic() + timeout
    work_end = deadline - min(1.0, timeout / 2)
    proc = None
    quiescent = False
    try:
        proc = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True)
        buffers = [bytearray(), bytearray()]
        with selectors.DefaultSelector() as sel:
            for i, stream in enumerate((proc.stdout, proc.stderr)):
                sel.register(stream, selectors.EVENT_READ, i)
            while sel.get_map():
                remaining = work_end - time.monotonic()
                require(remaining > 0, 3, 'INVENTORY_TIMEOUT')
                for key, _ in sel.select(remaining):
                    data = os.read(key.fd, 65536)
                    if not data:
                        sel.unregister(key.fileobj)
                        continue
                    i = key.data
                    require(len(buffers[i]) + len(data) <= (out_cap, err_cap)[i],
                            3, 'INVENTORY_OUTPUT_LIMIT')
                    buffers[i].extend(data)
        rc = proc.wait(timeout=max(0, work_end - time.monotonic()))
        reap_group(proc.pid)
        require(not group_exists(proc.pid), 3, 'INVENTORY_RESIDUAL_PROCESS')
        quiescent = True
        return rc, bytes(buffers[0]), bytes(buffers[1])
    except subprocess.TimeoutExpired:
        raise Denied(3, 'INVENTORY_TIMEOUT') from None
    except OSError:
        raise Denied(3, 'INVENTORY_TOOL_ERROR') from None
    finally:
        try:
            if proc is not None:
                # Reap the direct child with Popen; adopted descendants with waitpid.
                # A leader which is still alive keeps the group identity pinned.
                if not quiescent and (proc.poll() is None or group_exists(proc.pid)):
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        proc.wait(timeout=max(0, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        raise Denied(3, 'INVENTORY_CLEANUP_UNCONFIRMED') from None
                    while True:
                        reap_group(proc.pid)
                        if not group_exists(proc.pid):
                            break
                        require(time.monotonic() < deadline, 3, 'INVENTORY_CLEANUP_UNCONFIRMED')
                        time.sleep(0.01)
                proc.stdout.close()
                proc.stderr.close()
        finally:
            require(libc.prctl(36, old.value, 0, 0, 0) == 0, 3, 'INVENTORY_PROCESS_CONTROL')


def check_diagnostics(stderr):
    try:
        text = ' '.join(stderr.decode('utf-8', errors='strict').lower().split())
    except UnicodeError:
        raise Denied(3, 'INVALID_INVENTORY_DIAGNOSTIC') from None
    # Match diagnostic families rather than exact versions' punctuation or paths.
    # Ordinary unrelated warnings and native lookup deprecation are not failures.
    failure = re.search(
        r'\btraceback\b|(?:^|\s)(?:error[!:]|fatal:)|\[error\]|'
        r'(?:failed|unable|could not|cannot|can not|cannot be)\s+(?:to\s+)?(?:parse|load|read|execute|decode)|'
        r'(?:inventory|script|plugin|json|parser|source).{0,240}'
        r'(?:failed|failure|non-zero|not (?:parsed|found|loaded)|could not|unable|invalid json|execution error)|'
        r'no inventory was parsed|only implicit localhost|no hosts matched|'
        r'declined parsing|not a valid inventory|skipping.{0,100}inventory source|'
        r'value could not be parsed as json|unable to get json decoder|completely failed to parse', text)
    require(not failure, 3, 'INVENTORY_PARSE_FAILURE')
    # Native stderr is normally empty, or consists of warning/deprecation records.
    # Unclassified diagnostics cannot authorize a plan.
    prefix = r'(?:\[(?:deprecation )?warning\]:?|warning:)'
    require(not text or re.match(r'^' + prefix, text), 3, 'UNKNOWN_INVENTORY_DIAGNOSTIC')
    for record in re.split(prefix, text)[1:]:
        if re.search(r'\b(?:inventory|parser|plugin|script|source)\b', record):
            # Known benign native warning: lookup mode is deprecated, not failed.
            # A successful script may otherwise emit arbitrary, ambiguous diagnostics.
            require('inventory scripts should always provide' in record
                    and 'host variables will be collected' in record
                    and "'--host' option" in record
                    and 'will be removed from inventory plugin' in record,
                    3, 'UNKNOWN_INVENTORY_DIAGNOSTIC')


def load_effective_inventory(source):
    source = inventory_source(source)
    inv = shutil.which('ansible-inventory')
    cfg = shutil.which('ansible-config')
    require(inv and cfg and Path(inv).absolute().parent == Path(cfg).absolute().parent,
            3, 'INVENTORY_TOOL_MISSING')
    env = dict(os.environ, **FATAL_ENV)
    if 'ANSIBLE_CONFIG' in env:
        require(bool(env['ANSIBLE_CONFIG']) and Path(env['ANSIBLE_CONFIG']).is_file(),
                3, 'INVENTORY_CONFIG_MISSING')
    rc, output, diagnostics = bounded_command([os.path.abspath(cfg), 'dump', '--format', 'json'], env)
    require(rc == 0, 3, 'INVENTORY_CONFIG_ERROR')
    check_diagnostics(diagnostics)
    config = strict_json(output)
    require(type(config) is list and all(type(x) is dict and (type(x.get('name')) is str
                                             or x.keys() == {'GALAXY_SERVERS'})
                                         for x in config), 3, 'INVENTORY_CONFIG_ERROR')
    settings = {}
    for item in config:
        if 'name' not in item:  # Native ansible-config includes a GALAXY_SERVERS record.
            continue
        name = item['name']
        require(name not in settings, 3, 'INVENTORY_CONFIG_ERROR')
        settings[name] = item.get('value')
    require(settings.get('INVENTORY_ENABLED') == ['script']
            and settings.get('INVENTORY_ANY_UNPARSED_IS_FAILED') is True
            and settings.get('INVENTORY_UNPARSED_IS_FAILED') is True, 3, 'INVENTORY_CONFIG_UNVERIFIED')
    rc, output, diagnostics = bounded_command([os.path.abspath(inv), '-i', source, '--list'], env)
    require(rc == 0, 3, 'INVENTORY_PROVIDER_ERROR')
    check_diagnostics(diagnostics)
    return strict_json(output)


PUBLIC_FIELDS = ('scope_plan_version', 'plan_status', 'reason_code', 'plan_only',
                 'execution_allowed', 'active_dispatch_allowed', 'target_ids', 'target_count')


def main(argv=None):
    try:
        source, request = parse_cli(sys.argv[1:] if argv is None else argv)
        plan = build_plan(load_effective_inventory(source), request)
        print(json.dumps({k: plan[k] for k in PUBLIC_FIELDS}, sort_keys=True))
        return 0
    except Denied as exc:
        print(exc.reason, file=sys.stderr)
        return exc.code
    except (OSError, ValueError, RecursionError, KeyboardInterrupt):
        print('INVENTORY_TOOL_ERROR', file=sys.stderr)
        return 3


if __name__ == '__main__':
    # Make a supported termination follow the same subprocess cleanup path.
    def terminate(_signum, _frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminate)
    sys.exit(main())
