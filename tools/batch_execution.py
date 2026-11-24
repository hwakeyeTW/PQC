"""Private S1 native context. No public entry point or managed dispatch.

This adapter is for an exclusive, trusted, isolated controller worker. The
private Ansible APIs below are version-gated; an unverified version is denied.
"""
import contextlib
import copy
import hashlib
import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import time


ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('_pqc_scope_contract', ROOT / 'tools/pqc_scan.py')
_scope = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_scope)
Denied = _scope.Denied
require = _scope.require
REQUEST = frozenset(('hosts', 'groups', 'max_hosts', 'forks', 'run_id', 'profile',
                     'plan_only', 'run_flags', 'active_opt_in', 'active_endpoints'))
CORE = '2.19.11'
_PROVIDER_SECONDS = 30
COMMAND = ':'  # fixed synthetic boundary witness, never executed by S1


def _request(value):
    require(type(value) is dict and value.keys() == REQUEST and value['plan_only'] is True,
            2, 'INVALID_BATCH_REQUEST')
    require(type(value['run_flags']) is dict and value['run_flags'].keys() <= _scope.FLAGS,
            2, 'INVALID_BATCH_REQUEST')
    raw = {'pqc_scan_hosts': value['hosts'], 'pqc_scan_groups': value['groups'],
           'pqc_max_hosts': value['max_hosts'], 'pqc_scan_profile': value['profile'],
           'pqc_active_opt_in': value['active_opt_in'], 'pqc_active_endpoints': value['active_endpoints'],
           **value['run_flags']}
    if value['run_id'] is not None:
        raw['pqc_run_id'] = value['run_id']
    normalized = _scope.parse_scope(raw, value['forks'])
    require(normalized == value and type(value['active_opt_in']) is bool
            and all(type(v) is bool for v in value['run_flags'].values()), 2, 'INVALID_BATCH_REQUEST')
    require(normalized['profile'] != 'active', 2, 'ACTIVE_NOT_AVAILABLE_V2_0')
    return copy.deepcopy(normalized)


@contextlib.contextmanager
def _quiet():
    # Exclusive worker only. Do not forward native diagnostics or raw options.
    with open(os.devnull, 'w', encoding='utf-8') as sink:
        with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
            try:
                yield
            except Denied:
                raise
            except (Exception, SystemExit):
                raise Denied(3, 'NATIVE_CONTEXT_ERROR') from None


def _source_identity(path):
    try:
        p = Path(path)
        s = p.stat()
        require(p.resolve(strict=True) == p and stat.S_ISREG(s.st_mode), 4, 'UNSAFE_INVENTORY_SOURCE')
        return s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns
    except (OSError, ValueError):
        raise Denied(4, 'UNSAFE_INVENTORY_SOURCE') from None


def _native(source):
    # Fatal controls must be established before importing Ansible in the worker.
    require(all(os.environ.get(k) == v for k, v in _scope.FATAL_ENV.items()),
            3, 'INVENTORY_CONFIG_UNVERIFIED')
    import ansible
    from ansible import constants as C, context
    from ansible.inventory.manager import InventoryManager
    from ansible.parsing.dataloader import DataLoader
    from ansible.plugins.loader import init_plugin_loader, inventory_loader
    from ansible.vars.manager import VariableManager
    from ansible.plugins.inventory import script

    require(ansible.__version__ == CORE and C.INVENTORY_ENABLED == ['script']
            and C.INVENTORY_ANY_UNPARSED_IS_FAILED is True and C.INVENTORY_UNPARSED_IS_FAILED is True
            and C.CACHE_PLUGIN == 'memory' and not C.DEFAULT_LOG_PATH and not C.DEFAULT_DEBUG
            and not context.CLIARGS.get('extra_vars'), 3, 'NATIVE_CONTEXT_UNVERIFIED')
    require(set(C.VARIABLE_PLUGINS_ENABLED) <= {'host_group_vars', 'ansible.builtin.host_group_vars'},
            3, 'NATIVE_CONTEXT_UNVERIFIED')
    require(not os.environ.get('SSH_AUTH_SOCK'), 3, 'NATIVE_CONTEXT_UNVERIFIED')
    from ansible.utils.collection_loader import AnsibleCollectionConfig
    if AnsibleCollectionConfig.collection_finder is None:
        init_plugin_loader()
    plugin = inventory_loader.get('script')
    require(type(plugin) is script.InventoryModule, 3, 'NATIVE_CONTEXT_UNVERIFIED')
    loader = DataLoader()
    # Keep native vars-loader precedence; do not synthesize/merge hostvars.
    before = _source_identity(source)
    deadline = time.monotonic() + _PROVIDER_SECONDS
    remaining_bytes = _scope.OUT_BYTES
    calls = set()
    failure = []
    original = script.run_command

    def call_provider(path, options, origin):
        nonlocal remaining_bytes
        key = tuple(options)
        require(path == source and _source_identity(source) == before
                and (key == ('--list',) or len(key) == 2 and key[0] == '--host'
                     and _scope.HOST.fullmatch(key[1])) and key not in calls
                and (not calls or ('--list',) in calls), 3, 'INVENTORY_SOURCE_DRIFT')
        calls.add(key)
        left = deadline - time.monotonic()
        require(left > 1 and remaining_bytes > 0, 3, 'INVENTORY_TIMEOUT')
        rc, out, err = _scope.bounded_command([source, *options], dict(os.environ),
                                               timeout=left, out_cap=remaining_bytes)
        remaining_bytes -= len(out)
        require(rc == 0 and not err.strip(), 3, 'INVENTORY_PROVIDER_ERROR')
        if key != ('--list',) and not out.strip():
            out = b'{}'
        raw = _scope.strict_json(out)
        require(type(raw) is dict, 3, 'INVALID_INVENTORY_STRUCTURE')
        if key == ('--list',):
            meta = raw.get('_meta', {})
            require(type(meta) is dict and meta.get('profile', 'inventory_legacy') == 'inventory_legacy',
                    3, 'INVALID_INVENTORY_STRUCTURE')
        # Feed original validated bytes into the real script parser. Keep its
        # native tags, group graph, --host lookup and vars machinery intact.
        return script.TrustedAsTemplate().tag(origin.tag(out.decode('utf-8'))), '', None

    def bounded(path, options, origin):
        try:
            return call_provider(path, options, origin)
        except Denied as exc:
            failure.append(exc)
            raise

    try:
        script.run_command = bounded
        try:
            inventory = InventoryManager(loader=loader, sources=[source], cache=False)
        except Exception:
            if failure:
                raise failure[0] from None
            raise
    finally:
        script.run_command = original
    if failure:
        raise failure[0] from None
    require(('--list',) in calls and _source_identity(source) == before,
            3, 'INVENTORY_SOURCE_DRIFT')
    variables = VariableManager(loader=loader, inventory=inventory)
    require(not variables.extra_vars, 2, 'INVALID_EXTRA_VARS')
    return loader, inventory, variables, before


def _scalar(value):
    # Native data tags subclass str/int. Strip only tags on selected scalars,
    # never stringify a complex value, coerce an int to bool or evaluate Jinja.
    if isinstance(value, str):
        return str(value)
    if type(value) is bool or value is None:
        return value
    if isinstance(value, int):
        return int(value)
    return value


def _project(inventory, variables, request):
    graph = {str(name): {'hosts': [str(h.name) for h in group.hosts],
                         'children': [str(g.name) for g in group.child_groups]}
             for name, group in inventory.groups.items()}
    graph['_meta'] = {'hostvars': {}}
    targets, _, _ = _scope.resolve_targets(graph, request)
    require(all(h in inventory.hosts for h in targets), 4, 'UNKNOWN_TARGET')
    for name in targets:
        values = variables.get_vars(host=inventory.hosts[name], include_hostvars=False, use_cache=False)
        keys = {k for k in values if isinstance(k, str) and
                (k in _scope.FLAGS | _scope.RUN_FIELDS | _scope.INTERNAL_FIELDS
                 or k.startswith(('pqc_write_', 'pqc_collect_'))
                 or k in ('ansible_connection', 'ansible_host', 'ansible_ssh_host'))}
        graph['_meta']['hostvars'][name] = {str(k): _scalar(values[k]) for k in keys}
    targets, flags, _ = _scope.resolve_targets(graph, request)
    decisions = _scope.profile_plan(targets, flags, request)['profile_decisions']
    return tuple(targets), flags, decisions


def _literal(value):
    require(isinstance(value, str) and len(value) <= 4096
            and not re.search(r'[\x00-\x1f\x7f]|\{\{|\{%|\{#', value), 4, 'UNRESOLVED_CONNECTION')
    return str(value)


def _address(value):
    value = _literal(value)
    try:
        ipaddress.ip_address(value)
        valid = True
    except ValueError:
        valid = bool(_scope.HOST.fullmatch(value))
    require(valid and not _scope.loopback(value), 4, 'LOCAL_OR_UNSAFE_CONNECTION')
    return value


def _native_binding(ctx, name):
    from ansible import constants as C
    from ansible.executor.task_executor import TaskExecutor
    from ansible.playbook.play import Play
    from ansible.playbook.play_context import PlayContext
    from ansible.playbook.task import Task
    from ansible.plugins.loader import connection_loader
    from ansible.plugins.connection import ssh
    from ansible.template import Templar

    host = ctx._inventory.hosts[name]
    # Fixed task contract; no user-provided task, delegate, vars, loop or role.
    play = Play.load({'hosts': list(ctx._targets), 'gather_facts': False,
                      'connection': 'ssh', 'become': False},
                     variable_manager=ctx._variables, loader=ctx._loader)
    task = Task.load({'ansible.builtin.raw': COMMAND, 'connection': 'ssh', 'become': False,
                      'no_log': True}, variable_manager=ctx._variables, loader=ctx._loader)
    values = ctx._variables.get_vars(play=play, host=host, task=task, include_hostvars=False, use_cache=False)
    # Do not evaluate connection-related templates or permit a variable to
    # select a plugin before the guard. Other unconsumed hostvars stay private.
    for key, value in values.items():
        if isinstance(key, str) and key.startswith('ansible_') and isinstance(value, str):
            _literal(value)
    require(values.get('ansible_connection', 'ssh') in ('ssh', 'ansible.builtin.ssh')
            and _scope.flag(_scalar(values.get('ansible_become', False)), 4) is False
            and not values.get('ansible_delegated_vars'), 4, 'CONNECTION_POLICY_DENIED')
    require(values.get('ansible_shell_type', 'sh') in ('sh', 'ansible.builtin.sh')
            and values.get('ansible_shell_executable', '/bin/sh') == '/bin/sh',
            4, 'CONNECTION_POLICY_DENIED')
    templar = Templar(loader=ctx._loader, variables=values)
    pc = PlayContext(play=play).set_task_and_variable_override(task=task, variables=values, templar=templar)
    pc.post_validate(templar=templar)
    if not pc.remote_addr:
        pc.remote_addr = host.address
    require(pc.connection in ('ssh', 'ansible.builtin.ssh') and pc.become is False,
            4, 'CONNECTION_POLICY_DENIED')
    _address(pc.remote_addr)
    require(not pc.password, 4, 'CONNECTION_POLICY_DENIED')
    loaded = connection_loader.get_with_context('ansible.builtin.ssh', pc, new_stdin=None,
                                                 task_uuid=task._uuid, ansible_playbook_pid=os.getpid())
    conn = loaded.object
    import inspect
    require(type(conn).__name__ == 'Connection' and Path(inspect.getfile(type(conn))).resolve() == Path(ssh.__file__).resolve(),
            3, 'NATIVE_CONTEXT_UNVERIFIED')
    conn.set_become_plugin(None)
    # Use the actual native executor option resolution, not a parallel
    # hand-written inventory/ini/env precedence implementation.
    executor = TaskExecutor.__new__(TaskExecutor)
    executor._task, executor._play_context, executor._connection = task, pc, conn
    consumed = set(C.config.get_plugin_vars('connection', conn._load_name))
    consumed.update(C.config.get_plugin_vars('shell', conn._shell._load_name))
    require(all(_scalar(values[k]) is None or type(_scalar(values[k])) in (str, bool, int)
                for k in consumed & values.keys()), 4, 'UNRESOLVED_CONNECTION')
    executor._set_connection_options(values, templar)
    require(conn.become is None and not task.delegate_to and not task.run_once
            and not task.loop and task.action == 'ansible.builtin.raw', 4, 'CONNECTION_POLICY_DENIED')
    return conn


# Only an explicit existing SSH config with a closed, non-executing subset is
# eligible for S1. Do not rewrite SSH configuration or silently disable options.
_OPTION = frozenset(('port', 'user', 'identityfile', 'identitiesonly', 'stricthostkeychecking',
                     'userknownhostsfile', 'globalknownhostsfile', 'connecttimeout', 'batchmode',
                     'controlmaster', 'controlpath', 'proxyjump', 'canonicalizehostname',
                     'passwordauthentication', 'kbdinteractiveauthentication', 'preferredauthentications',
                     'compression', 'loglevel', 'serveraliveinterval', 'serveralivecountmax', 'numberofpasswordprompts'))


def _option(key, value):
    key, value = key.lower(), _literal(value)
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    require(key in _OPTION and value and re.fullmatch(r'[A-Za-z0-9_./@:,=*-]+', value),
            4, 'UNSUPPORTED_SSH_OPTION')
    if key in ('port', 'connecttimeout', 'serveraliveinterval', 'serveralivecountmax'):
        require(value.isdecimal(), 4, 'UNSUPPORTED_SSH_OPTION')
        number = int(value)
        require((1 <= number <= 65535 if key == 'port' else 1 <= number <= 15
                 if key == 'connecttimeout' else 0 <= number <= 60), 4, 'UNSUPPORTED_SSH_OPTION')
    elif key == 'numberofpasswordprompts':
        require(value == '1', 4, 'UNSUPPORTED_SSH_OPTION')
    elif key == 'user':
        require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}', value), 4, 'UNSUPPORTED_SSH_OPTION')
    elif key == 'stricthostkeychecking':
        require(value.lower() in ('yes', 'ask'), 4, 'HOST_KEY_CHECKING_REQUIRED')
    elif key in ('controlmaster', 'canonicalizehostname', 'passwordauthentication', 'kbdinteractiveauthentication'):
        require(value.lower() == 'no', 4, 'UNSUPPORTED_SSH_OPTION')
    elif key == 'batchmode':
        require(value.lower() == 'yes', 4, 'UNSUPPORTED_SSH_OPTION')
    elif key == 'controlpath':
        require(value.lower() == 'none', 4, 'UNSUPPORTED_SSH_OPTION')
    elif key in ('identityfile', 'userknownhostsfile', 'globalknownhostsfile'):
        p = Path(value)
        require(p.is_absolute() and p.resolve() != Path('/dev/null'), 4, 'UNSUPPORTED_SSH_OPTION')
    elif key == 'proxyjump':
        if value.lower() != 'none':
            for jump in value.split(','):
                match = re.fullmatch(r'(?:([A-Za-z_][A-Za-z0-9_.-]{0,63})@)?([A-Za-z0-9][A-Za-z0-9.-]*)(?::([0-9]+))?', jump)
                require(match is not None, 4, 'UNSUPPORTED_SSH_OPTION')
                _address(match[2])
                require(match[3] is None or 1 <= int(match[3]) <= 65535, 4, 'UNSUPPORTED_SSH_OPTION')
    return key, value


def _args(tokens):
    configs, options = [], []
    i = 0
    while i < len(tokens):
        arg = _literal(tokens[i])
        i += 1
        if arg == '-C':
            continue
        require(arg in ('-F', '-o') and i < len(tokens), 4, 'UNSUPPORTED_SSH_OPTION')
        value = _literal(tokens[i])
        i += 1
        if arg == '-F':
            require(re.fullmatch(r'/[A-Za-z0-9_./-]+', value), 4, 'SSH_CONFIG_UNVERIFIED')
            configs.append(value)
        else:
            key, sep, val = value.partition('=')
            require(sep == '=', 4, 'UNSUPPORTED_SSH_OPTION')
            options.append(_option(key, val))
    require(len(configs) == 1, 4, 'SSH_CONFIG_UNVERIFIED')
    return configs[0], tuple(options)


def _config(path):
    # Explicit -F avoids implicit user/system Include/Match exec. A config
    # outside this initial audited subset is denied, never edited.
    p = Path(path)
    try:
        require(p.is_absolute() and p.resolve(strict=True) == p, 4, 'SSH_CONFIG_UNVERIFIED')
        with os.fdopen(os.open(p, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), 'rb') as f:
            require(stat.S_ISREG(os.fstat(f.fileno()).st_mode), 4, 'SSH_CONFIG_UNVERIFIED')
            raw = f.read(65537)
        require(len(raw) <= 65536, 4, 'SSH_CONFIG_UNVERIFIED')
        require(not re.search(rb'[\x00-\x08\x0b-\x1f\x7f]', raw), 4, 'SSH_CONFIG_UNVERIFIED')
        for line in raw.decode('ascii').splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            require(re.fullmatch(r'[A-Za-z0-9_./@:,=*-]+(?:[ \t]+[A-Za-z0-9_./@:,=*-]+)+', line.strip()),
                    4, 'SSH_CONFIG_UNVERIFIED')
            parts = line.split()
            require(len(parts) == 2, 4, 'SSH_CONFIG_UNVERIFIED')
            if parts[0].lower() == 'host':
                require(parts[1] == '*' or _scope.HOST.fullmatch(parts[1]), 4, 'SSH_CONFIG_UNVERIFIED')
            else:
                _option(*parts)
        return hashlib.sha256(raw).hexdigest()
    except (OSError, UnicodeError, ValueError):
        raise Denied(4, 'SSH_CONFIG_UNVERIFIED') from None


def _native_argv(conn):
    require(conn.get_option('host_key_checking') is True and conn.become is None,
            4, 'HOST_KEY_CHECKING_REQUIRED')
    require(not any(conn.get_option(k) for k in ('password', 'private_key', 'private_key_passphrase',
                                                 'pkcs11_provider', 'reconnection_retries')),
            4, 'CONNECTION_POLICY_DENIED')
    binary = conn.get_option('ssh_executable')
    require(binary in ('ssh', '/usr/bin/ssh'), 4, 'UNSUPPORTED_SSH_EXECUTABLE')
    tokens = []
    for k in ('ssh_args', 'ssh_common_args', 'ssh_extra_args'):
        tokens.extend(shlex.split(_literal(conn.get_option(k) or '')))
    path, _ = _args(tokens)  # reject unsafe inputs before native builder side effects
    fingerprint = _config(path)
    host = _address(conn.get_option('host') or conn._play_context.remote_addr)
    conn.host = host
    argv = tuple(conn._build_command(binary, 'ssh', host, COMMAND))
    actual_path, _ = _args([x.decode('utf-8') for x in argv[1:-2]])
    require(actual_path == path and argv[-2:] == (host.encode(), COMMAND.encode()), 4, 'CONNECTION_POLICY_DENIED')
    return argv, fingerprint


def _effective_ssh(argv, fingerprint):
    """Verify the exact native argv with actual OpenSSH -G; never run a remote command."""
    path, _ = _args([x.decode('utf-8') for x in argv[1:-2]])
    require(_config(path) == fingerprint, 4, 'CONNECTION_CONTEXT_DRIFT')
    binary = Path('/usr/bin/ssh')
    selected = shutil.which(os.fsdecode(argv[0]))
    require(binary.is_file() and os.access(binary, os.X_OK) and selected is not None
            and Path(selected).resolve() == binary.resolve(), 3, 'OPENSSH_EFFECTIVE_CONFIG_UNAVAILABLE')
    # -G evaluates configuration without connecting. The restricted explicit
    # config/argv disallow Match exec, Include, ProxyCommand and forwarding.
    def dump(args):
        rc, out, _ = _scope.bounded_command([str(binary), '-G', *args], dict(os.environ),
                                             timeout=5, out_cap=65536, err_cap=65536)
        require(rc == 0, 3, 'OPENSSH_EFFECTIVE_CONFIG_UNAVAILABLE')
        entries = {}
        for line in out.decode('utf-8').splitlines():
            key, sep, val = line.partition(' ')
            require(sep and key and val, 3, 'OPENSSH_EFFECTIVE_CONFIG_UNAVAILABLE')
            entries.setdefault(key, []).append(val)
        def one(key, allowed):
            require(len(entries.get(key, [])) == 1 and entries[key][0] in allowed,
                    4, 'UNSUPPORTED_SSH_EFFECTIVE_CONFIG')
        one('hostname', [args[-1]])
        for key in ('user', 'port', 'connecttimeout'):
            require(len(entries.get(key, [])) == 1, 4, 'UNSUPPORTED_SSH_EFFECTIVE_CONFIG')
            _option(key, entries[key][0])
        _address(entries['hostname'][0])
        one('stricthostkeychecking', ('yes', 'ask', 'true'))
        one('controlmaster', ('no', 'false'))
        one('controlpersist', ('no', '0', 'false'))
        one('canonicalizehostname', ('no', 'false'))
        one('batchmode', ('yes', 'true'))
        for key in ('forwardagent', 'forwardx11', 'permitlocalcommand'):
            one(key, ('no', 'false'))
        for key in ('identityfile', 'userknownhostsfile', 'globalknownhostsfile'):
            require(entries.get(key), 4, 'UNSUPPORTED_SSH_EFFECTIVE_CONFIG')
            for record in entries[key]:
                for value in record.split():
                    p = Path(value).expanduser()
                    require(p.is_absolute() and p.resolve() != Path('/dev/null')
                            and value.lower() != 'none', 4, 'UNSUPPORTED_SSH_EFFECTIVE_CONFIG')
        require(not entries.get('proxycommand') or entries['proxycommand'] == ['none'],
                4, 'UNSUPPORTED_SSH_EFFECTIVE_CONFIG')
        require(not entries.get('localcommand') and not entries.get('remoteforward')
                and not entries.get('localforward') and not entries.get('dynamicforward'),
                4, 'UNSUPPORTED_SSH_EFFECTIVE_CONFIG')
        return entries, hashlib.sha256(out).hexdigest()
    args = [x.decode('utf-8') for x in argv[1:-1]]
    effective, digest = dump(args)
    jumps = effective.get('proxyjump', ['none'])
    require(len(jumps) == 1, 4, 'UNSUPPORTED_SSH_EFFECTIVE_CONFIG')
    _option('proxyjump', jumps[0])
    proofs = [digest]
    if jumps[0] != 'none':
        for jump in jumps[0].split(','):
            userhost, port = (jump.rsplit(':', 1) if ':' in jump else (jump, None))
            user, host = (userhost.split('@', 1) if '@' in userhost else (None, userhost))
            ja = ['-F', path]
            if port:
                ja += ['-o', 'Port=' + port]
            if user:
                ja += ['-o', 'User=' + user]
            j, proof = dump(ja + [host])
            require(j.get('proxyjump', ['none']) == ['none'], 4, 'UNSUPPORTED_SSH_EFFECTIVE_CONFIG')
            proofs.append(proof)
    require(_config(path) == fingerprint, 4, 'CONNECTION_CONTEXT_DRIFT')
    return tuple(proofs)


class _Context:
    """Private object graph, never a serialized plan or reusable public grant."""
    __slots__ = ('_loader', '_inventory', '_variables', '_source', '_source_id',
                 '_request', '_targets', '_flags', '_decisions', '_bound', '_proofs')

    def __init__(self, source, request):
        self._request = _request(request)
        self._source = _scope.inventory_source(source)
        with _quiet():
            self._loader, self._inventory, self._variables, self._source_id = _native(self._source)
            self._targets, self._flags, self._decisions = _project(self._inventory, self._variables, self._request)
        self._bound = {}
        self._proofs = {}

    def _preflight(self):
        self._bound, self._proofs = {}, {}
        with _quiet():
            require(_source_identity(self._source) == self._source_id, 4, 'CONNECTION_CONTEXT_DRIFT')
            bindings, proofs = {}, {}
            for name in self._targets:
                conn = _native_binding(self, name)
                argv, fingerprint = _native_argv(conn)
                proofs[name] = (argv, fingerprint, _effective_ssh(argv, fingerprint))
                bindings[name] = conn
            self._bound, self._proofs = bindings, proofs

    def _boundary(self, name):
        """S1 guarded native SSH argv boundary; deliberately no dispatch."""
        with _quiet():
            require(name in self._targets and self._bound.keys() == set(self._targets)
                    and self._proofs.keys() == set(self._targets), 4, 'BATCH_GUARD_DENIED')
            require(_source_identity(self._source) == self._source_id
                    and _project(self._inventory, self._variables, self._request)
                    == (self._targets, self._flags, self._decisions), 4, 'CONNECTION_CONTEXT_DRIFT')
            # Recheck the whole batch, then compare the actual consumed argv at
            # the native plugin's _run boundary. Never call its original _run.
            for target in self._targets:
                argv, fingerprint = _native_argv(_native_binding(self, target))
                require((argv, fingerprint, _effective_ssh(argv, fingerprint)) == self._proofs[target],
                        4, 'CONNECTION_CONTEXT_DRIFT')
            conn = self._bound[name]
            expected = self._proofs[name]
            original = conn._run

            def guarded(argv, in_data, sudoable=True, checkrc=True):
                require(in_data is None and sudoable is False and conn.become is None
                        and tuple(argv) == expected[0]
                        and _effective_ssh(tuple(argv), expected[1]) == expected[2],
                        4, 'BATCH_GUARD_DENIED')
                return _stop_s1()

            try:
                conn._run = guarded
                return conn.exec_command(COMMAND, sudoable=False)
            finally:
                conn._run = original


def _stop_s1():
    raise Denied(2, 'LIVE_NOT_AVAILABLE')
