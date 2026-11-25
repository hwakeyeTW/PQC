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
import tempfile
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


def _config_bytes(path):
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
        return raw
    except (OSError, UnicodeError, ValueError):
        raise Denied(4, 'SSH_CONFIG_UNVERIFIED') from None


def _config(path):
    return hashlib.sha256(_config_bytes(path)).hexdigest()


@contextlib.contextmanager
def _validated_snapshot(path, fingerprint):
    # Bind the bounded, validated read to what OpenSSH will actually open.
    # Reopening the original pathname after a hash check is not safe: a
    # transient edit can disappear before a subsequent hash check.
    raw = _config_bytes(path)
    require(hashlib.sha256(raw).hexdigest() == fingerprint, 4, 'CONNECTION_CONTEXT_DRIFT')
    try:
        temporary = tempfile.TemporaryDirectory(prefix='pqc-ssh-', dir='/tmp')
    except OSError:
        raise Denied(4, 'SSH_CONFIG_SNAPSHOT_ERROR') from None
    try:
        try:
            directory = Path(temporary.name)
            ds = directory.lstat()
            require(directory.resolve(strict=True) == directory and stat.S_ISDIR(ds.st_mode)
                    and stat.S_IMODE(ds.st_mode) == 0o700 and ds.st_uid == os.geteuid(),
                    4, 'SSH_CONFIG_SNAPSHOT_ERROR')
            snapshot = directory / 'config'
            # No caller-selected destination, existing file or symlink. This
            # private file is shared only by the bounded consumers in this
            # trusted worker, not by inventory/provider or maintenance paths.
            flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            with os.fdopen(os.open(snapshot, flags, 0o600), 'w+b') as f:
                fs = os.fstat(f.fileno())
                require(stat.S_ISREG(fs.st_mode) and stat.S_IMODE(fs.st_mode) == 0o600
                        and fs.st_uid == os.geteuid() and fs.st_nlink == 1,
                        4, 'SSH_CONFIG_SNAPSHOT_ERROR')
                require(f.write(raw) == len(raw), 4, 'SSH_CONFIG_SNAPSHOT_ERROR')
                f.flush()
                f.seek(0)
                require(f.read(65537) == raw, 4, 'SSH_CONFIG_SNAPSHOT_ERROR')
        except (OSError, ValueError):
            raise Denied(4, 'SSH_CONFIG_SNAPSHOT_ERROR') from None
        yield str(snapshot)
    finally:
        # Cleanup must complete before any proof can be returned; errors are
        # a closed failure, including after a successful final consumer.
        try:
            temporary.cleanup()
        except OSError:
            raise Denied(4, 'SSH_CONFIG_SNAPSHOT_CLEANUP_FAILED') from None


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
        require(_config(path) == fingerprint, 4, 'CONNECTION_CONTEXT_DRIFT')
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
    with _validated_snapshot(path, fingerprint) as snapshot:
        args = [x.decode('utf-8') for x in argv[1:-1]]
        # _args validated exactly one separate -F argument. Only the -G
        # assessment uses the snapshot; retain original native argv/path for
        # the binding and late-drift guard. Preserve all other options/order.
        args[args.index('-F') + 1] = snapshot
        effective, digest = dump(args)
        jumps = effective.get('proxyjump', ['none'])
        require(len(jumps) == 1, 4, 'UNSUPPORTED_SSH_EFFECTIVE_CONFIG')
        _option('proxyjump', jumps[0])
        proofs = [digest]
        if jumps[0] != 'none':
            for jump in jumps[0].split(','):
                userhost, port = (jump.rsplit(':', 1) if ':' in jump else (jump, None))
                user, host = (userhost.split('@', 1) if '@' in userhost else (None, userhost))
                ja = ['-F', snapshot]
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
                 '_request', '_targets', '_flags', '_decisions', '_bound', '_proofs', '_batch_used')

    def __init__(self, source, request):
        self._batch_used = False
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
                expected = self._proofs[target]
                require((argv, fingerprint) == expected[:2], 4, 'CONNECTION_CONTEXT_DRIFT')
                require(_effective_ssh(argv, fingerprint) == expected[2], 4, 'CONNECTION_CONTEXT_DRIFT')
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


# S2: version-gated native queue execution; product transport remains closed.
import json
import signal
import sys

_GUARD_SECONDS = 30
_SSH_SECONDS = 15
_COMMAND_SECONDS = 30
_WORKER_GRACE = 2
_QUEUE_BYTES = 3500
_COLLECTORS = tuple(sorted(_scope.FLAGS))
_PASSIVE = frozenset(_COLLECTORS) - {'pqc_collect_tls_services'}
_VALID = frozenset(('COLLECTED', 'NOT_APPLICABLE', 'PARTIAL'))
_FULL = frozenset(('COLLECTED', 'NOT_APPLICABLE'))
# A requested, unavailable adapter is a gap, not a successful empty result.
_OUTCOMES = {
    'COLLECTED': frozenset(('COLLECTED',)),
    'NOT_APPLICABLE': frozenset(('NOT_APPLICABLE',)),
    'PARTIAL': frozenset(('INCOMPLETE_COLLECTION',)),
    'UNKNOWN': frozenset(('UNKNOWN_RESULT',)),
    'PERMISSION_DENIED': frozenset(('PERMISSION_DENIED',)),
    'ERROR': frozenset(('COMMAND_FAILED', 'COMMAND_TIMEOUT', 'COMMAND_OUTPUT_LIMIT',
                        'COMMAND_START_FAILED', 'COMMAND_IO_FAILED', 'RESIDUAL_PROCESS',
                        'REMOTE_CLEANUP_UNCONFIRMED', 'INVALID_ADAPTER_RESULT',
                        'PROCESS_CONTROL_UNAVAILABLE', 'INVALID_COMMAND_CONTRACT',
                        'INTERRUPTED', 'OUTCOME_UNKNOWN', 'CONNECTION_TIMEOUT')),
    'UNREACHABLE': frozenset(('CONNECTION_FAILED',)),
    'NOT_SCANNED': frozenset(('DISABLED', 'ADAPTER_NOT_AVAILABLE',
                              'NO_EXECUTABLE_COLLECTORS', 'NOT_DISPATCHED',
                              'GUARD_REJECTED', 'STOPPED', 'INTERRUPTED')),
}
_FATAL = frozenset(('REMOTE_CLEANUP_UNCONFIRMED', 'INVALID_ADAPTER_RESULT',
                    'PROCESS_CONTROL_UNAVAILABLE', 'INVALID_COMMAND_CONTRACT',
                    'GUARD_REJECTED', 'OUTCOME_UNKNOWN', 'INVALID_NATIVE_RESULT',
                    'CONTROLLER_TIMEOUT', 'CONTROLLER_CLEANUP_UNCONFIRMED', 'CONTROLLER_WORKER_FAILED', 'INTERRUPTED'))
_HOST_REASONS = frozenset(('COMPLETE', 'INCOMPLETE_COLLECTION', 'NO_VALID_RESULT',
                           'CONNECTION_FAILED', 'CONNECTION_TIMEOUT', 'NO_EXECUTABLE_COLLECTORS',
                           'NOT_DISPATCHED', 'STOPPED')) | _FATAL
_RUN_REASONS = frozenset(('COMPLETE', 'INCOMPLETE_COLLECTION', 'NO_VALID_RESULT',
                          'NO_EXECUTABLE_COLLECTORS')) | _FATAL


def _passive_adapters():
    # Deliberately empty until producer-specific integration and qualification.
    # No public parameter, environment, hostvar, plan or entry point selects a
    # callable. Only test code in an isolated trusted worker replaces this.
    return {}


def _restricted_connection(name):
    # No production transport, including a localhost fallback.
    raise Denied(2, 'LIVE_NOT_AVAILABLE')


def _outcome(flag, requested, state, reason, rc=None, ids=()):
    return {'collector_id': flag, 'requested': requested, 'state': state,
            'reason_code': reason, 'rc': rc, 'collection_ids': list(ids)}


def _valid_outcome(row, flag, requested):
    if (type(row) is not dict or row.keys() != {'collector_id', 'requested', 'state',
                                                'reason_code', 'rc', 'collection_ids'}
            or row['collector_id'] != flag or row['requested'] is not requested
            or type(row['state']) is not str or row['state'] not in _OUTCOMES
            or type(row['reason_code']) is not str or row['reason_code'] not in _OUTCOMES[row['state']]):
        return False
    rc, ids = row['rc'], row['collection_ids']
    if ((rc is not None and (type(rc) is not int or not -255 <= rc <= 255))
            or type(ids) is not list or len(ids) > 8
            or any(type(x) is not str or not re.fullmatch(r'c-[0-9a-f]{64}', x) for x in ids)
            or ids != sorted(set(ids))):
        return False
    state, reason = row['state'], row['reason_code']
    if not requested:
        return state == 'NOT_SCANNED' and reason == 'DISABLED' and rc is None and not ids
    if state == 'NOT_SCANNED':
        return reason != 'DISABLED' and rc is None and not ids
    if state == 'UNREACHABLE':
        return rc is None and not ids
    if state == 'COLLECTED':
        return rc == 0
    if state == 'NOT_APPLICABLE':
        return rc in (None, 0)
    if state == 'ERROR' and reason == 'COMMAND_FAILED':
        return rc is not None and rc != 0
    return True


def _host(name, attempted, collectors, special=None):
    requested = [r for r in collectors if r['requested']]
    usable = any(r['state'] in _VALID for r in requested)
    if not attempted:
        state, reason = 'NOT_ATTEMPTED', special or 'NO_EXECUTABLE_COLLECTORS'
    elif special == 'CONNECTION_FAILED':
        state, reason = 'UNREACHABLE', special
    elif special in _FATAL or special == 'CONNECTION_TIMEOUT':
        # An unconfirmed remote cleanup is ERROR, even if an earlier slot
        # acquired data. Retain those typed slot outcomes without claiming a
        # safely completed host.
        state, reason = 'ERROR', special
    elif requested and all(r['state'] in _FULL for r in requested):
        state, reason = 'COMPLETE', 'COMPLETE'
    elif usable:
        state, reason = 'PARTIAL', 'INCOMPLETE_COLLECTION'
    else:
        state, reason = 'ERROR', 'NO_VALID_RESULT'
    return {'target_id': name, 'host_state': state, 'attempted': attempted,
            'reason_code': reason, 'collectors': collectors}


def _blank(name, flags, reason, attempted=False):
    if attempted:
        rows = [_outcome(f, flags[f], 'ERROR', 'OUTCOME_UNKNOWN') if flags[f]
                else _outcome(f, False, 'NOT_SCANNED', 'DISABLED') for f in _COLLECTORS]
    else:
        gap = reason if reason in _OUTCOMES['NOT_SCANNED'] else 'STOPPED'
        rows = [_outcome(f, flags[f], 'NOT_SCANNED', gap if flags[f] else 'DISABLED')
                for f in _COLLECTORS]
    return _host(name, attempted, rows, reason)


def _valid_host(row, name, flags):
    if (type(row) is not dict or row.keys() != {'target_id', 'host_state', 'attempted',
                                                'reason_code', 'collectors'}
            or row['target_id'] != name or type(row['attempted']) is not bool
            or type(row['reason_code']) is not str or row['reason_code'] not in _HOST_REASONS
            or type(row['collectors']) is not list or len(row['collectors']) != len(_COLLECTORS)):
        return False
    rows = row['collectors']
    if not all(_valid_outcome(r, f, flags[f]) for r, f in zip(rows, _COLLECTORS)):
        return False
    ids = [i for r in rows for i in r['collection_ids']]
    if len(ids) > 16 or len(ids) != len(set(ids)):
        return False
    reason = row['reason_code']
    if not row['attempted']:
        return (reason in ('NO_EXECUTABLE_COLLECTORS', 'NOT_DISPATCHED', 'STOPPED', 'GUARD_REJECTED', 'INTERRUPTED')
                and all(r['state'] == 'NOT_SCANNED' for r in rows)
                and row == _host(name, False, rows, reason))
    if not any(flags.values()):
        return False
    if reason == 'CONNECTION_FAILED':
        if not all(r['state'] == 'UNREACHABLE' for r in rows if r['requested']):
            return False
    elif any(r['state'] == 'UNREACHABLE' for r in rows):
        return False
    fatal = [r['reason_code'] for r in rows if r['reason_code'] in _FATAL
             and r['state'] == 'ERROR']
    if fatal and reason not in _FATAL:
        return False
    special = reason if reason in _FATAL or reason in ('CONNECTION_FAILED', 'CONNECTION_TIMEOUT') else None
    return row == _host(name, True, rows, special)


def _run_state(rows, stopped=None):
    if rows and all(r['host_state'] == 'COMPLETE' for r in rows) and stopped is None:
        return 'COMPLETE', 'COMPLETE', 0
    # B05 derives run coverage from terminal host states, not individual
    # successful slots in a host whose safe termination remains unconfirmed.
    valid = any(r['host_state'] in ('COMPLETE', 'PARTIAL') for r in rows)
    state, rc = ('PARTIAL', 5) if valid else ('ERROR', 6)
    reason = stopped or ('INCOMPLETE_COLLECTION' if valid else 'NO_VALID_RESULT')
    if stopped is None and all(r['reason_code'] == 'NO_EXECUTABLE_COLLECTORS' for r in rows):
        reason = 'NO_EXECUTABLE_COLLECTORS'
    return state, reason, 7 if stopped == 'INTERRUPTED' else rc


def validate_terminal_manifest(manifest, rc):
    """Validate the closed B04/B05 terminal shape and recompute its summary.

    This checks the batch contract, not authenticity or the referenced
    Evidence document. Only a trusted in-process result is a native result.
    """
    require(type(manifest) is dict and manifest.keys() == {'batch_manifest_version', 'target_ids',
                'target_count', 'limits', 'profile', 'run_state', 'reason_code', 'hosts'}
            and type(manifest['batch_manifest_version']) is int and manifest['batch_manifest_version'] == 1,
            3, 'INVALID_TERMINAL_MANIFEST')
    targets, limits, rows = manifest['target_ids'], manifest['limits'], manifest['hosts']
    require(type(targets) is list and 1 <= len(targets) <= 10
            and all(type(n) is str and _scope.HOST.fullmatch(n) and n.lower() not in _scope.RESERVED
                    and not _scope.loopback(n) for n in targets) and targets == sorted(set(targets))
            and type(manifest['target_count']) is int and manifest['target_count'] == len(targets)
            and type(limits) is dict and limits.keys() == {'max_hosts', 'forks', 'serial', 'ssh_timeout_s', 'command_timeout_s'}
            and all(type(v) is int for v in limits.values())
            and len(targets) <= limits['max_hosts'] <= 10 and limits['forks'] in (1, 2)
            and limits['serial'] == 2 and limits['ssh_timeout_s'] == 15 and limits['command_timeout_s'] == 30
            and manifest['profile'] in ('baseline', 'extended')
            and type(rows) is list and len(rows) == len(targets)
            and type(rc) is int and rc in (0, 5, 6, 7), 3, 'INVALID_TERMINAL_MANIFEST')
    all_ids = set()
    for name, row in zip(targets, rows):
        require(type(row) is dict and type(row.get('collectors')) is list
                and len(row['collectors']) == len(_COLLECTORS)
                and all(type(c) is dict and type(c.get('requested')) is bool for c in row['collectors']),
                3, 'INVALID_TERMINAL_MANIFEST')
        flags = {f: c['requested'] for f, c in zip(_COLLECTORS, row['collectors'])}
        require(not flags['pqc_collect_tls_services'] and
                (manifest['profile'] == 'extended' or not flags['pqc_collect_nginx_certs'])
                and _valid_host(row, name, flags), 3, 'INVALID_TERMINAL_MANIFEST')
        ids = {i for c in row['collectors'] for i in c['collection_ids']}
        require(not all_ids & ids, 3, 'INVALID_TERMINAL_MANIFEST')
        all_ids.update(ids)
    reason = manifest['reason_code']
    require(type(reason) is str and reason in _RUN_REASONS, 3, 'INVALID_TERMINAL_MANIFEST')
    stopped = reason if reason in _FATAL else None
    require(stopped is not None or not any(r['reason_code'] in _FATAL or r['reason_code'] == 'STOPPED' for r in rows),
            3, 'INVALID_TERMINAL_MANIFEST')
    require((manifest['run_state'], reason, rc) == _run_state(rows, stopped), 3, 'INVALID_TERMINAL_MANIFEST')
    return None


def _manifest(ctx, rows, stopped=None):
    state, reason, rc = _run_state(rows, stopped)
    out = {'batch_manifest_version': 1, 'target_ids': list(ctx._targets), 'target_count': len(ctx._targets),
           'limits': {'max_hosts': ctx._request['max_hosts'], 'forks': ctx._request['forks'],
                      'serial': 2, 'ssh_timeout_s': 15, 'command_timeout_s': 30},
           'profile': ctx._request['profile'], 'run_state': state, 'reason_code': reason, 'hosts': rows}
    validate_terminal_manifest(out, rc)
    return rc, out


class _Ledger:
    """One terminal row per frozen target, never infer from a recap."""
    def __init__(self, ctx, registry):
        self.targets = ctx._targets
        self.flags = {n: dict(ctx._decisions[n]['requested_flags']) for n in self.targets}
        self.eligible = {n: tuple(f for f in _COLLECTORS if self.flags[n][f] and f in registry)
                         for n in self.targets}
        self.started = {}
        self.rows = {n: _blank(n, self.flags[n], 'NO_EXECUTABLE_COLLECTORS')
                     for n in self.targets if not self.eligible[n]}
        self.stop = None
        self.ids = set()

    def fail(self, reason):
        if (self.stop is None or reason == 'INTERRUPTED'
                or reason in ('CONTROLLER_CLEANUP_UNCONFIRMED', 'REMOTE_CLEANUP_UNCONFIRMED')
                and self.stop != 'INTERRUPTED'):
            self.stop = reason

    def start(self, name, task_uuid):
        require(name in self.eligible and self.eligible[name] and name not in self.started
                and name not in self.rows and self.stop is None, 3, 'INVALID_NATIVE_RESULT')
        self.started[name] = task_uuid

    def accept(self, message):
        require(type(message) is dict and message.keys() == {'target_id', 'task_uuid', 'row'}
                and type(message['target_id']) is str, 3, 'INVALID_NATIVE_RESULT')
        n = message['target_id']
        require(n in self.started and n not in self.rows and self.started[n] == message['task_uuid'],
                3, 'INVALID_NATIVE_RESULT')
        row = message['row']
        require(_valid_host(row, n, self.flags[n]) and row['attempted'], 3, 'INVALID_NATIVE_RESULT')
        # Unavailable slots cannot contribute success. A connection-level
        # failure is recorded for the requested host, not treated as evidence.
        require(all(c['collector_id'] in self.eligible[n] or c['state'] == 'NOT_SCANNED'
                    or row['reason_code'] in ('CONNECTION_FAILED', 'CONNECTION_TIMEOUT')
                    for c in row['collectors']), 3, 'INVALID_NATIVE_RESULT')
        ids = {i for c in row['collectors'] for i in c['collection_ids']}
        require(not self.ids & ids, 3, 'INVALID_NATIVE_RESULT')
        self.ids.update(ids)
        self.rows[n] = copy.deepcopy(row)
        if row['reason_code'] in _FATAL:
            self.fail(row['reason_code'])

    def worker_failed(self, name, reason):
        # Results are provisional until the native worker is joined. Preserve
        # known slot observations but do not promote an unsafe worker to COMPLETE.
        if name in self.rows and self.rows[name]['attempted']:
            old = self.rows[name]
            if old['reason_code'] == 'REMOTE_CLEANUP_UNCONFIRMED' and reason != 'CONTROLLER_CLEANUP_UNCONFIRMED':
                reason = old['reason_code']
            # A connection failure is provisional until normal worker exit.
            # Do not retain UNREACHABLE slots when that receipt is missing.
            rows = [_outcome(c['collector_id'], True, 'ERROR', 'OUTCOME_UNKNOWN')
                    if c['state'] == 'UNREACHABLE' else c for c in old['collectors']]
            self.rows[name] = _host(name, True, rows, reason)
        elif name in self.started:
            self.rows[name] = _blank(name, self.flags[name], reason, True)
        self.fail(reason)

    def finish(self):
        result = []
        for n in self.targets:
            if n in self.rows:
                result.append(self.rows[n])
            elif n in self.started:
                result.append(_blank(n, self.flags[n], self.stop or 'OUTCOME_UNKNOWN', True))
            else:
                result.append(_blank(n, self.flags[n], 'INTERRUPTED' if self.stop == 'INTERRUPTED'
                                     else 'GUARD_REJECTED' if self.stop == 'GUARD_REJECTED' else 'STOPPED'))
        return result


class _Deadline(BaseException):
    pass


class _Cancelled(BaseException):
    pass


@contextlib.contextmanager
def _deadline(seconds, defer=None):
    # No nested/external timer or blocked alarm. The parent may defer an
    # exception only across the native fork-to-process-receipt critical section.
    require(seconds > 0 and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
            and signal.SIGALRM not in signal.pthread_sigmask(signal.SIG_BLOCK, ())
            and signal.SIGALRM not in signal.sigpending(), 3, 'NATIVE_CONTEXT_UNVERIFIED')
    expired = False
    def expire(signum, frame):
        nonlocal expired
        expired = True
        if defer is None or not defer():
            raise _Deadline()
    previous = signal.signal(signal.SIGALRM, expire)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
        if expired:
            raise _Deadline()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _collect(name, flags, registry):
    """Trusted adapter bridge, one connection and at most one call per slot."""
    try:
        with _deadline(_SSH_SECONDS):
            connected = _restricted_connection(name)
    except _Deadline:
        # A controller-side deadline is not a cleanup receipt.
        connected = 'REMOTE_CLEANUP_UNCONFIRMED'
    except Exception:
        connected = 'REMOTE_CLEANUP_UNCONFIRMED'
    if connected != 'CONNECTED':
        reason = connected if connected in ('CONNECTION_FAILED', 'CONNECTION_TIMEOUT',
                                             'REMOTE_CLEANUP_UNCONFIRMED') else 'INVALID_ADAPTER_RESULT'
        rows = [_outcome(f, flags[f], 'UNREACHABLE' if reason == 'CONNECTION_FAILED' else 'ERROR', reason)
                if flags[f] and (f in registry or reason in ('CONNECTION_FAILED', 'CONNECTION_TIMEOUT'))
                else _outcome(f, flags[f], 'NOT_SCANNED', 'ADAPTER_NOT_AVAILABLE' if flags[f] else 'DISABLED')
                for f in _COLLECTORS]
        return _host(name, True, rows, reason)
    rows = []
    stop = None
    for f in _COLLECTORS:
        if not flags[f] or f not in registry or stop:
            rows.append(_outcome(f, flags[f], 'NOT_SCANNED', 'DISABLED' if not flags[f] else
                                 'STOPPED' if stop else 'ADAPTER_NOT_AVAILABLE'))
            continue
        try:
            # The remote helper owns the 30s wall clock and cleanup. The
            # controller additionally bounds a trusted adapter's return.
            # A lost return cannot prove remote termination.
            with _deadline(_COMMAND_SECONDS + 1):
                value = registry[f](name)
            require(type(value) is dict and value.keys() == {'state', 'reason_code', 'rc', 'collection_ids'},
                    3, 'INVALID_ADAPTER_RESULT')
            row = {'collector_id': f, 'requested': True, **value}
            require(_valid_outcome(row, f, True) and row['state'] not in ('UNREACHABLE', 'NOT_SCANNED'),
                    3, 'INVALID_ADAPTER_RESULT')
        except _Deadline:
            row = _outcome(f, True, 'ERROR', 'REMOTE_CLEANUP_UNCONFIRMED')
        except Exception:
            row = _outcome(f, True, 'ERROR', 'INVALID_ADAPTER_RESULT')
        rows.append(row)
        if row['reason_code'] in _FATAL:
            stop = row['reason_code']
    return _host(name, True, rows, stop)


def _task(ctx, names):
    from ansible.playbook.play import Play
    from ansible.playbook.play_context import PlayContext
    play = Play.load({'hosts': list(names), 'gather_facts': False, 'connection': 'ssh',
                      'become': False, 'serial': 2, 'tasks': [
                          {'ansible.builtin.raw': COMMAND, 'connection': 'ssh', 'become': False,
                           'no_log': True}]}, variable_manager=ctx._variables, loader=ctx._loader)
    task = play.tasks[0].block[0]
    return play, task, PlayContext(play=play)


@contextlib.contextmanager
def _worker_boundary(ctx, name, registry, collect=None):
    """Inherited only by the next native fork; never invoke original SSH _run."""
    from ansible.executor.task_executor import TaskExecutor
    from ansible.plugins.connection import ssh
    from ansible.plugins.loader import connection_loader
    expected = ctx._proofs[name]
    flags = ctx._decisions[name]['requested_flags']
    original_run = ssh.Connection._run
    original_get = TaskExecutor._get_connection
    used = False

    def get_connection(executor, cvars, templar, current_connection):
        require(current_connection in ('ssh', 'ansible.builtin.ssh') and executor._host.name == name
                and executor._task.action == 'ansible.builtin.raw' and not executor._task.delegate_to
                and not executor._task.loop and not executor._task.run_once
                and _scope.flag(_scalar(cvars.get('ansible_become', False)), 4) is False
                and not cvars.get('ansible_delegated_vars'), 4, 'BATCH_GUARD_DENIED')
        connection = original_get(executor, cvars, templar, current_connection)
        # Loader may create separate class objects for FQCN/short plugin
        # names. Check the actual source, and put the deny boundary on the
        # consumed instance as well, never a different class's method.
        import inspect
        require(Path(inspect.getfile(type(connection))).resolve() == Path(ssh.__file__).resolve()
                and connection.become is None, 4, 'BATCH_GUARD_DENIED')
        native_exec = connection.exec_command
        def exec_witness(cmd, in_data=None, sudoable=True):
            require(cmd == COMMAND and in_data is None and connection.become is None,
                    4, 'BATCH_GUARD_DENIED')
            return native_exec(cmd, in_data=None, sudoable=False)
        connection.exec_command = exec_witness
        connection._run = lambda argv, in_data, sudoable=True, checkrc=True: guarded(
            connection, argv, in_data, sudoable, checkrc)
        return connection

    def guarded(conn, argv, in_data, sudoable=True, checkrc=True):
        nonlocal used
        require(not used and in_data is None and sudoable is False and conn.become is None
                and tuple(argv) == expected[0], 4, 'BATCH_GUARD_DENIED')
        used = True
        with _deadline(_GUARD_SECONDS):
            require(_source_identity(ctx._source) == ctx._source_id
                    and _project(ctx._inventory, ctx._variables, ctx._request)
                    == (ctx._targets, ctx._flags, ctx._decisions), 4, 'CONNECTION_CONTEXT_DRIFT')
            # Verify the actual native option consumer and exact argv again,
            # including the existing validated -F snapshot proof.
            actual = _native_argv(conn)
            require(actual == expected[:2] and _effective_ssh(tuple(argv), expected[1]) == expected[2],
                    4, 'BATCH_GUARD_DENIED')
        result = _collect(name, flags, registry) if collect is None else collect(name, flags, registry)
        raw = json.dumps(result, sort_keys=True, separators=(',', ':')).encode('ascii')
        require(len(raw) <= _QUEUE_BYTES - 350, 3, 'INVALID_NATIVE_RESULT')
        return 0, raw, b''

    def deny(*args, **kwargs):
        raise Denied(2, 'LIVE_NOT_AVAILABLE')

    try:
        # Defensive class stop: actual instance receives only the restricted
        # witness above. No original _run call, even on adapter failure.
        ssh.Connection._run = deny
        TaskExecutor._get_connection = get_connection
        yield
    finally:
        TaskExecutor._get_connection = original_get
        ssh.Connection._run = original_run


def _make_queue(receipt_validator=None):
    from ansible.executor.task_queue_manager import FinalQueue
    class ClosedQueue(FinalQueue):
        # The actual WorkerProcess calls this native result boundary. Do not
        # send raw task fields, exceptions, stdout/stderr, or arbitrary vars.
        def send_task_result(self, result):
            wire = result.as_wire_task_result()
            data = wire.return_data
            row = None
            try:
                out = data.get('stdout')
                if (type(data.get('rc')) is int and data['rc'] == 0 and not data.get('failed')
                        and not data.get('unreachable') and not data.get('skipped') and data.get('stderr') == ''
                        and isinstance(out, str) and len(out) <= _QUEUE_BYTES):
                    row = _scope.strict_json(out.encode('utf-8'))
            except Exception:
                pass
            # Filter before IPC as well as at the controller. Native failure
            # output can contain arbitrary diagnostics and is not an outcome.
            name, task_id = wire.host_name, wire.task_uuid
            if not isinstance(name, str) or not _scope.HOST.fullmatch(name):
                name = 'invalid-target'
                row = None
            if not isinstance(task_id, str) or not re.fullmatch(r'[0-9a-f-]{1,128}', task_id):
                task_id = 'invalid-task'
                row = None
            if row is not None and receipt_validator is not None:
                if not receipt_validator(row, name):
                    row = None
            elif row is not None:
                try:
                    rows = row['collectors']
                    flags = {f: c['requested'] for f, c in zip(_COLLECTORS, rows)}
                    if (set(flags) != set(_COLLECTORS) or not all(type(v) is bool for v in flags.values())
                            or not _valid_host(row, name, flags) or not row['attempted']):
                        row = None
                except (KeyError, TypeError, ValueError):
                    row = None
            msg = {'target_id': name, 'task_uuid': task_id, 'row': row}
            raw = json.dumps(msg, separators=(',', ':'), ensure_ascii=True).encode('ascii')
            if len(raw) > _QUEUE_BYTES:
                msg['row'] = None
                raw = json.dumps(msg, separators=(',', ':'), ensure_ascii=True).encode('ascii')
            # Atomic small multiprocessing pipe message on supported Linux;
            # no raw diagnostic path. Receiver checks the bound independently.
            if len(raw) <= _QUEUE_BYTES:
                self.put(raw)

        def send_display(self, *args, **kwargs):
            return None

        def send_callback(self, *args, **kwargs):
            return None

        def send_prompt(self, *args, **kwargs):
            raise Denied(3, 'INVALID_NATIVE_RESULT')
    return ClosedQueue()


def _queue_strategy(tqm):
    from ansible.plugins.strategy import StrategyBase
    # Use the actual core 2.19.11 native _queue_task, WorkerProcess and
    # TaskExecutor. This private fixed-task driver owns waves and bounded
    # result polling; it does not start the general playbook result thread
    # (which can dispatch prompts/callbacks and join without a deadline).
    class FixedQueue(StrategyBase):
        def __init__(self, manager):
            self._tqm, self._loader = manager, manager.get_loader()
            self._variable_manager = manager.get_variable_manager()
            self._workers, self._final_q = manager._workers, manager._final_q
            self._cur_worker = self._pending_results = 0
            self._queued_task_cache = {}
    return FixedQueue(tqm)


def _drain(queue, ledger, after_accept=None):
    while queue._reader.poll(0):
        raw = queue.get()
        require(type(raw) is bytes and len(raw) <= _QUEUE_BYTES, 3, 'INVALID_NATIVE_RESULT')
        ledger.accept(_scope.strict_json(raw))
        if after_accept is not None:
            after_accept()


def _stop_workers(workers):
    """Bounded controller-side group termination and join, not remote proof."""
    end = time.monotonic() + _WORKER_GRACE
    try:
        for sig, until in ((signal.SIGTERM, min(end, time.monotonic() + 1.25)), (signal.SIGKILL, end)):
            for worker in workers:
                if worker is None or worker.pid is None:
                    continue
                try:
                    worker.join(0)
                    if not worker.is_alive():
                        _scope.reap_group(worker.pid)
                        if not _scope.group_exists(worker.pid):
                            continue
                    # Native WorkerProcess calls setsid. A pre-setsid worker
                    # must be signalled by its own pid, never our group.
                    if os.getpgid(worker.pid) == worker.pid:
                        os.killpg(worker.pid, sig)
                    elif worker.is_alive():
                        os.kill(worker.pid, sig)
                except ProcessLookupError:
                    if _scope.group_exists(worker.pid):
                        os.killpg(worker.pid, sig)
            while True:
                for worker in workers:
                    if worker is not None and worker.pid is not None:
                        worker.join(0)
                        if not worker.is_alive():
                            _scope.reap_group(worker.pid)
                if all(w is None or w.pid is None or (not w.is_alive() and not _scope.group_exists(w.pid))
                       for w in workers):
                    return True
                if time.monotonic() >= until:
                    break
                time.sleep(0.01)
    except (Denied, OSError, AssertionError, ValueError):
        pass
    return False


def _guard(ctx, name):
    # S1 remains a fixed stop. Only that exact terminal reason proves the
    # retained native boundary was reached; no return value is authorization.
    try:
        # The scheduler owns the bounded phase, including the earliest
        # outstanding worker deadline; do not install a nested timer here.
        ctx._boundary(name)
    except Denied as exc:
        if exc.code == 2 and exc.reason == 'LIVE_NOT_AVAILABLE':
            return
        raise
    raise Denied(4, 'BATCH_GUARD_DENIED')


class _WorkerWave:
    """Callback and process completion are separate, bounded receipts."""
    def __init__(self, ledger, queue):
        self.ledger, self.queue = ledger, queue
        self.workers, self.ends, self.grace = {}, {}, {}
        self.confirmed, self.faults = set(), {}

    def track(self, name, worker, task_uuid, end):
        self.ledger.start(name, task_uuid)
        self.workers[name], self.ends[name] = worker, end

    def limit(self):
        return min((min(end, self.grace.get(n, end)) for n, end in self.ends.items()
                    if n not in self.confirmed), default=float('inf'))

    def fail(self, name, reason):
        self.faults.setdefault(name, reason)
        self.ledger.fail(reason)

    def _drain_receipts(self):
        _drain(self.queue, self.ledger)

    def _grace_changed(self):
        pass

    def poll(self):
        self._drain_receipts()
        for n, worker in self.workers.items():
            if n in self.confirmed or n in self.faults:
                continue
            worker.join(0)
            if not worker.is_alive():
                # SimpleQueue sends synchronously. Drain again after exit so
                # a last legitimate callback is not mistaken for a lost one.
                self._drain_receipts()
                _scope.reap_group(worker.pid)
                if n not in self.ledger.rows:
                    self.fail(n, 'OUTCOME_UNKNOWN')
                elif worker.exitcode != 0 or _scope.group_exists(worker.pid):
                    self.fail(n, 'CONTROLLER_WORKER_FAILED')
                elif time.monotonic() >= min(self.ends[n], self.grace.get(n, self.ends[n])):
                    self.fail(n, 'CONTROLLER_TIMEOUT')
                else:
                    self.confirmed.add(n)
            else:
                now = time.monotonic()
                if n in self.ledger.rows:
                    self.grace.setdefault(n, min(self.ends[n], now + _WORKER_GRACE))
                    self._grace_changed()
                if now >= min(self.ends[n], self.grace.get(n, self.ends[n])):
                    self.fail(n, 'CONTROLLER_TIMEOUT')

    def finish(self, workers):
        # Observe normal exits before forcing termination, then drain any
        # last callback. A callback received during forced cleanup cannot
        # itself convert an unconfirmed worker into a successful terminal.
        try:
            self.poll()
        except (Exception, SystemExit):
            self.ledger.fail('INVALID_NATIVE_RESULT')
        try:
            quiet = _stop_workers(workers)
        except (Exception, SystemExit):
            quiet = False
        try:
            _drain(self.queue, self.ledger)
        except (Exception, SystemExit):
            self.ledger.fail('INVALID_NATIVE_RESULT')
        if not quiet:
            self.ledger.fail('CONTROLLER_CLEANUP_UNCONFIRMED')
        for n in self.workers:
            if not quiet or n not in self.confirmed:
                reason = ('CONTROLLER_CLEANUP_UNCONFIRMED' if not quiet else
                          self.faults.get(n, 'CONTROLLER_WORKER_FAILED'))
                self.ledger.worker_failed(n, reason)
        return quiet


class _ProducerWorkerWave(_WorkerWave):
    """V2 receipt work shares the scheduler's existing deadline."""
    def __init__(self, ledger, queue, phase):
        super().__init__(ledger, queue)
        self.phase = phase

    def _drain_receipts(self):
        # Includes queue read, receipt validation and actual normalization.
        # An exit drain may follow a newly established shorter grace.
        with self.phase():
            _drain(self.queue, self.ledger, self._receipt_accepted)

    def _receipt_accepted(self):
        # Establish grace before another queued receipt can start expensive
        # projection work, not only after the complete queue drain.
        now = time.monotonic()
        for n, worker in self.workers.items():
            if n not in self.confirmed and n not in self.faults and n in self.ledger.rows and worker.is_alive():
                self.grace.setdefault(n, min(self.ends[n], now + _WORKER_GRACE))
        self._grace_changed()

    def _grace_changed(self):
        with self.phase():
            pass

    def poll(self):
        with self.phase():
            super().poll()

    def finish(self, workers):
        # A timeout/cancellation/fatal stop is not permission for another
        # normalization. Even a normal final poll must use the original limit.
        try:
            if self.ledger.stop is None:
                self.poll()
        except _Cancelled:
            self.ledger.fail('INTERRUPTED')
        except _Deadline:
            self.ledger.fail('CONTROLLER_TIMEOUT')
        except (Exception, SystemExit):
            self.ledger.fail('INVALID_NATIVE_RESULT')
        finally:
            # The phase has unwound. This is the separate bounded termination
            # budget, not a new worker/receipt deadline. Do not consume late
            # receipts after forced termination; retain already validated rows.
            try:
                quiet = _stop_workers(workers)
            except (Exception, SystemExit):
                quiet = False
        if not quiet:
            self.ledger.fail('CONTROLLER_CLEANUP_UNCONFIRMED')
        for n in self.workers:
            if not quiet or n not in self.confirmed:
                stopped = self.ledger.stop
                reason = ('CONTROLLER_CLEANUP_UNCONFIRMED' if not quiet else
                          self.faults.get(n, stopped if stopped in ('CONTROLLER_TIMEOUT', 'INTERRUPTED')
                                          else 'CONTROLLER_WORKER_FAILED'))
                self.ledger.worker_failed(n, reason)
        return quiet


def execute_batch(ctx):
    """One private native batch invocation -> (rc, closed terminal manifest).

    Denied(2/3/4) before dispatch is a preflight rejection, not a run.
    There is no public adapter/transport parameter or live execution grant.
    """
    return _execute_batch(ctx)


def _execute_batch(ctx, producer_session=None):
    import threading
    import ctypes
    from ansible import context
    from ansible.executor.task_queue_manager import TaskQueueManager
    from multiprocessing.process import BaseProcess
    require(type(ctx) is _Context and not ctx._batch_used and sys.platform == 'linux'
            and threading.current_thread() is threading.main_thread()
            and threading.active_count() == 1 and not context.CLIARGS.get('extra_vars')
            and signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
            and not {signal.SIGALRM, signal.SIGINT, signal.SIGTERM}
            & signal.pthread_sigmask(signal.SIG_BLOCK, ()), 3, 'NATIVE_CONTEXT_UNVERIFIED')
    ctx._batch_used = True
    started = time.monotonic()
    deadline = started + _GUARD_SECONDS
    interrupted = phase_active = fork_critical = False
    active_phase_end = None
    controller_pid = os.getpid()
    handlers = {}
    if producer_session is not None:
        producer_session.handlers = handlers
    tqm = queue = ledger = None
    wave = None
    subreaper = scheduling = False
    libc = ctypes.CDLL(None, use_errno=True)
    old = ctypes.c_int()

    def interrupt(signum, frame):
        nonlocal interrupted
        if os.getpid() != controller_pid or interrupted:
            return
        interrupted = True
        if phase_active and not fork_critical:
            # Disarm before unwinding a bounded child/guard's own finally.
            signal.setitimer(signal.ITIMER_REAL, 0)
            raise _Cancelled()

    @contextlib.contextmanager
    def phase():
        nonlocal phase_active, active_phase_end
        end = min(deadline, time.monotonic() + _GUARD_SECONDS,
                  wave.limit() if wave is not None else float('inf'))
        if interrupted:
            raise _Cancelled()
        if phase_active and producer_session is not None:
            # Polling inside the native pre-fork phase, and drain/grace checks
            # inside a poll, borrow the outer alarm. Never restore a longer
            # timer, renew an expired one, or install another handler.
            end = min(end, active_phase_end)
            remaining = end - time.monotonic()
            timer = signal.getitimer(signal.ITIMER_REAL)[0]
            if remaining <= 0 or timer <= 0:
                raise _Deadline()
            if end < active_phase_end:
                active_phase_end = end
                if remaining < timer:
                    signal.setitimer(signal.ITIMER_REAL, remaining)
            yield active_phase_end
            if interrupted:
                raise _Cancelled()
            if time.monotonic() >= active_phase_end:
                raise _Deadline()
            return
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise _Deadline()
        with _deadline(remaining, lambda: fork_critical):
            phase_active = True
            active_phase_end = end
            try:
                if interrupted:
                    raise _Cancelled()
                yield end
            finally:
                end = active_phase_end
                active_phase_end = None
                phase_active = False
        if interrupted:
            raise _Cancelled()
        if time.monotonic() >= end:
            raise _Deadline()

    def poll():
        if producer_session is not None:
            if interrupted:
                ledger.fail('INTERRUPTED')
            if time.monotonic() >= deadline:
                ledger.fail('CONTROLLER_TIMEOUT')
            if ledger.stop is not None:
                return False
        if wave is not None:
            wave.poll()
        if interrupted:
            ledger.fail('INTERRUPTED')
        if time.monotonic() >= deadline:
            ledger.fail('CONTROLLER_TIMEOUT')
        return ledger.stop is None

    def queue_one(strategy, host, task, vals, pc, name):
        # Native _queue_task assigns its WorkerProcess to this empty slot
        # before start(). Capture ownership even when queuing raises after
        # fork. Do not interrupt multiprocessing's narrow start receipt.
        nonlocal fork_critical
        slot = strategy._cur_worker
        pending = strategy._pending_results
        require(tqm._workers[slot] is None, 3, 'INVALID_NATIVE_RESULT')
        end = min(deadline, time.monotonic() + budgets[name])
        original_start = BaseProcess.start
        try:
            with phase() as phase_end:
                def start_worker(worker):
                    nonlocal fork_critical
                    # Last observable boundary inside native queueing, after
                    # worker initialization but before the actual child fork.
                    if not poll():
                        raise _Cancelled() if interrupted else Denied(3, 'INVALID_NATIVE_RESULT')
                    require(worker is tqm._workers[slot], 3, 'INVALID_NATIVE_RESULT')
                    launch_end = min(phase_end, wave.limit(),
                                     active_phase_end if producer_session is not None else phase_end)
                    remaining = launch_end - time.monotonic()
                    if remaining <= 0:
                        raise _Deadline()
                    # A newly observed callback may shorten the grace while
                    # native queuing is in progress. Never extend the timer.
                    timer = signal.getitimer(signal.ITIMER_REAL)[0]
                    if timer <= 0:
                        raise _Deadline()
                    if remaining < timer:
                        signal.setitimer(signal.ITIMER_REAL, remaining)
                    fork_critical = True
                    try:
                        original_start(worker)
                    finally:
                        fork_critical = False
                    if interrupted:
                        raise _Cancelled()
                    if time.monotonic() >= launch_end:
                        raise _Deadline()
                BaseProcess.start = start_worker
                boundary = (_worker_boundary(ctx, name, registry) if producer_session is None else
                            _worker_boundary(ctx, name, registry, producer_session.collect))
                with boundary:
                    strategy._queue_task(host, task, vals, pc)
        finally:
            BaseProcess.start = original_start
            # Outside the interruptible phase: register every actual start
            # before classifying any queue exception or cancellation.
            worker = tqm._workers[slot]
            if worker is not None and worker.pid is not None:
                wave.track(name, worker, task._uuid, end)
        require(worker is not None and worker.pid is not None
                and strategy._pending_results == pending + 1, 3, 'INVALID_NATIVE_RESULT')

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            handlers[sig] = signal.signal(sig, interrupt)
        # Include the initial native VariableManager projection even when
        # there are no eligible adapters. No provider reload.
        try:
            with phase():
                require(_request(ctx._request) == ctx._request and _source_identity(ctx._source) == ctx._source_id
                        and _project(ctx._inventory, ctx._variables, ctx._request)
                        == (ctx._targets, ctx._flags, ctx._decisions), 4, 'CONNECTION_CONTEXT_DRIFT')
                if producer_session is None:
                    registry = _passive_adapters()
                    require(type(registry) is dict and registry.keys() <= _PASSIVE
                            and all(callable(v) for v in registry.values()), 3, 'INVALID_ADAPTER_REGISTRY')
                    ledger = _Ledger(ctx, registry)
                else:
                    registry, ledger = producer_session.prepare(ctx)
        except _Deadline:
            if not interrupted:
                raise Denied(3, 'BATCH_GUARD_TIMEOUT') from None
            raise _Cancelled()
        names = [n for n in ledger.targets if ledger.eligible[n]]
        if names:
            width = min(ctx._request['forks'], 2)
            budgets = {n: _GUARD_SECONDS + _SSH_SECONDS + (_COMMAND_SECONDS + 1) * len(ledger.eligible[n])
                       + _WORKER_GRACE + 5 for n in names}
            # Initial projection and preflight each have the existing guard
            # cap; account for both in the single absolute invocation budget.
            deadline = started + 2 * _GUARD_SECONDS + sum(2 * _GUARD_SECONDS + budgets[n] for n in names) + 5
            require(libc.prctl(37, ctypes.byref(old), 0, 0, 0) == 0
                    and libc.prctl(36, 1, 0, 0, 0) == 0, 3, 'NATIVE_CONTEXT_UNVERIFIED')
            subreaper = True
            try:
                with phase():
                    ctx._preflight()
            except _Deadline:
                if not interrupted:
                    raise Denied(3, 'BATCH_GUARD_TIMEOUT') from None
                raise _Cancelled()
            scheduling = True
            # Keep a reference even if native initialization partially fails.
            # TQM installs its own CLI handlers, so restore ours before
            # unmasking on every path; SIGALRM remains unblocked.
            with phase():
                mask = signal.pthread_sigmask(signal.SIG_BLOCK, handlers)
                try:
                    tqm = TaskQueueManager.__new__(TaskQueueManager)
                    tqm.__init__(ctx._inventory, ctx._variables, ctx._loader, {}, forks=width,
                                 run_additional_callbacks=False)
                finally:
                    for sig in handlers:
                        signal.signal(sig, interrupt)
                    signal.pthread_sigmask(signal.SIG_SETMASK, mask)
                tqm._final_q.close()
                queue = tqm._final_q = (_make_queue() if producer_session is None else
                                        _make_queue(producer_session.bridge.valid_receipt))
            with _quiet():
                for offset in range(0, len(names), width):
                    if not poll():
                        break
                    selected = names[offset:offset + width]
                    with phase():
                        tqm._initialize_processes(len(selected))
                        strategy = _queue_strategy(tqm)
                    wave = (_WorkerWave(ledger, queue) if producer_session is None else
                            _ProducerWorkerWave(ledger, queue, phase))
                    try:
                        for n in selected:
                            if not poll():
                                break
                            try:
                                with phase():
                                    _guard(ctx, n)
                                if not poll():
                                    break
                                with phase():
                                    play, task, pc = _task(ctx, selected)
                                    host = ctx._inventory.hosts[n]
                                    vals = ctx._variables.get_vars(play=play, host=host, task=task,
                                                                    include_hostvars=False, use_cache=False)
                            except (Denied, _Deadline) as exc:
                                if producer_session is None:
                                    poll()
                                elif isinstance(exc, _Deadline) and time.monotonic() >= min(deadline, wave.limit()):
                                    ledger.fail('CONTROLLER_TIMEOUT')
                                    break
                                ledger.fail('GUARD_REJECTED')
                                break
                            if not poll():
                                break
                            queue_one(strategy, host, task, vals, pc, n)
                        while poll() and len(wave.confirmed) != len(wave.workers):
                            queue._reader.poll(max(0, min(0.02, wave.limit() - time.monotonic(),
                                                          deadline - time.monotonic())))
                    except _Cancelled:
                        ledger.fail('INTERRUPTED')
                    except _Deadline:
                        ledger.fail('CONTROLLER_TIMEOUT')
                    except (Exception, SystemExit):
                        ledger.fail('INVALID_NATIVE_RESULT')
                    finally:
                        if wave.finish(tqm._workers):
                            for worker in tqm._workers:
                                if worker is not None:
                                    worker.close()
                            tqm._workers[:] = []
                        wave = None
                    if interrupted:
                        ledger.fail('INTERRUPTED')
    except _Cancelled:
        if ledger is None:
            ledger = (_Ledger(ctx, {}) if producer_session is None else
                      producer_session.cancelled_before_prepare(ctx))
            ledger.rows.clear()
        ledger.fail('INTERRUPTED')
    except _Deadline:
        if ledger is None:
            raise Denied(3, 'BATCH_GUARD_TIMEOUT') from None
        ledger.fail('CONTROLLER_TIMEOUT')
    except (Exception, SystemExit):
        if not scheduling:
            raise
        ledger.fail('INVALID_NATIVE_RESULT')
    finally:
        try:
            if tqm is not None:
                workers = getattr(tqm, '_workers', ())
                if workers:
                    try:
                        quiet = _stop_workers(workers)
                    except (Exception, SystemExit):
                        quiet = False
                    if not quiet:
                        ledger.fail('CONTROLLER_CLEANUP_UNCONFIRMED')
                # Native local queue/lockfile closure is bounded separately
                # from process-group termination. Attempt each owned resource
                # even if partial construction or another close failed.
                for resource in ('_final_q', '_connection_lockfile'):
                    obj = getattr(tqm, resource, None)
                    if obj is not None:
                        try:
                            with _deadline(_WORKER_GRACE):
                                obj.close()
                        except (Exception, SystemExit, _Deadline):
                            ledger.fail('CONTROLLER_CLEANUP_UNCONFIRMED')
                tqm.terminate()
        finally:
            if producer_session is None:
                for sig, previous in handlers.items():
                    signal.signal(sig, previous)
            if subreaper:
                require(libc.prctl(36, old.value, 0, 0, 0) == 0, 3, 'NATIVE_CONTEXT_UNVERIFIED')
    if interrupted:
        ledger.fail('INTERRUPTED')
    if producer_session is not None:
        return producer_session.finish(ctx, ledger, lambda: interrupted)
    return _manifest(ctx, ledger.finish(), ledger.stop)


# I1a: the same guarded queue, worker deadlines and lifecycle, with a distinct
# private receipt path. V1 never consumes a V2 result or its reference limits.
def _v2_base_row(row):
    result = {k: v for k, v in row.items() if k != 'platform'}
    result['collectors'] = [{**c, 'collection_ids': [],
        'reason_code': 'COMMAND_IO_FAILED' if c['reason_code'] == 'COLLECTION_ERROR' else c['reason_code']}
        for c in row['collectors']]
    return result


def _valid_v2_outcome(row, flag, requested, cap):
    if type(row) is not dict or type(row.get('collection_ids')) is not list:
        return False
    ids = row['collection_ids']
    if (len(ids) > cap or any(type(x) is not str or not re.fullmatch(r'c-[0-9a-f]{64}', x) for x in ids)
            or ids != sorted(set(ids))):
        return False
    reduced = {**row, 'collection_ids': []}
    # V2 can report an aggregate collection error without inventing a command
    # rc. Reuse V1's state/rc shape, not its collection-reference capacity.
    if reduced.get('reason_code') == 'COLLECTION_ERROR':
        if reduced.get('state') != 'ERROR' or reduced.get('rc') is not None:
            return False
        reduced['reason_code'] = 'COMMAND_IO_FAILED'
    return _valid_outcome(reduced, flag, requested) and (row['state'] != 'UNREACHABLE' or not ids)


def validate_producer_manifest(manifest, rc):
    """V2 terminal shape only; exact Evidence binding is a separate check."""
    from tools import scan_collectors as bridge
    require(type(manifest) is dict and type(manifest.get('batch_manifest_version')) is int
            and manifest['batch_manifest_version'] == 2 and type(manifest.get('hosts')) is list
            and 1 <= len(manifest['hosts']) <= 10, 3, 'INVALID_TERMINAL_MANIFEST')
    caps = {bridge.PLATFORM: 10, bridge.PACKAGES: 2, bridge.SSL: 261, bridge.POLICY_FLAG: 9,
            bridge.SSHD: 8, bridge.KEYS: 1, bridge.CERT_FLAG: 3, bridge.NGINX: 0, bridge.TLS: 0}
    reduced = []
    refs = set()
    for row in manifest['hosts']:
        require(type(row) is dict and row.keys() == {'target_id', 'host_state', 'attempted', 'reason_code', 'collectors', 'platform'}
                and type(row['collectors']) is list and len(row['collectors']) == len(_COLLECTORS)
                and all(type(c) is dict and type(c.get('requested')) is bool for c in row['collectors']),
                3, 'INVALID_TERMINAL_MANIFEST')
        flags = {f: c['requested'] for f, c in zip(_COLLECTORS, row['collectors'])}
        require(not flags[bridge.NGINX] and not flags[bridge.TLS]
                and _valid_v2_outcome(row['platform'], bridge.PLATFORM, any(flags.values()), 10)
                and all(_valid_v2_outcome(c, f, flags[f], caps[f]) for c, f in zip(row['collectors'], _COLLECTORS)),
                3, 'INVALID_TERMINAL_MANIFEST')
        ids = [i for c in [row['platform'], *row['collectors']] for i in c['collection_ids']]
        require(len(ids) <= bridge.MAX_REFS and len(ids) == len(set(ids)) and not refs.intersection(ids)
                and (row['attempted'] or (not ids and row['platform']['state'] == 'NOT_SCANNED')),
                3, 'INVALID_TERMINAL_MANIFEST')
        refs.update(ids)
        reduced.append(_v2_base_row(row))
    require(len(refs) <= bridge.MAX_REFS * 10, 3, 'INVALID_TERMINAL_MANIFEST')
    validate_terminal_manifest({**manifest, 'batch_manifest_version': 1, 'hosts': reduced}, rc)
    return None


class _ProducerLedger(_Ledger):
    """Retain validated snapshots independently of the provisional terminal."""
    def __init__(self, ctx, session, eligible):
        self.session = session
        self.targets = ctx._targets
        self.flags = {n: dict(ctx._decisions[n]['requested_flags']) for n in self.targets}
        self.eligible = eligible
        self.started = {}
        self.rows = {n: _blank(n, self.flags[n], 'NO_EXECUTABLE_COLLECTORS')
                     for n in self.targets if not eligible[n]}
        self.stop = None
        self.ids = set()
        self.projections = {}
        self.metrics = {}

    def accept(self, message):
        require(type(message) is dict and message.keys() == {'target_id', 'task_uuid', 'row'}
                and type(message['target_id']) is str, 3, 'INVALID_NATIVE_RESULT')
        n, receipt = message['target_id'], message['row']
        if n in self.started and n in self.rows:
            # Duplicate receipt invalidates the host terminal, not its
            # previously validated observations. Never continue dispatch.
            self.worker_failed(n, 'INVALID_NATIVE_RESULT')
            raise Denied(3, 'INVALID_NATIVE_RESULT')
        require(n in self.started and n not in self.rows and self.started[n] == message['task_uuid']
                and self.session.bridge.valid_receipt(receipt, n), 3, 'INVALID_NATIVE_RESULT')
        # Only the V2 scheduler may authorize receipt work. In particular,
        # an expired/missing alarm must not turn into a fresh guard interval.
        if signal.getitimer(signal.ITIMER_REAL)[0] <= 0:
            raise _Deadline()
        try:
            envelope = self.session.handoff.read(n, receipt)
            projection = self.session.bridge.normalize_handoff(envelope, self.session.run_id, n, self.flags[n],
                                                                self.session.started_at, self.session.rules)
        except Exception:
            # Never send a raw parsing/normalizer exception or retained snapshot
            # through the queue. Known earlier valid hosts remain available.
            self.fail('INVALID_NATIVE_RESULT')
            raise Denied(3, 'INVALID_NATIVE_RESULT') from None
        row = _host(n, True, [projection.outcomes[f] for f in _COLLECTORS], projection.special)
        row['platform'] = projection.outcomes[self.session.bridge.PLATFORM]
        ids = {i for c in [row['platform'], *row['collectors']] for i in c['collection_ids']}
        require(not self.ids & ids, 3, 'INVALID_NATIVE_RESULT')
        merged_ids = self.ids | ids
        metrics = {'typed_bytes': receipt['byte_count'],
                   'ipc_bytes': len(json.dumps(message, separators=(',', ':'), ensure_ascii=True).encode('ascii'))}
        # Publish the validated observation and its terminal/metric together.
        # Mask only these in-memory assignments, never read/normalize or stop
        # workers. An interrupted projection must not leave partial bindings.
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, (signal.SIGALRM, signal.SIGINT, signal.SIGTERM))
        try:
            if signal.getitimer(signal.ITIMER_REAL)[0] <= 0:
                raise _Deadline()
            self.ids = merged_ids
            self.projections[n] = projection
            self.metrics[n] = metrics
            self.rows[n] = row
            if row['reason_code'] in _FATAL:
                self.fail(row['reason_code'])
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def worker_failed(self, name, reason):
        old = self.rows.get(name, {}).get('platform')
        super().worker_failed(name, reason)
        if old is not None:
            self.rows[name]['platform'] = (_outcome(self.session.bridge.PLATFORM, True, 'ERROR', 'OUTCOME_UNKNOWN')
                                          if old['state'] == 'UNREACHABLE' else old)

    def finish(self):
        rows = super().finish()
        for row in rows:
            if 'platform' not in row:
                enabled = any(self.flags[row['target_id']].values())
                reason = row['reason_code']
                row['platform'] = (_outcome(self.session.bridge.PLATFORM, enabled, 'ERROR', 'OUTCOME_UNKNOWN')
                                   if row['attempted'] else
                                   _outcome(self.session.bridge.PLATFORM, enabled, 'NOT_SCANNED',
                                            'DISABLED' if not enabled else reason if reason in _OUTCOMES['NOT_SCANNED'] else 'STOPPED'))
        return rows


class _ProducerSession:
    def __init__(self, rules):
        from tools import scan_collectors as bridge
        self.bridge = bridge
        self.rules = copy.deepcopy(rules)
        bridge.assessment.validate_rules(self.rules)
        self.handoff = None
        self.run_id = None
        self.started_at = None
        self.handlers = {}

    def _identity(self, ctx):
        import uuid
        self.run_id = ctx._request['run_id'] or 'i1a-' + uuid.uuid4().hex
        self.started_at = self.bridge.stamp()

    def prepare(self, ctx):
        self._identity(ctx)
        registry = self.bridge._producer_adapters()
        require(type(registry) is dict and registry.keys() <= set(self.bridge.PRODUCERS)
                and all(callable(v) for v in registry.values()), 3, 'INVALID_ADAPTER_REGISTRY')
        try:
            eligible = {n: self.bridge.requested(ctx._decisions[n]['requested_flags']) for n in ctx._targets}
        except self.bridge.BridgeError:
            raise Denied(2, 'UNSUPPORTED_PRODUCER') from None
        require(all(set(v) <= registry.keys() for v in eligible.values()), 2, 'PRODUCER_ADAPTER_NOT_AVAILABLE')
        ledger = _ProducerLedger(ctx, self, eligible)
        targets = [n for n in ctx._targets if eligible[n]]
        if targets:
            self.handoff = self.bridge.Handoff(self.run_id, targets)
        return registry, ledger

    def cancelled_before_prepare(self, ctx):
        if self.run_id is None:
            self._identity(ctx)
        return _ProducerLedger(ctx, self, {n: () for n in ctx._targets})

    def collect(self, name, flags, registry):
        """Called only after the unchanged native per-dispatch/argv guard."""
        b = self.bridge
        records = []
        try:
            with _deadline(_SSH_SECONDS):
                connected = _restricted_connection(name)
        except (_Deadline, Exception):
            connected = 'REMOTE_CLEANUP_UNCONFIRMED'
        if connected not in b.CONNECTIONS:
            connected = 'INVALID_ADAPTER_RESULT'
        if connected == 'CONNECTED':
            platform_snapshot = None
            for producer in b.requested(flags):
                value = None
                try:
                    # One bounded synthetic surrogate per producer. I1b must
                    # separately prove each actual remote command and cleanup.
                    with _deadline(_COMMAND_SECONDS + 1):
                        gap = producer != b.PLATFORM and b._platform_status(platform_snapshot) != 'UNVERIFIED'
                        if gap:
                            value = dict(reason_code='PLATFORM_GAP', rc=None, cleanup_confirmed=True,
                                         snapshot=b._gap_snapshot(producer, flags, b._platform_status(platform_snapshot)))
                        else:
                            value = registry[producer](name, copy.deepcopy(flags), copy.deepcopy(platform_snapshot))
                        row = b.record(producer, value, flags, platform_snapshot, self.run_id, name, gap=gap)
                except _Deadline:
                    row = b.failed_record(producer, 'REMOTE_CLEANUP_UNCONFIRMED')
                except Exception:
                    # A malformed projection is not a successful acquisition.
                    # Only a genuine adapter cleanup receipt permits the less
                    # severe invalid-result classification.
                    clean = type(value) is dict and value.get('cleanup_confirmed') is True
                    row = b.failed_record(producer, 'INVALID_ADAPTER_RESULT' if clean else 'REMOTE_CLEANUP_UNCONFIRMED', cleanup=clean)
                records.append(row)
                if producer == b.PLATFORM:
                    platform_snapshot = row['snapshot']
                    if platform_snapshot is None:
                        break
                if b.record_stop(row):
                    break
        envelope = dict(handoff_version=b.WIRE_VERSION, run_id=self.run_id, target_id=name,
                        connection=connected, records=records)
        return self.handoff.write(name, envelope)

    def close(self):
        if self.handoff is not None:
            handoff, self.handoff = self.handoff, None
            try:
                with _deadline(_WORKER_GRACE):
                    return handoff.close()
            except (_Deadline, OSError, self.bridge.BridgeError):
                return False
        return True

    def finish(self, ctx, ledger, interrupted):
        if not self.close():
            ledger.fail('CONTROLLER_CLEANUP_UNCONFIRMED')
            for name in ledger.started:
                ledger.worker_failed(name, 'CONTROLLER_CLEANUP_UNCONFIRMED')
        if interrupted():
            ledger.fail('INTERRUPTED')
        rows = ledger.finish()
        # Use the original B05 classification with platform excluded. Only
        # the actual V2 row contains expanded collection references.
        rc, base = _manifest(ctx, [_v2_base_row(r) for r in rows], ledger.stop)
        manifest = {**base, 'batch_manifest_version': 2, 'hosts': rows}
        validate_producer_manifest(manifest, rc)
        b = self.bridge
        hosts = [b.host_record(self.run_id, r['target_id'], r['host_state'], r['reason_code']) for r in rows]
        doc = b.document(self.run_id, self.started_at, hosts, manifest['run_state'], b.stamp())
        companions = {}
        for name, projection in ledger.projections.items():
            doc = b._append(doc, projection.document)
            companions[name] = projection.companions
        # Existing validator and evaluator keep their own document limits.
        # No truncation, second evaluator or fake Evidence on overflow.
        try:
            with _deadline(_GUARD_SECONDS):
                b.validate_bindings(manifest, doc, companions, ledger.projections)
                raw = b.evidence.canonical_bytes(doc)
                doc = b.evidence.parse_evidence_bytes(raw)
                assessed = b.assessment.evaluate_document(doc, self.rules)
                assessed = b.evidence.parse_evidence_bytes(b.evidence.canonical_bytes(assessed))
                # Keep the original interrupt handler active throughout the
                # bounded final evaluation. The evaluator's results depend on
                # host/evidence rows, not run_state; only update the run state.
                if interrupted() and rc != 7:
                    ledger.fail('INTERRUPTED')
                    rc, base = _manifest(ctx, [_v2_base_row(r) for r in rows], ledger.stop)
                    manifest = {**base, 'batch_manifest_version': 2, 'hosts': rows}
                    validate_producer_manifest(manifest, rc)
                    doc['run']['run_state'] = assessed['run']['run_state'] = manifest['run_state']
                    b.validate_bindings(manifest, doc, companions, ledger.projections)
                    b.evidence.validate_document(assessed)
        except _Deadline:
            raise Denied(3, 'PRODUCER_VALIDATION_TIMEOUT') from None
        except b.evidence.EvidenceError as exc:
            raise Denied(3, 'PRODUCER_EVIDENCE_SIZE_LIMIT' if exc.code == 'SIZE_LIMIT' else 'INVALID_PRODUCER_PROJECTION') from None
        return rc, manifest, dict(document=doc, assessed=assessed, companions=companions,
                                  handoff_metrics=ledger.metrics)


def execute_producer_batch(ctx, rules):
    """I1a private V2 API -> (rc, manifest, typed Controller bundle).

    No adapter/transport/path argument. Product registry remains empty; the
    only positive route is a trusted test-injected synthetic adapter.
    """
    session = _ProducerSession(rules)
    try:
        return _execute_batch(ctx, session)
    finally:
        # Covers before-dispatch denial and initialization/validation errors.
        try:
            if not session.close():
                raise Denied(3, 'CONTROLLER_CLEANUP_UNCONFIRMED') from None
        finally:
            for sig, previous in session.handlers.items():
                signal.signal(sig, previous)
