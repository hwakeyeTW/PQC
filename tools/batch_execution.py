"""Private S1 native context. No public entry point or managed dispatch.

This adapter is for an exclusive, trusted, isolated controller worker. The
private Ansible APIs below are version-gated; an unverified version is denied.
"""
import contextlib
import contextvars
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


# B: the validated configuration graph is bounded before native parsing.
# Implicit source qualification is separate from the synthetic source seam.
_CONFIG_FILES = 32
_CONFIG_DEPTH = 8
_CONFIG_TOTAL = 256 * 1024
_CONFIG_FILE = 64 * 1024
_CONFIG_EXPANSIONS = 32
_CONFIG_ENUM = 256
_SENDENV_DIRECTIVE = 32
_SENDENV_CLOSURE = 128
_SENDENV_NAMES = frozenset(('LANG', 'LANGUAGE', 'LC_*', 'LC_ALL', 'LC_CTYPE',
                            'LC_NUMERIC', 'LC_TIME', 'LC_COLLATE', 'LC_MONETARY',
                            'LC_MESSAGES', 'LC_PAPER', 'LC_NAME', 'LC_ADDRESS',
                            'LC_TELEPHONE', 'LC_MEASUREMENT', 'LC_IDENTIFICATION',
                            'COLORTERM', 'NO_COLOR', 'XMODIFIERS'))


def _sendenv(value):
    # Syntax only. Do not consult or expand the local environment. OpenSSH
    # owns order, duplicates and removal of these exact allowed patterns.
    tokens = _literal(value).split()
    require(0 < len(tokens) <= _SENDENV_DIRECTIVE and
            all(t in _SENDENV_NAMES or t.startswith('-') and t[1:] in _SENDENV_NAMES
                for t in tokens), 4, 'UNSUPPORTED_SSH_OPTION')
    return tokens
_MUX = frozenset(('controlmaster', 'controlpersist', 'controlpath'))
_NO_MUX = ('-o', 'ControlMaster=no', '-o', 'ControlPersist=no', '-o', 'ControlPath=none')
_NO_MUX_CONFIG = b'ControlMaster no\nControlPersist no\nControlPath none\n'
_OPTION = frozenset(('port', 'user', 'identityfile', 'identitiesonly', 'stricthostkeychecking',
                     'userknownhostsfile', 'globalknownhostsfile', 'connecttimeout', 'batchmode',
                     'controlmaster', 'controlpersist', 'controlpath', 'proxyjump', 'canonicalizehostname',
                     'passwordauthentication', 'kbdinteractiveauthentication', 'preferredauthentications',
                     'compression', 'loglevel', 'serveraliveinterval', 'serveralivecountmax', 'numberofpasswordprompts',
                     'ciphers', 'macs', 'kexalgorithms', 'hostkeyalgorithms', 'pubkeyacceptedalgorithms',
                     'casignaturealgorithms', 'hostbasedacceptedalgorithms',
                     'sendenv', 'hashknownhosts'))


def _mux_path(value, ansible=False):
    value = _literal(value)
    if ansible and value.startswith('%(directory)s/'):
        value = '/pqc-control-dir/' + value[len('%(directory)s/'):]
    # Syntax only: never expand, stat, create or connect to a mux pathname.
    require(value.lower() == 'none' or re.fullmatch(r'(?:/|~/)[A-Za-z0-9_./%+-]+', value)
            and not any(x == '..' for x in value.split('/'))
            and not re.search(r'%(?![%CdhijkLlnpru])', value), 4, 'UNSUPPORTED_SSH_OPTION')


def _option(key, value):
    key, value = key.lower(), _literal(value)
    if key == 'sendenv':
        _sendenv(value)
        return key, value
    if value.startswith('"') and value.endswith('"'):
        value = value[1:-1]
    require(key in _OPTION and value, 4, 'UNSUPPORTED_SSH_OPTION')
    if key == 'hashknownhosts':
        require(value.lower() in ('yes', 'no'), 4, 'UNSUPPORTED_SSH_OPTION')
        return key, value
    if key == 'controlpath':
        _mux_path(value)
        return key, value
    require(re.fullmatch(r'[A-Za-z0-9_./@:,=*!?+~%-]+', value), 4, 'UNSUPPORTED_SSH_OPTION')
    if key in ('port', 'connecttimeout', 'serveraliveinterval', 'serveralivecountmax'):
        require(value.isdecimal() and len(value) <= 6, 4, 'UNSUPPORTED_SSH_OPTION')
        number = int(value)
        require((1 <= number <= 65535 if key == 'port' else 1 <= number <= 15
                 if key == 'connecttimeout' else 0 <= number <= 60), 4, 'UNSUPPORTED_SSH_OPTION')
    elif key == 'numberofpasswordprompts':
        require(value == '1', 4, 'UNSUPPORTED_SSH_OPTION')
    elif key == 'user':
        require(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}', value), 4, 'UNSUPPORTED_SSH_OPTION')
    elif key == 'stricthostkeychecking':
        require(value.lower() in ('yes', 'ask'), 4, 'HOST_KEY_CHECKING_REQUIRED')
    elif key in ('canonicalizehostname', 'passwordauthentication', 'kbdinteractiveauthentication'):
        require(value.lower() == 'no', 4, 'UNSUPPORTED_SSH_OPTION')
    elif key == 'controlmaster':
        require(value.lower() in ('no', 'yes', 'auto', 'autoask', 'ask'), 4, 'UNSUPPORTED_SSH_OPTION')
    elif key == 'controlpersist':
        if value.lower() not in ('no', 'yes'):
            # OpenSSH accepts compound literal durations (e.g. 1h30m).
            # Bound syntax and total before the scan-only no-mux override;
            # never expand the value or extend the existing seven-day cap.
            duration = value.lower()
            require(len(duration) <= 64 and
                    re.fullmatch(r'(?:[0-9]{1,6}[smhdw])*[0-9]{1,6}[smhdw]?', duration),
                    4, 'UNSUPPORTED_SSH_OPTION')
            units = {'':1, 's':1, 'm':60, 'h':3600, 'd':86400, 'w':604800}
            require(sum(int(n) * units[u] for n, u in re.findall(r'([0-9]+)([smhdw]?)', duration)) <= 604800,
                    4, 'UNSUPPORTED_SSH_OPTION')
    elif key == 'batchmode':
        require(value.lower() == 'yes', 4, 'UNSUPPORTED_SSH_OPTION')
    elif key in ('identityfile', 'userknownhostsfile', 'globalknownhostsfile'):
        require(re.fullmatch(r'(?:/|~/)[A-Za-z0-9_./+-]+', value) and '..' not in value.split('/'),
                4, 'UNSUPPORTED_SSH_OPTION')
        p = (_passwd_ssh_dir().parent / value[2:] if value.startswith('~/') else Path(value))
        require(p.is_absolute() and p.resolve() != Path('/dev/null'), 4, 'UNSUPPORTED_SSH_OPTION')
    elif key == 'proxyjump':
        if value.lower() != 'none':
            require(len(value.split(',')) <= _CONFIG_FILES, 4, 'UNSUPPORTED_SSH_OPTION')
            for jump in value.split(','):
                match = re.fullmatch(r'(?:([A-Za-z_][A-Za-z0-9_.-]{0,63})@)?([A-Za-z0-9][A-Za-z0-9.-]*)(?::([0-9]{1,5}))?', jump)
                require(match is not None, 4, 'UNSUPPORTED_SSH_OPTION')
                _address(match[2])
                require(match[3] is None or 1 <= int(match[3]) <= 65535, 4, 'UNSUPPORTED_SSH_OPTION')
    else:
        # Non-mux options never carry tokens, shell syntax or variable expansion.
        require(not re.search(r'[%~?]', value), 4, 'UNSUPPORTED_SSH_OPTION')
    return key, value


def _args(tokens):
    configs, options = [], []
    i = 0
    while i < len(tokens):
        arg = _literal(tokens[i]); i += 1
        if arg == '-C':
            continue
        require(arg in ('-F', '-o') and i < len(tokens), 4, 'UNSUPPORTED_SSH_OPTION')
        value = _literal(tokens[i]); i += 1
        if arg == '-F':
            _config_path(value)
            configs.append(value)
        else:
            key, sep, val = value.partition('=')
            require(sep == '=', 4, 'UNSUPPORTED_SSH_OPTION')
            options.append(_option(key, val))
    require(sum(len(_sendenv(v)) for k, v in options if k == 'sendenv') <= _SENDENV_CLOSURE,
            4, 'SSH_CONFIG_LIMIT')
    require(len(configs) <= 1, 4, 'SSH_CONFIG_UNVERIFIED')
    return configs[0] if configs else None, tuple(options)


def _config_path(value, pattern=False):
    chars = r'[A-Za-z0-9_.+*?\[\]-]' if pattern else r'[A-Za-z0-9_.+-]'
    require(isinstance(value, str) and len(value) <= 4096 and value.startswith('/')
            and all(x not in ('', '.', '..') and re.fullmatch(chars + '+', x)
                    for x in value.split('/')[1:]), 4, 'SSH_CONFIG_UNVERIFIED')
    return Path(value)


def _passwd_ssh_dir():
    import pwd
    try:
        return _config_path(pwd.getpwuid(os.geteuid()).pw_dir) / '.ssh'
    except (KeyError, OSError, UnicodeError):
        raise Denied(4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED') from None


# Fixed, extensible build contracts, not an OS-version guess or a runtime
# allowlist supplied by Inventory. The signed-package evidence in #8
# 7140990021 identifies this archive and ELF. The same archive ships
# /etc/ssh/ssh_config and ssh(1)/ssh_config(5), which explicitly document
# the default per-user and system paths and first-set order. Unknown or
# rebuilt clients are unqualified until their own contract is established.
_IMPLICIT_BUILDS = {
    (1047584, 'af3b04ec5653755032fc18ad02445e4e51170e75d8bac4265647d423caa9a83e'):
        ('Debian openssh-client 1:10.0p1-7+deb13u4 amd64', '/etc/ssh'),
}


def _qualified_implicit_client(binary):
    # Only _fixed_ssh selects the product binary. A private native test may
    # exercise this exact same qualification on an approved local copy.
    events = []
    try:
        owner = 0 if binary == Path('/usr/bin/ssh') else os.geteuid()
        with _directory(binary.parent, events, owner=owner, managed_root=binary.parent) as fd:
            st = os.stat(binary.name, dir_fd=fd, follow_symlinks=False)
            _trusted_stat(st, owner=owner)
            require(0 < st.st_size <= 16 * 1024**2
                    and st.st_mode & 0o111 and not st.st_mode & 0o7000,
                    4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
            flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
            with os.fdopen(os.open(binary.name, flags, dir_fd=fd), 'rb') as stream:
                before = _node_id(os.fstat(stream.fileno()), True)
                require(before == _node_id(st, True), 4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
                raw = stream.read(st.st_size + 1)
                require(len(raw) == st.st_size and before == _node_id(os.fstat(stream.fileno()), True)
                        and before == _node_id(os.stat(binary.name, dir_fd=fd, follow_symlinks=False), True),
                        4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
            digest = hashlib.sha256(raw).hexdigest()
            build = _IMPLICIT_BUILDS.get((st.st_size, digest))
            if build is not None:
                return Path(build[1]), (build[0], digest, before, tuple(events))
            return _ol9_qualified_client(binary, raw, before, tuple(events))
    except (OSError, ValueError, Denied):
        raise Denied(4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED') from None



# OL9 stock installed-package contract: Oracle ELSA-2026-13381 (8.7p1)
# and ELSA-2026-19219 (9.9p1), Oracle OpenSSH client documentation,
# and OL9 RPM 4.16/SQLite. The existing trusted OS/admin and RPM DB are
# the local authority, not a fresh signature or remote attestation.
_OL9_SSH = Path('/usr/bin/ssh')
_OL9_RPM = Path('/usr/bin/rpm')
_OL9_OS_RELEASE = Path('/etc/os-release')
_OL9_OS_RELEASE_TARGET = Path('/usr/lib/os-release')
_OL9_RPM_DB = Path('/var/lib/rpm')
_OL9_RPM_RC = Path('/usr/lib/rpm/rpmrc')
_OL9_RPM_MACROS = Path('/usr/lib/rpm/macros')
_OL9_OWNER = 0
_OL9_DIGESTS = {'8': 'sha256', '9': 'sha384', '10': 'sha512'}
_OL9_QF = ('PQC_PACKAGE\t%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t'
           '%{VENDOR}\t%{SOURCERPM}\t%{FILEDIGESTALGO}\n'
           '[PQC_FILE\t%{FILENAMES}\t%{FILESIZES}\t%{FILEDIGESTS}\n]')
_RPM_PROOF = contextvars.ContextVar('_pqc_rpm_proof', default=None)


def _ol9_file(path, cap, executable=False):
    events = []
    with _directory(path.parent, events, owner=_OL9_OWNER, managed_root=path.parent) as fd:
        st = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        _trusted_stat(st, owner=_OL9_OWNER)
        require(0 < st.st_size <= cap and not st.st_mode & 0o7000
                and (not executable or st.st_mode & 0o111), 4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
        identity = _node_id(st, True)
        with os.fdopen(os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=fd), 'rb') as stream:
            require(_node_id(os.fstat(stream.fileno()), True) == identity,
                    4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
            raw = stream.read(st.st_size + 1)
            require(len(raw) == st.st_size and _node_id(os.fstat(stream.fileno()), True) == identity
                    and _node_id(os.stat(path.name, dir_fd=fd, follow_symlinks=False), True) == identity,
                    4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
    return raw, (str(path), identity, tuple(events), hashlib.sha256(raw).hexdigest())


def _ol9_identity():
    # /etc/os-release takes precedence; admit only the stock link to
    # /usr/lib/os-release, not an arbitrary administrator/user pathname.
    path = _OL9_OS_RELEASE
    events = []
    with _directory(path.parent, events, owner=_OL9_OWNER, managed_root=path.parent) as fd:
        st = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        source = _node_id(st, True)
        if stat.S_ISLNK(st.st_mode):
            link = os.readlink(path.name, dir_fd=fd)
            require(st.st_uid == _OL9_OWNER and st.st_nlink == 1
                    and link in ('../usr/lib/os-release', '/usr/lib/os-release'),
                    4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
            path = _OL9_OS_RELEASE_TARGET
        raw, proof = _ol9_file(path, 16384)
        require(_node_id(os.stat(_OL9_OS_RELEASE.name, dir_fd=fd, follow_symlinks=False), True) == source,
                4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
    fields = {}
    for line in raw.decode('ascii').splitlines():
        key, sep, value = line.partition('=')
        if key not in ('ID', 'VERSION_ID'):
            continue
        require(sep and key not in fields, 4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        fields[key] = value
    require(fields.get('ID') == 'ol' and re.fullmatch(r'9(?:\.[0-9]+)?', fields.get('VERSION_ID', '')),
            4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
    arch = os.uname().machine
    require(arch in ('x86_64', 'aarch64'), 4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
    return arch, (tuple(events), source, proof, tuple(sorted(fields.items())))


def _ol9_db_identity():
    # Only the fixed OL9 SQLite DB and its known sidecars; never enumerate
    # the package inventory or read DB contents directly. Absence is bound.
    events = []
    with _directory(_OL9_RPM_DB, events, owner=_OL9_OWNER, managed_root=_OL9_RPM_DB) as fd:
        entries = []
        ds = _node_id(os.fstat(fd), True)
        for name in ('rpmdb.sqlite', 'rpmdb.sqlite-wal', 'rpmdb.sqlite-shm', '.rpm.lock'):
            try:
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                require(name != 'rpmdb.sqlite', 4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
                entries.append((name, None)); continue
            _trusted_stat(st, owner=_OL9_OWNER)
            require(name != 'rpmdb.sqlite' or st.st_size > 0, 4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
            entries.append((name, _node_id(st, True)))
        require(_node_id(os.fstat(fd), True) == ds, 4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
    return tuple(events), ds, tuple(entries)


def _ol9_metadata(out, raw, arch):
    # Exactly one owner package and one record for the fixed binary. The
    # array is from that one package only; other files are never opened.
    require(len(out) <= 65536 and not re.search(rb'[\x00-\x08\x0b-\x1f\x7f]', out),
            4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
    rows = out.decode('ascii').splitlines()
    require(2 <= len(rows) <= 257, 4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
    header = rows[0].split('\t')
    require(len(header) == 9 and header[0] == 'PQC_PACKAGE', 4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
    name, epoch, version, release, package_arch, vendor, source, algo = header[1:]
    require(name == 'openssh-clients' and (epoch == '(none)' or re.fullmatch(r'[0-9]{1,4}', epoch))
            and version in ('8.7p1', '9.9p1')
            and re.fullmatch(r'[0-9][A-Za-z0-9.]*\.el9(?:_[0-9]+)?(?:\.[0-9]+)*', release)
            and package_arch == arch and vendor == 'Oracle America'
            and source == 'openssh-' + version + '-' + release + '.src.rpm'
            and algo in _OL9_DIGESTS, 4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
    files = {}
    for line in rows[1:]:
        fields = line.split('\t')
        require(len(fields) == 4 and fields[0] == 'PQC_FILE' and fields[1].startswith('/')
                and fields[1] not in files, 4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
        files[fields[1]] = tuple(fields[2:])
    require('/usr/bin/ssh' in files and '/etc/ssh/ssh_config' in files,
            4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
    size, digest = files['/usr/bin/ssh']
    actual = hashlib.new(_OL9_DIGESTS[algo], raw).hexdigest()
    require(size.isascii() and size.isdecimal() and len(size) <= 9 and int(size) == len(raw)
            and digest == actual, 4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
    return tuple(header[1:]), (size, digest)


def _ol9_qualified_client(binary, raw, before, events):
    require(binary == _OL9_SSH, 4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
    # Same fixed paths and actual file identities at every recheck. During
    # one destination/jump proof reuse only a result for the exact same
    # state; a new proof or dispatch obtains fresh RPM metadata. No TTL.
    def local_state():
        arch, os_proof = _ol9_identity()
        _, rpm_proof = _ol9_file(_OL9_RPM, 16 * 1024**2, executable=True)
        _, rc_proof = _ol9_file(_OL9_RPM_RC, 256 * 1024)
        _, macros_proof = _ol9_file(_OL9_RPM_MACROS, 256 * 1024)
        return arch, os_proof, rpm_proof, rc_proof, macros_proof, _ol9_db_identity()
    local = local_state()
    state = (before, events, hashlib.sha256(raw).hexdigest(), local)
    cache = _RPM_PROOF.get()
    if cache is not None and cache:
        require(cache[0] == state, 4, 'CONNECTION_CONTEXT_DRIFT')
        metadata = cache[1]
    else:
        # The stock rpm query is read-only, no verify scripts, plugins,
        # user macros or arbitrary caller-selected query/path. Fixed macro
        # inputs are trusted files, with an explicit SQLite DB location.
        left = signal.getitimer(signal.ITIMER_REAL)[0]
        budget = min(5, left - 0.05) if left > 0 else 5
        require(budget > 0, 4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
        argv = [str(_OL9_RPM), '--noplugins', '--rcfile', str(_OL9_RPM_RC),
                '--macros', str(_OL9_RPM_MACROS), '--dbpath', str(_OL9_RPM_DB),
                '--define', '_db_backend sqlite', '-qf', '--queryformat', _OL9_QF, '/usr/bin/ssh']
        rc, out, err = _scope.bounded_command(argv, {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/'},
                                               timeout=budget, out_cap=65536, err_cap=65536)
        require(rc == 0 and not err and local_state() == local, 4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
        # Recheck the selected executable after metadata acquisition as well.
        current, identity = _ol9_file(binary, 16 * 1024**2, executable=True)
        require(current == raw and identity[1] == before and identity[2] == events,
                4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED')
        metadata = _ol9_metadata(out, raw, local[0])
        if cache is not None:
            cache.extend((state, metadata))
    return Path('/etc/ssh'), ('Oracle Linux 9 installed openssh-clients', metadata, state)

def _implicit_roots():
    try:
        system, binding = _qualified_implicit_client(_fixed_ssh((b'/usr/bin/ssh',)))
        return _passwd_ssh_dir(), system, binding
    except (OSError, ValueError, Denied):
        raise Denied(4, 'SSH_IMPLICIT_ROOT_UNQUALIFIED') from None


def _managed_config_roots():
    # No Inventory, CLI, environment or user-config path can designate an
    # OS-managed trust root. Tests exercise the same checks on isolated trees.
    return (Path('/etc/ssh'), Path('/etc/crypto-policies'), Path('/usr/share/crypto-policies')), 0


def _trusted_stat(s, directory=False, owner=None):
    sticky = owner is None and directory and s.st_uid == 0 and bool(s.st_mode & stat.S_ISVTX)
    owners = (0, os.geteuid()) if owner is None else (owner,)
    require(s.st_uid in owners and (not s.st_mode & 0o022 or sticky),
            4, 'SSH_CONFIG_UNVERIFIED')
    require(stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink == 1,
            4, 'SSH_CONFIG_UNVERIFIED')


def _node_id(s, content=False):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid) + (
        (s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns) if content else ())


@contextlib.contextmanager
def _directory(path, events, absent=False, owner=None, managed_root=None):
    # Pin every traversed directory with no-follow directory descriptors.
    # Production system roots require root-owned, non-writable ancestors too.
    # The nonzero owner form is used solely with private synthetic roots.
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        _trusted_stat(os.fstat(fd), True, owner=0 if owner == 0 else None)
        current = Path('/')
        for part in path.parts[1:]:
            current = current / part
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                require(absent, 4, 'SSH_CONFIG_UNVERIFIED')
                events.append(('missing-dir', str(path), _node_id(os.fstat(fd), True), part))
                yield None
                return
            os.close(fd); fd = child
            ds = os.fstat(fd)
            strict = owner if owner == 0 or (managed_root is not None and _is_under(current, managed_root)) else None
            _trusted_stat(ds, True, owner=strict)
            events.append(('directory', part, _node_id(ds)))
        yield fd
    finally:
        os.close(fd)


def _is_under(path, root):
    return path == root or root in path.parents


def _config_name(path):
    # Never treat key, known-host or arbitrary file names in an Include glob
    # as candidate configuration. Explicit -F remains an operator config path.
    name = path.name.lower()
    return name in ('config', 'ssh_config') or name.endswith(('.conf', '.config'))


class _ConfigClosure:
    def __init__(self, path):
        self.path = path
        self.events, self.files, self.roots = [], {}, []
        self.total = self.expansions = self.enumerated = self.links = self.sendenv = 0
        self.overlay = path is None
        self.managed, self.managed_owner = _managed_config_roots()
        user = _passwd_ssh_dir()
        if path is None:
            user, system, binding = _implicit_roots()
            self.events.append(('implicit-client', binding, str(user), str(system)))
            roots = ((user / 'config', user, True), (system / 'ssh_config', system, True))
        else:
            p = _config_path(path)
            roots = ((p, user, False),)
            system = self.managed[0]
        self.allowed = {user, system, *self.managed}
        if path is not None:
            # An explicit private config directory is an additional trusted
            # absolute Include root; relative Include still uses passwd .ssh.
            parent = Path(path).parent
            if parent != Path('/'):
                with _directory(parent, self.events) as fd:
                    ds = os.fstat(fd)
                    if ds.st_uid == os.geteuid() and stat.S_IMODE(ds.st_mode) == 0o700:
                        self.allowed.add(parent)
        try:
            for p, relative, absent in roots:
                self.roots.append(self.visit(p, relative, (), 0, absent))
        except (OSError, UnicodeError, ValueError):
            raise Denied(4, 'SSH_CONFIG_UNVERIFIED') from None
        self.fingerprint = hashlib.sha256(repr((self.roots, self.events)).encode('utf-8')).hexdigest()

    def managed_root(self, path):
        return next((r for r in self.managed if _is_under(path, r)), None)

    def directory(self, path, absent=False):
        root = self.managed_root(path)
        return _directory(path, self.events, absent=absent,
                          owner=self.managed_owner if root is not None else None,
                          managed_root=root)

    def link_target(self, path, value):
        # Relative links may traverse pinned ancestors (leading ../ only).
        # Reject ambiguous a/../b, intermediate symlinks, unverified roots
        # and secret-name targets before opening a target file.
        require(isinstance(value, str) and len(value) <= 4096 and value,
                4, 'SSH_CONFIG_OS_LINK_UNQUALIFIED')
        if value.startswith('/'):
            target = _config_path(value)
        else:
            parts = value.split('/')
            parent = path.parent
            if parts[0] == '.':
                parts.pop(0)
            while parts and parts[0] == '..':
                require(parent != Path('/'), 4, 'SSH_CONFIG_OS_LINK_UNQUALIFIED')
                parent = parent.parent; parts.pop(0)
            require(parts and all(re.fullmatch(r'[A-Za-z0-9_.+-]+', x) and x not in ('.', '..') for x in parts),
                    4, 'SSH_CONFIG_OS_LINK_UNQUALIFIED')
            target = _config_path(str(parent.joinpath(*parts)))
        root = self.managed_root(target)
        # Distribution crypto-policy client backends commonly use a .txt
        # target; admit only the named OpenSSH client policy basename there.
        require(root is not None and root != target and
                ((_config_name(target) if root == self.managed[0] else
                  target.name in ('openssh.config', 'openssh.txt')))
                and not re.search(r'^(?:id_|known_hosts|authorized_keys)|\.(?:pem|key|p12|pfx)$', target.name, re.I),
                4, 'SSH_CONFIG_OS_LINK_UNQUALIFIED')
        return target

    def read(self, path, absent, links=()):
        root = self.managed_root(path)
        owner = self.managed_owner if root is not None else None
        with self.directory(path.parent, absent=absent) as fd:
            if fd is None:
                self.events.append(('absent', str(path)))
                return None
            try:
                st = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                require(absent, 4, 'SSH_CONFIG_UNVERIFIED')
                self.events.append(('absent', str(path), _node_id(os.fstat(fd), True)))
                return None
            if stat.S_ISLNK(st.st_mode):
                require(root is not None, 4, 'SSH_CONFIG_UNVERIFIED')
                require((root == self.managed[0] and _config_name(path) or
                         root in self.managed[1:] and path.name in ('openssh.config', 'openssh.txt'))
                        and st.st_uid == owner and st.st_nlink == 1
                        and path not in links and len(links) < _CONFIG_DEPTH,
                        4, 'SSH_CONFIG_OS_LINK_UNQUALIFIED')
                self.links += 1
                require(self.links <= _CONFIG_EXPANSIONS, 4, 'SSH_CONFIG_LIMIT')
                parent = _node_id(os.fstat(fd), True)
                identity = _node_id(st, True)
                value = os.readlink(path.name, dir_fd=fd)
                target = self.link_target(path, value)
                self.events.append(('os-link', str(path), identity, parent, value, str(target)))
                raw = self.read(target, False, (*links, path))
                require(raw is not None and parent == _node_id(os.fstat(fd), True)
                        and identity == _node_id(os.stat(path.name, dir_fd=fd, follow_symlinks=False), True)
                        and value == os.readlink(path.name, dir_fd=fd), 4, 'CONNECTION_CONTEXT_DRIFT')
                return raw
            _trusted_stat(st, owner=owner)
            require(st.st_size <= _CONFIG_FILE, 4, 'SSH_CONFIG_LIMIT')
            f = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
            with os.fdopen(f, 'rb') as stream:
                before = os.fstat(stream.fileno()); _trusted_stat(before, owner=owner)
                require(_node_id(before, True) == _node_id(st, True), 4, 'CONNECTION_CONTEXT_DRIFT')
                require(before.st_size <= _CONFIG_FILE, 4, 'SSH_CONFIG_LIMIT')
                raw = stream.read(_CONFIG_FILE + 1)
                require(len(raw) <= _CONFIG_FILE and len(raw) == before.st_size
                        and _node_id(before, True) == _node_id(os.fstat(stream.fileno()), True)
                        and _node_id(before, True) == _node_id(os.stat(path.name, dir_fd=fd, follow_symlinks=False), True),
                        4, 'SSH_CONFIG_LIMIT_OR_DRIFT')
                self.events.append(('file', str(path), _node_id(before, True), hashlib.sha256(raw).hexdigest()))
                return raw

    def matches(self, value, relative):
        import fnmatch
        require(re.fullmatch(r'[A-Za-z0-9_./+*?\[\]~-]+', value) is not None,
                4, 'SSH_CONFIG_UNVERIFIED')
        require('..' not in value.split('/') and '.' not in value.split('/')
                and '//' not in value, 4, 'SSH_CONFIG_UNVERIFIED')
        if value.startswith('~/'):
            path = _passwd_ssh_dir().parent / value[2:]
        elif value.startswith('/'):
            path = Path(value)
        else:
            path = relative / value
        _config_path(str(path), pattern=True)
        bases = sorted((r for r in self.allowed if _is_under(path, r)), key=lambda r: -len(r.parts))
        require(bases and path != bases[0], 4, 'SSH_CONFIG_INCLUDE_UNVERIFIED')
        base = bases[0]; parts = path.relative_to(base).parts
        wildcard = any(re.search(r'[*?\[]', part) for part in parts)
        if wildcard:
            require((os.environ.get('LC_ALL') or os.environ.get('LC_COLLATE') or os.environ.get('LANG') or 'C')
                    in ('C', 'C.UTF-8', 'C.utf8', 'POSIX'), 4, 'SSH_CONFIG_GLOB_ORDER_UNVERIFIED')
        current = [base]
        for part in parts:
            if not re.search(r'[*?\[]', part):
                current = [x / part for x in current]
                continue
            found = []
            for parent in current:
                with self.directory(parent, absent=True) as fd:
                    if fd is None:
                        continue
                    before = _node_id(os.fstat(fd), True)
                    with os.scandir(fd) as it:
                        for item in it:
                            self.enumerated += 1
                            require(self.enumerated <= _CONFIG_ENUM, 4, 'SSH_CONFIG_LIMIT')
                            if (not item.name.startswith('.') or part.startswith('.')) and fnmatch.fnmatchcase(item.name, part):
                                _config_path(str(parent / item.name)); found.append(parent / item.name)
                    require(before == _node_id(os.fstat(fd), True), 4, 'CONNECTION_CONTEXT_DRIFT')
                    self.events.append(('glob-dir', str(parent), before))
            current = found
        current.sort(key=lambda p: os.fsencode(str(p)))
        require(len(current) <= _CONFIG_FILES and all(_config_name(p) for p in current), 4, 'SSH_CONFIG_INCLUDE_UNVERIFIED')
        self.events.append(('include', value, str(relative), tuple(map(str, current))))
        return current, wildcard

    def visit(self, path, relative, chain, depth, absent=False):
        require(depth <= _CONFIG_DEPTH and path not in chain, 4, 'SSH_CONFIG_LIMIT_OR_CYCLE')
        # Explicit root is operator-selected configuration, not a key or
        # known-host input. Included files have the closed config-name gate.
        require(not re.search(r'^(?:id_|known_hosts|authorized_keys)|\.(?:pem|key|p12|pfx)$', path.name, re.I),
                4, 'SSH_CONFIG_INCLUDE_UNVERIFIED')
        raw = self.read(path, absent)
        if raw is None:
            return None
        self.expansions += 1; self.total += len(raw)
        require(self.expansions <= _CONFIG_EXPANSIONS and self.total <= _CONFIG_TOTAL
                and len(self.files) < _CONFIG_FILES, 4, 'SSH_CONFIG_LIMIT')
        require(not re.search(rb'[\x00-\x08\x0b-\x1f\x7f]', raw), 4, 'SSH_CONFIG_UNVERIFIED')
        parts = []
        for line in raw.decode('ascii').splitlines(keepends=True):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                parts.append(line.encode('ascii')); continue
            # Closed syntax, not a shell interpreter. Native parser owns Host
            # and Match final application and first-set option precedence.
            fields = stripped.split(); key = fields[0].lower(); values = fields[1:]
            if key == 'host':
                require(values and all(re.fullmatch(r'!?[A-Za-z0-9_.?*-]+', x) for x in values),
                        4, 'SSH_CONFIG_UNVERIFIED')
            elif key == 'match':
                require([v.lower() for v in values] == ['final', 'all'], 4, 'SSH_CONFIG_UNVERIFIED')
            elif key == 'include':
                require(values, 4, 'SSH_CONFIG_UNVERIFIED')
                children = []
                for value in values:
                    matches, wildcard = self.matches(value, relative)
                    children.extend(self.visit(p, relative, (*chain, path), depth + 1, wildcard) for p in matches)
                parts.append(('include', tuple(children))); continue
            elif key == 'sendenv':
                _, value = _option(key, ' '.join(values))
                self.sendenv += len(_sendenv(value))
                require(self.sendenv <= _SENDENV_CLOSURE, 4, 'SSH_CONFIG_LIMIT')
            else:
                require(len(values) == 1, 4, 'SSH_CONFIG_UNVERIFIED')
                k,v = _option(key, values[0])
                if k in _MUX and v.lower() not in {'controlmaster': ('no',), 'controlpersist': ('no','0'), 'controlpath': ('none',)}[k]:
                    self.overlay = True
            parts.append(line.encode('ascii'))
        node = (str(path), str(relative))
        if node in self.files:
            require(self.files[node] == parts, 4, 'CONNECTION_CONTEXT_DRIFT')
        self.files[node] = parts
        return node


def _config(path):
    try:
        return _ConfigClosure(path).fingerprint
    except (OSError, UnicodeError, ValueError):
        raise Denied(4, 'SSH_CONFIG_UNVERIFIED') from None


@contextlib.contextmanager
def _validated_snapshot(path, fingerprint):
    try:
        closure = _ConfigClosure(path)
    except (OSError, UnicodeError, ValueError):
        raise Denied(4, 'SSH_CONFIG_UNVERIFIED') from None
    require(closure.fingerprint == fingerprint, 4, 'CONNECTION_CONTEXT_DRIFT')
    try:
        temporary = tempfile.TemporaryDirectory(prefix='pqc-ssh-', dir='/tmp')
    except OSError:
        raise Denied(4, 'SSH_CONFIG_SNAPSHOT_ERROR') from None
    try:
        try:
            directory = Path(temporary.name); ds = directory.lstat()
            require(directory.resolve(strict=True) == directory and stat.S_ISDIR(ds.st_mode)
                    and stat.S_IMODE(ds.st_mode) == 0o700 and ds.st_uid == os.geteuid(),
                    4, 'SSH_CONFIG_SNAPSHOT_ERROR')
            snapshot = directory / 'config'
            names = {node: directory / ('source-%02d.conf' % i) for i, node in enumerate(closure.files)}
            if not closure.overlay and len(closure.roots) == 1 and closure.roots[0] is not None:
                names[closure.roots[0]] = snapshot
            def write(p, raw):
                flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                with os.fdopen(os.open(p, flags, 0o600), 'w+b') as f:
                    fs = os.fstat(f.fileno())
                    require(stat.S_ISREG(fs.st_mode) and stat.S_IMODE(fs.st_mode) == 0o600
                            and fs.st_uid == os.geteuid() and fs.st_nlink == 1, 4, 'SSH_CONFIG_SNAPSHOT_ERROR')
                    require(f.write(raw) == len(raw), 4, 'SSH_CONFIG_SNAPSHOT_ERROR')
                    f.flush(); f.seek(0); require(f.read(len(raw)+1) == raw, 4, 'SSH_CONFIG_SNAPSHOT_ERROR')
            for node, parts in closure.files.items():
                data = []
                for part in parts:
                    if isinstance(part, bytes):
                        data.append(part)
                    else:
                        children = [os.fsencode(names[x]) for x in part[1] if x is not None]
                        data.append(b'Include ' + (b' '.join(children) if children else os.fsencode(directory/'empty-*')) + b'\n')
                write(names[node], b''.join(data))
            if snapshot not in names.values():
                roots = [os.fsencode(names[x]) for x in closure.roots if x is not None]
                write(snapshot, _NO_MUX_CONFIG + b''.join(b'Include ' + p + b'\n' for p in roots))
        except (OSError, ValueError):
            raise Denied(4, 'SSH_CONFIG_SNAPSHOT_ERROR') from None
        yield str(snapshot)
    finally:
        try:
            temporary.cleanup()
        except OSError:
            raise Denied(4, 'SSH_CONFIG_SNAPSHOT_CLEANUP_FAILED') from None


_MUX_OPTIONS = ('ssh_args', 'ssh_common_args', 'ssh_extra_args', 'control_path', 'control_path_dir')


def _native_raw(conn):
    raw = tuple(_scalar(conn.get_option(k)) for k in _MUX_OPTIONS)
    require(all(v is None or isinstance(v, str) for v in raw), 4, 'UNSUPPORTED_SSH_OPTION')
    try:
        tokens = [shlex.split(_literal(v or '')) for v in raw[:3]]
    except ValueError:
        raise Denied(4, 'UNSUPPORTED_SSH_OPTION') from None
    for group in tokens:
        _args(group)
    path, _ = _args([x for group in tokens for x in group])
    for v in raw[3:]:
        if v:
            _mux_path(v, ansible=True)
    return raw, tokens, path


@contextlib.contextmanager
def _no_mux(conn):
    raw, groups, _ = _native_raw(conn)
    saved = {k: getattr(conn, k, None) for k in ('_persistent','control_path','control_path_dir')}
    try:
        for i, (k, tokens) in enumerate(zip(_MUX_OPTIONS[:3], groups)):
            normalized = list(_NO_MUX) if i == 0 else []
            j = 0
            while j < len(tokens):
                if tokens[j] == '-o' and tokens[j+1].partition('=')[0].lower() in _MUX:
                    j += 2
                else:
                    normalized.append(tokens[j]); j += 1
            conn.set_option(k, shlex.join(normalized))
        conn.set_option('control_path', None)
        yield
    finally:
        for k, v in zip(_MUX_OPTIONS, raw):
            conn.set_option(k, v)
        for k, v in saved.items():
            setattr(conn, k, v)


@contextlib.contextmanager
def _consume_builder(conn, expected_raw, end=None):
    original = conn._build_command
    def build(*args, **kwargs):
        def consume():
            require(_native_raw(conn)[0] == expected_raw, 4, 'CONNECTION_CONTEXT_DRIFT')
            with _no_mux(conn):
                return original(*args, **kwargs)
        if end is not None:
            with _deadline(end - time.monotonic()):
                return consume()
        return consume()
    conn._build_command = build
    try:
        yield
    finally:
        conn._build_command = original


def _native_argv(conn):
    require(conn.get_option('host_key_checking') is True and conn.become is None,
            4, 'HOST_KEY_CHECKING_REQUIRED')
    require(not any(conn.get_option(k) for k in ('password', 'private_key', 'private_key_passphrase',
                                                 'pkcs11_provider', 'reconnection_retries')),
            4, 'CONNECTION_POLICY_DENIED')
    binary = conn.get_option('ssh_executable')
    require(binary in ('ssh', '/usr/bin/ssh'), 4, 'UNSUPPORTED_SSH_EXECUTABLE')
    _, _, path = _native_raw(conn)  # reject before builder side effects
    fingerprint = _config(path)
    host = _address(conn.get_option('host') or conn._play_context.remote_addr)
    conn.host = host
    with _no_mux(conn):
        argv = tuple(conn._build_command(binary, 'ssh', host, COMMAND))
    actual_path, _ = _args([x.decode('utf-8') for x in argv[1:-2]])
    require(actual_path == path and argv[-2:] == (host.encode(), COMMAND.encode()), 4, 'CONNECTION_POLICY_DENIED')
    return argv, fingerprint


def _fixed_ssh(argv):
    binary = Path('/usr/bin/ssh')
    selected = shutil.which(os.fsdecode(argv[0]))
    require(binary.is_file() and os.access(binary, os.X_OK) and selected is not None
            and Path(selected).resolve() == binary.resolve(), 3, 'OPENSSH_EFFECTIVE_CONFIG_UNAVAILABLE')
    return binary


def _effective_ssh(argv, fingerprint):
    """Verify actual native argv against the private validated closure."""
    token = _RPM_PROOF.set([])
    try:
        return _effective_ssh_proof(argv, fingerprint)
    finally:
        _RPM_PROOF.reset(token)


def _effective_ssh_proof(argv, fingerprint):
    path, _ = _args([x.decode('utf-8') for x in argv[1:-2]])
    require(_config(path) == fingerprint, 4, 'CONNECTION_CONTEXT_DRIFT')
    binary = _fixed_ssh(argv)
    # -G evaluates only the validated private closure, never a live transport.
    def dump(args):
        require(_config(path) == fingerprint, 4, 'CONNECTION_CONTEXT_DRIFT')
        left = signal.getitimer(signal.ITIMER_REAL)[0]
        budget = min(5, left) if left > 0 else 5
        rc, out, _ = _scope.bounded_command([str(binary), '-G', *args],
                                             {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'},
                                             timeout=budget, out_cap=65536, err_cap=65536)
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
        require(entries.get('controlpath', ['none']) == ['none'], 4, 'UNSUPPORTED_SSH_EFFECTIVE_CONFIG')
        one('canonicalizehostname', ('no', 'false'))
        one('batchmode', ('yes', 'true'))
        one('hashknownhosts', ('yes', 'no'))
        for pattern in entries.get('sendenv', []):
            require(pattern in _SENDENV_NAMES, 4, 'UNSUPPORTED_SSH_EFFECTIVE_CONFIG')
        for key in ('forwardagent', 'forwardx11', 'permitlocalcommand'):
            one(key, ('no', 'false'))
        for key in ('identityfile', 'userknownhostsfile', 'globalknownhostsfile'):
            require(entries.get(key), 4, 'UNSUPPORTED_SSH_EFFECTIVE_CONFIG')
            for record in entries[key]:
                for value in record.split():
                    p = (_passwd_ssh_dir().parent / value[2:] if value.startswith('~/') else Path(value))
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
        # Only the proof consumer uses the private closure. Native guarded
        # argv retains its source selection and fixed scan-only mux policy.
        if '-F' in args:
            args[args.index('-F') + 1] = snapshot
        else:
            args = ['-F', snapshot, *args]
        effective, digest = dump(args)
        jumps = effective.get('proxyjump', ['none'])
        require(len(jumps) == 1, 4, 'UNSUPPORTED_SSH_EFFECTIVE_CONFIG')
        _option('proxyjump', jumps[0])
        proofs = [digest]
        if jumps[0] != 'none':
            chain = jumps[0].split(',')
            for i in reversed(range(len(chain))):
                jump = chain[i]
                userhost, port = (jump.rsplit(':', 1) if ':' in jump else (jump, None))
                user, host = (userhost.split('@', 1) if '@' in userhost else (None, userhost))
                ja = ['-F', snapshot]
                if port:
                    ja += ['-o', 'Port=' + port]
                if user:
                    ja += ['-o', 'User=' + user]
                prefix = ','.join(chain[:i])
                if prefix:
                    ja += ['-o', 'ProxyJump=' + prefix]
                j, proof = dump(ja + [host])
                require(j.get('proxyjump', ['none']) == [prefix or 'none'], 4, 'UNSUPPORTED_SSH_EFFECTIVE_CONFIG')
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
                proofs[name] = (argv, fingerprint, _effective_ssh(argv, fingerprint), _native_raw(conn)[0])
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
                current = _native_binding(self, target)
                argv, fingerprint = _native_argv(current)
                expected = self._proofs[target]
                require((argv, fingerprint) == expected[:2] and _native_raw(current)[0] == expected[3],
                        4, 'CONNECTION_CONTEXT_DRIFT')
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
                require(_native_raw(conn)[0] == expected[3] and _native_argv(conn) == expected[:2],
                        4, 'CONNECTION_CONTEXT_DRIFT')
                conn._run = guarded
                with _consume_builder(conn, expected[3]):
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
_PLATFORM_WORKER = contextvars.ContextVar('_pqc_platform_worker', default=None)


def _platform_budget():
    return 3 * (_GUARD_SECONDS + _SSH_SECONDS + _COMMAND_SECONDS + 1) + _GUARD_SECONDS


def _openssl_budget():
    return 7 * (_GUARD_SECONDS + _SSH_SECONDS + _COMMAND_SECONDS + 1) + _GUARD_SECONDS


def _policy_budget():
    return 2 * (_GUARD_SECONDS + _SSH_SECONDS + _COMMAND_SECONDS + 1) + _GUARD_SECONDS


def _ssh_budget():
    return 2 * (_GUARD_SECONDS + _SSH_SECONDS + _COMMAND_SECONDS + 1) + _GUARD_SECONDS


def _cert_budget():
    return _GUARD_SECONDS + _SSH_SECONDS + _COMMAND_SECONDS + 1 + _GUARD_SECONDS


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


class _PlatformLease:
    """Bounded private shared memory, one per staged native worker wave.

    Each active worker's deadline only decreases. Removing a confirmed worker
    from the minimum cannot extend a phase already begun. An unavailable
    lock/lease fails closed, including a worker killed in its tiny critical
    section. No external service, serialized plan or filesystem grant.
    """
    def __init__(self, targets, deadline):
        from multiprocessing import get_context
        self.slots = {n: 2 + 2*i for i, n in enumerate(targets)}
        self.data = get_context('fork').Array('d', [0.0, deadline] + [0.0] * (2*len(targets)))

    @contextlib.contextmanager
    def locked(self):
        lock = self.data.get_lock()
        if not lock.acquire(timeout=.05):
            raise Denied(3, 'PLATFORM_LEASE_UNAVAILABLE')
        try:
            yield self.data.get_obj()
        finally:
            lock.release()

    def reserve(self, name, end):
        with self.locked() as data:
            require(not data[0] and data[self.slots[name]] == 0, 3, 'INVALID_NATIVE_RESULT')
            data[self.slots[name]] = min(end, data[1])

    def sync(self, wave):
        with self.locked() as data:
            if wave.ledger.stop is not None:
                data[0] = 1
            for name, end in wave.ends.items():
                slot = self.slots[name]
                if name in wave.confirmed:
                    data[slot] = 0
                else:
                    require(data[slot] > 0, 3, 'INVALID_NATIVE_RESULT')
                    data[slot] = min(data[slot], end, wave.grace.get(name, end))

    def stop(self):
        with self.locked() as data:
            data[0] = 1

    def _limit(self, data, name):
        if data[0]:
            raise _Cancelled()
        require(data[self.slots[name]] > 0, 3, 'PLATFORM_LEASE_UNAVAILABLE')
        return min([data[1]] + [data[i] for i in self.slots.values() if data[i] > 0])

    def limit(self, name):
        with self.locked() as data:
            return self._limit(data, name)

    def begin(self, name, horizon):
        with self.locked() as data:
            now = time.monotonic()
            end = min(horizon, self._limit(data, name))
            if end - now < _COMMAND_SECONDS + 1:
                raise _Deadline()
            slot = self.slots[name] + 1
            require(data[slot] == 0, 3, 'INVALID_NATIVE_RESULT')
            data[slot] = 1
            return now + _COMMAND_SECONDS + 1

    def clean(self, name):
        with self.locked() as data:
            data[self.slots[name] + 1] = 0

    def pending(self, name):
        try:
            with self.locked() as data:
                return data[self.slots[name] + 1] != 0
        except Denied:
            return True


class _PlatformWorker:
    """Only constructed inside the actual native fixed raw witness."""
    def __init__(self, name, task_uuid, host_end, lease, verify, flags):
        self.name, self.task_uuid = name, task_uuid
        self.host_end, self.lease, self.verify = host_end, lease, verify
        self.producer_end = None
        self.validation_left = _GUARD_SECONDS
        self.ordinal = 0
        self.run_id = None
        from tools import scan_collectors as b
        self.producer = None
        self.plan = ()
        self.platform_proof = None
        self.openssl_plan = b._openssl_plan(flags)
        self.policy_requested = flags[b.POLICY_FLAG]
        self.ssh_flags = {f: flags[f] for f in (b.SSHD, b.KEYS)}
        self.openssl_completed = False
        self.openssl_gap_completed = False
        self.policy_completed = False
        self.ssh_completed = False
        self.ssh_halted = False
        self.cert_requested = flags[b.CERT_FLAG]
        self.cert_completed = False

    def limit(self, end):
        end = min(end, self.host_end, self.lease.limit(self.name))
        if end <= time.monotonic():
            raise _Deadline()
        return end

    def start(self, run_id):
        from tools import scan_collectors as b
        require(self.producer_end is None and self.producer is None, 3, 'INVALID_NATIVE_RESULT')
        self.run_id = run_id
        self.producer = b.PLATFORM
        self.plan = tuple(enumerate(b._PLATFORM_STAGES))
        self.producer_end = min(self.host_end, time.monotonic() + _platform_budget())

    def note_platform(self, row):
        from tools import scan_collectors as b
        require(self.producer == b.PLATFORM and self.platform_proof is None
                and row['producer_id'] == b.PLATFORM and row['reason_code'] == 'COMMAND_OK'
                and row['cleanup_confirmed'] is True and row['snapshot'] is not None
                and not b.record_stop(row) and not self.lease.pending(self.name),
                3, 'INVALID_NATIVE_RESULT')
        expected = len(self.plan) if self.validate(b._rpm_eligible, row['snapshot']) else 1
        require(self.ordinal == expected, 3, 'INVALID_NATIVE_RESULT')
        self.limit(self.producer_end)
        self.platform_proof = row['snapshot']

    def start_openssl(self, run_id, flags, platform_snapshot):
        from tools import scan_collectors as b
        require(self.producer == b.PLATFORM and self.run_id == run_id
                and self.platform_proof is not None and self.platform_proof is platform_snapshot
                and self.openssl_plan and b._openssl_plan(flags) == self.openssl_plan
                and not self.lease.pending(self.name), 3, 'INVALID_NATIVE_RESULT')
        require(self.validate(b._platform_status, platform_snapshot) == 'UNVERIFIED',
                3, 'INVALID_NATIVE_RESULT')
        # Only the next fixed producer gets a new local budget. The same host,
        # task UUID and shared earliest lease still cap every operation.
        self.producer_end = min(self.limit(self.host_end), time.monotonic() + _openssl_budget())
        self.producer = b.OPENSSL
        self.plan = self.openssl_plan
        self.ordinal = 0
        self.validation_left = _GUARD_SECONDS

    def note_openssl(self, row):
        from tools import scan_collectors as b
        require(self.producer == b.OPENSSL and not self.openssl_completed
                and row['producer_id'] == b.OPENSSL and row['cleanup_confirmed'] is True
                and not b.record_stop(row) and not self.lease.pending(self.name)
                and ((row['reason_code'] == 'COMMAND_OK' and row['snapshot'] is not None
                      and self.ordinal == len(self.plan))
                     or (row['reason_code'] in b._STAGE_RPM_FAILURES
                         and row['snapshot'] is None and 0 < self.ordinal <= len(self.plan))),
                3, 'INVALID_NATIVE_RESULT')
        self.limit(self.producer_end)
        self.openssl_completed = True

    def note_openssl_gap(self, row, flags, platform_snapshot):
        from tools import scan_collectors as b
        require(self.producer == b.PLATFORM and self.platform_proof is platform_snapshot
                and self.platform_proof is not None and self.openssl_plan
                and b._openssl_plan(flags) == self.openssl_plan
                and not self.openssl_completed and not self.openssl_gap_completed
                and row['producer_id'] == b.OPENSSL and row['reason_code'] == 'PLATFORM_GAP'
                and row['cleanup_confirmed'] is True and not self.lease.pending(self.name),
                3, 'INVALID_NATIVE_RESULT')
        status = self.validate(b._platform_status, platform_snapshot)
        require(status != 'UNVERIFIED' and row['snapshot'] == b._gap_snapshot(b.OPENSSL, flags, status),
                3, 'INVALID_NATIVE_RESULT')
        self.limit(self.producer_end)
        self.openssl_gap_completed = True

    def start_policy(self, run_id, flags, platform_snapshot):
        from tools import scan_collectors as b
        require(self.producer in (b.PLATFORM, b.OPENSSL) and self.run_id == run_id
                and self.platform_proof is not None and self.platform_proof is platform_snapshot
                and self.policy_requested is True and flags[b.POLICY_FLAG] is True
                and b._openssl_plan(flags) == self.openssl_plan
                and not self.lease.pending(self.name), 3, 'INVALID_NATIVE_RESULT')
        previous = self.producer
        # One bounded producer interval, capped by the original host and
        # shared wave lease. Empty plans have the same proof requirements.
        self.producer_end = min(self.limit(self.host_end), time.monotonic() + _policy_budget())
        self.producer = b.POLICY
        self.ordinal = 0
        self.validation_left = _GUARD_SECONDS
        status = self.validate(b._platform_status, platform_snapshot)
        if status == 'UNVERIFIED' and self.openssl_plan:
            require(previous == b.OPENSSL and self.openssl_completed, 3, 'INVALID_NATIVE_RESULT')
        else:
            require(previous == b.PLATFORM and not self.openssl_completed, 3, 'INVALID_NATIVE_RESULT')
        self.plan = self.validate(b._policy_plan, flags, platform_snapshot)

    def note_policy(self, row):
        from tools import scan_collectors as b
        require(self.producer == b.POLICY and not self.policy_completed
                and row['producer_id'] == b.POLICY and row['reason_code'] in ('COMMAND_OK', 'PLATFORM_GAP')
                and row['cleanup_confirmed'] is True and row['snapshot'] is not None
                and not b.record_stop(row) and self.ordinal == len(self.plan)
                and not self.lease.pending(self.name), 3, 'INVALID_NATIVE_RESULT')
        self.limit(self.producer_end)
        self.policy_completed = True

    def start_ssh(self, run_id, flags, platform_snapshot):
        from tools import scan_collectors as b
        require(self.run_id == run_id and self.platform_proof is not None
                and self.platform_proof is platform_snapshot and any(self.ssh_flags.values())
                and {f: flags[f] for f in self.ssh_flags} == self.ssh_flags
                and b._openssl_plan(flags) == self.openssl_plan
                and flags[b.POLICY_FLAG] is self.policy_requested
                and not self.lease.pending(self.name), 3, 'INVALID_NATIVE_RESULT')
        previous = self.producer
        self.producer_end = min(self.limit(self.host_end), time.monotonic() + _ssh_budget())
        self.validation_left = _GUARD_SECONDS
        status = self.validate(b._platform_status, platform_snapshot)
        require((not self.openssl_plan or (self.openssl_completed if status == 'UNVERIFIED'
                                         else self.openssl_gap_completed))
                and (previous == b.POLICY and self.policy_completed if self.policy_requested else
                     previous == (b.OPENSSL if self.openssl_plan and status == 'UNVERIFIED' else b.PLATFORM)),
                3, 'INVALID_NATIVE_RESULT')
        self.producer = b.SSH
        self.ordinal = 0
        self.plan = self.validate(b._ssh_plan, flags, platform_snapshot)

    def note_ssh(self, row):
        from tools import scan_collectors as b
        require(self.producer == b.SSH and not self.ssh_completed and row['producer_id'] == b.SSH
                and row['cleanup_confirmed'] is True and row['snapshot'] is not None
                and not b.record_stop(row, staged_ssh=True) and not self.lease.pending(self.name),
                3, 'INVALID_NATIVE_RESULT')
        expected = sum(row['snapshot']['slots'][stage]['reason'] != 'ACQUISITION_STOPPED'
                       for _, stage in self.plan)
        require(self.ordinal == expected, 3, 'INVALID_NATIVE_RESULT')
        self.limit(self.producer_end)
        self.ssh_completed = True
        self.ssh_halted = b._host_local_stop(row, staged_ssh=True)

    def start_cert(self, run_id, flags, platform_snapshot):
        from tools import scan_collectors as b
        require(self.run_id == run_id and self.platform_proof is platform_snapshot
                and platform_snapshot is not None and self.cert_requested is True
                and flags[b.CERT_FLAG] is True and not self.cert_completed
                and b._openssl_plan(flags) == self.openssl_plan
                and flags[b.POLICY_FLAG] is self.policy_requested
                and {f: flags[f] for f in self.ssh_flags} == self.ssh_flags
                and not self.ssh_halted and not self.lease.pending(self.name),
                3, 'INVALID_NATIVE_RESULT')
        previous = self.producer
        self.producer_end = min(self.limit(self.host_end), time.monotonic() + _cert_budget())
        self.validation_left = _GUARD_SECONDS
        status = self.validate(b._platform_status, platform_snapshot)
        openssl_done = self.openssl_completed if status == 'UNVERIFIED' else self.openssl_gap_completed
        require((openssl_done if self.openssl_plan else not (self.openssl_completed or self.openssl_gap_completed))
                and self.policy_completed is self.policy_requested
                and self.ssh_completed == any(self.ssh_flags.values())
                and previous == (b.SSH if any(self.ssh_flags.values()) else
                                 b.POLICY if self.policy_requested else
                                 b.OPENSSL if self.openssl_plan and status == 'UNVERIFIED' else b.PLATFORM),
                3, 'INVALID_NATIVE_RESULT')
        self.producer = b.CERT
        self.ordinal = 0
        self.plan = self.validate(b._cert_plan, flags, platform_snapshot)

    def note_cert(self, row):
        from tools import scan_collectors as b
        require(self.producer == b.CERT and not self.cert_completed
                and row['producer_id'] == b.CERT and row['cleanup_confirmed'] is True
                and not b.record_stop(row) and self.ordinal == len(self.plan)
                and not self.lease.pending(self.name), 3, 'INVALID_NATIVE_RESULT')
        self.limit(self.producer_end)
        self.cert_completed = True

    def validate(self, fn, *args, **kwargs):
        # Cumulative per-producer 30s validation, not 30s for each stage.
        start = time.monotonic()
        end = self.limit(min(self.producer_end, start + self.validation_left))
        try:
            with _deadline(end - time.monotonic()):
                result = fn(*args, **kwargs)
            self.limit(end)
            return result
        finally:
            self.validation_left -= time.monotonic() - start

    def invoke(self, prepare, binding):
        from tools import scan_collectors as b
        require(((self.producer == b.PLATFORM and type(binding) is b._StageBinding)
                 or (self.producer == b.OPENSSL and type(binding) is b._OpenSSLStageBinding
                     and binding.producer_id == b.OPENSSL)
                 or (self.producer == b.POLICY and type(binding) is b._PolicyStageBinding
                     and binding.producer_id == b.POLICY)
                 or (self.producer == b.SSH and type(binding) is b._SSHStageBinding
                     and binding.producer_id == b.SSH)
                 or (self.producer == b.CERT and type(binding) is b._CertStageBinding
                     and binding.producer_id == b.CERT))
                and binding.run_id == self.run_id and binding.target_id == self.name
                and binding.task_uuid == self.task_uuid and type(binding.ordinal) is int
                and self.ordinal < len(self.plan)
                and (binding.ordinal, binding.stage) == self.plan[self.ordinal],
                3, 'INVALID_NATIVE_RESULT')
        self.ordinal += 1
        used = False
        trusted_clean = False
        receipt_failure = None
        command_end = None
        try:
            start = time.monotonic()
            stage_end = self.limit(min(self.producer_end,
                                      start + _GUARD_SECONDS + _SSH_SECONDS + _COMMAND_SECONDS + 1))
            if self.producer in (b.POLICY, b.SSH, b.CERT) and stage_end - start < _COMMAND_SECONDS + 1:
                raise _Deadline()
            # Packaging and both guard checks share one G budget. No launch
            # inside prepare. Recheck the actual consumed binding immediately
            # after the separate synthetic connection witness.
            with _deadline(self.limit(min(stage_end, start + _GUARD_SECONDS)) - time.monotonic()):
                self.verify()
                launch = prepare(binding)
                require(callable(launch), 3, 'INVALID_NATIVE_RESULT')
            guard_left = _GUARD_SECONDS - (time.monotonic() - start)
            with _deadline(self.limit(min(stage_end, time.monotonic() + _SSH_SECONDS)) - time.monotonic()):
                if _restricted_connection(self.name) != 'CONNECTED':
                    raise b._StageFailure('REMOTE_CLEANUP_UNCONFIRMED')
            with _deadline(self.limit(min(stage_end, time.monotonic() + guard_left)) - time.monotonic()):
                self.verify()
            end = self.limit(stage_end)
            if end - time.monotonic() < _COMMAND_SECONDS + 1:
                raise _Deadline()

            def begin():
                # Called exactly once by the trusted launcher immediately
                # before P1 dispatch. No path/argv or deadline input.
                nonlocal used, command_end
                require(not used, 3, 'INVALID_NATIVE_RESULT')
                command_end = self.lease.begin(self.name, end)
                used = True
                timer = signal.getitimer(signal.ITIMER_REAL)[0]
                left = command_end - time.monotonic()
                if timer <= 0 or left <= 0:
                    raise _Deadline()
                if left < timer:
                    signal.setitimer(signal.ITIMER_REAL, left)
                return command_end

            with _deadline(end - time.monotonic()):
                completion = launch(begin)
                # No arbitrary launch path and no second consumption. A
                # missing or replayed completion cannot clear the active slot.
                if not used:
                    raise b._StageFailure('REMOTE_CLEANUP_UNCONFIRMED')
                try:
                    receipt = b._stage_receipt(completion, binding)
                    trusted_clean = True
                except b._StageFailure as exc:
                    receipt_failure = exc
                    trusted_clean = exc.clean
                    raise
                finally:
                    if trusted_clean:
                        self.lease.clean(self.name)
                self.limit(command_end)
            self.limit(command_end)
            return receipt
        except b._StageFailure as exc:
            if self.producer in (b.POLICY, b.SSH, b.CERT):
                # Only a matching completion, not a launcher exception,
                # can prove clean termination of an active native stage.
                if used and not trusted_clean:
                    # Only a matching, validated Cert receipt can carry its
                    # actual fatal rc; a launch exception cannot supply it.
                    if (self.producer == b.CERT and exc is receipt_failure
                            and exc.reason == 'REMOTE_CLEANUP_UNCONFIRMED'):
                        raise
                    raise b._StageFailure('REMOTE_CLEANUP_UNCONFIRMED') from None
                if not used and exc.clean:
                    raise b._StageFailure('INVALID_ADAPTER_RESULT', clean=True) from None
            if self.producer in (b.OPENSSL, b.POLICY, b.SSH, b.CERT) and used and trusted_clean:
                try:
                    self.limit(command_end)
                except _Deadline:
                    raise b._StageFailure('CONTROLLER_TIMEOUT', clean=True) from None
            raise
        except _Cancelled:
            # The controller has already observed a stop; do not produce a
            # later successful envelope or dispatch another stage.
            raise
        except _Deadline:
            clean = not used or trusted_clean
            raise b._StageFailure('CONTROLLER_TIMEOUT' if clean else 'REMOTE_CLEANUP_UNCONFIRMED',
                                  clean=clean) from None
        except Denied as exc:
            clean = not used or trusted_clean
            reason = 'GUARD_REJECTED' if exc.code == 4 else 'INVALID_ADAPTER_RESULT'
            raise b._StageFailure(reason if clean else 'REMOTE_CLEANUP_UNCONFIRMED', clean=clean) from None
        except Exception:
            clean = not used or trusted_clean
            raise b._StageFailure('INVALID_ADAPTER_RESULT' if clean else 'REMOTE_CLEANUP_UNCONFIRMED',
                                  clean=clean) from None


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
def _worker_boundary(ctx, name, registry, collect=None, staged=None):
    """Inherited only by the next native fork; never invoke original SSH _run."""
    from ansible.executor.task_executor import TaskExecutor
    from ansible.plugins.connection import ssh
    from ansible.plugins.loader import connection_loader
    expected = ctx._proofs[name]
    flags = ctx._decisions[name]['requested_flags']
    original_run = ssh.Connection._run
    original_get = TaskExecutor._get_connection
    used = False
    guard_end = None
    raw_proof = None
    native_builder = None
    actual_executor = None

    def get_connection(executor, cvars, templar, current_connection):
        nonlocal native_builder, actual_executor
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
        if staged is not None:
            require(executor._task._uuid == staged[0] and executor._task.no_log is True,
                    4, 'BATCH_GUARD_DENIED')
        actual_executor, native_builder = executor, connection._build_command
        native_exec = connection.exec_command
        def exec_witness(cmd, in_data=None, sudoable=True):
            nonlocal guard_end, raw_proof
            require(cmd == COMMAND and in_data is None and connection.become is None,
                    4, 'BATCH_GUARD_DENIED')
            guard_end = time.monotonic() + _GUARD_SECONDS
            with _deadline(_GUARD_SECONDS):
                raw_proof = _native_raw(connection)[0]
                require(raw_proof == expected[3] and _native_argv(connection) == expected[:2],
                        4, 'BATCH_GUARD_DENIED')
            with _consume_builder(connection, expected[3], guard_end):
                return native_exec(cmd, in_data=None, sudoable=False)
        connection.exec_command = exec_witness
        connection.reset = lambda *a, **k: deny(*a, **k)
        connection._run = lambda argv, in_data, sudoable=True, checkrc=True: guarded(
            connection, argv, in_data, sudoable, checkrc)
        return connection

    def guarded(conn, argv, in_data, sudoable=True, checkrc=True):
        nonlocal used
        require(not used and in_data is None and sudoable is False and conn.become is None
                and tuple(argv) == expected[0], 4, 'BATCH_GUARD_DENIED')
        used = True
        require(guard_end is not None and raw_proof == expected[3], 4, 'BATCH_GUARD_DENIED')
        with _deadline(guard_end - time.monotonic()):
            require(_source_identity(ctx._source) == ctx._source_id
                    and _project(ctx._inventory, ctx._variables, ctx._request)
                    == (ctx._targets, ctx._flags, ctx._decisions), 4, 'CONNECTION_CONTEXT_DRIFT')
            # Verify the actual native option consumer and exact argv again,
            # including the existing validated -F snapshot proof.
            require(_native_raw(conn)[0] == expected[3]
                    and _effective_ssh(tuple(argv), expected[1]) == expected[2],
                    4, 'BATCH_GUARD_DENIED')
        if staged is None:
            result = _collect(name, flags, registry) if collect is None else collect(name, flags, registry)
        else:
            task_uuid, host_end, lease = staged

            def verify():
                require(actual_executor._host.name == name and actual_executor._task._uuid == task_uuid
                        and actual_executor._task.no_log is True and conn.become is None
                        and _source_identity(ctx._source) == ctx._source_id
                        and _project(ctx._inventory, ctx._variables, ctx._request)
                        == (ctx._targets, ctx._flags, ctx._decisions), 4, 'CONNECTION_CONTEXT_DRIFT')
                # Recheck the whole existing preflight closure, including
                # effective proof and the actual native connection consumer.
                # Do not execute a second raw witness or original SSH _run.
                for target in ctx._targets:
                    current = _native_binding(ctx, target)
                    proof = ctx._proofs[target]
                    av, fingerprint = _native_argv(current)
                    require((av, fingerprint) == proof[:2] and _native_raw(current)[0] == proof[3]
                            and _effective_ssh(av, fingerprint) == proof[2], 4, 'CONNECTION_CONTEXT_DRIFT')
                # _consume_builder is still on the original witness stack;
                # use its original native builder for this guarded rebuild,
                # not the expired initial guard timer. Never call _run.
                builder = conn._build_command
                try:
                    conn._build_command = native_builder
                    require(_native_raw(conn)[0] == expected[3] and _native_argv(conn) == expected[:2]
                            and _effective_ssh(tuple(argv), expected[1]) == expected[2],
                            4, 'CONNECTION_CONTEXT_DRIFT')
                finally:
                    conn._build_command = builder

            token = _PLATFORM_WORKER.set(_PlatformWorker(name, task_uuid, host_end, lease, verify, flags))
            try:
                result = collect(name, flags, registry)
            finally:
                _PLATFORM_WORKER.reset(token)
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
        if after_accept is not None and after_accept() is False:
            break


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
    def __init__(self, ledger, queue, phase, lease=None):
        super().__init__(ledger, queue)
        self.phase = phase
        self.lease = lease

    def track(self, name, worker, task_uuid, end):
        super().track(name, worker, task_uuid, end)
        if self.lease is not None:
            self.lease.sync(self)

    def _drain_receipts(self):
        # Includes queue read, receipt validation and actual normalization.
        # An exit drain may follow a newly established shorter grace.
        if self.lease is not None and self.ledger.stop is not None:
            return
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
        return None if self.lease is None else self.ledger.stop is None

    def _grace_changed(self):
        if self.lease is not None:
            self.lease.sync(self)
        with self.phase():
            pass

    def poll(self):
        with self.phase():
            super().poll()
            if self.lease is not None:
                self.lease.sync(self)

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
            if self.lease is not None:
                try:
                    self.lease.stop()
                except Denied:
                    self.ledger.fail('REMOTE_CLEANUP_UNCONFIRMED')
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
                if self.lease is not None and self.lease.pending(n):
                    # Controller-group exit is not independent P1 target
                    # cleanup. A missing trusted completion remains fatal.
                    reason = 'REMOTE_CLEANUP_UNCONFIRMED'
                self.ledger.worker_failed(n, reason)
        return quiet


def execute_batch(ctx):
    """One private native batch invocation -> (rc, closed terminal manifest).

    Denied(2/3/4) before dispatch is a preflight rejection, not a run.
    There is no public adapter/transport parameter or live execution grant.
    """
    return _execute_batch(ctx)


def _execute_batch(ctx, producer_session=None, *, workflow=None):
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
    if workflow is not None:
        from tools.scan_workflow import _Control
        require(type(workflow) is _Control and workflow.ctx is ctx
                and type(producer_session) is _ProducerSession
                and workflow.session is producer_session, 3, 'NATIVE_CONTEXT_UNVERIFIED')
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
        if os.getpid() != controller_pid:
            return
        if workflow is not None and workflow.frozen:
            workflow.late_interrupted = True
            return
        if interrupted:
            return
        interrupted = True
        # Complete the bounded Store call's ownership/durability handoff
        # before observing cancellation. The original alarm is not renewed.
        if workflow is not None and workflow.storage_active:
            return
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
        with _deadline(remaining, lambda: fork_critical or
                       (workflow is not None and workflow.reserving)):
            # Reservation has its own ownership-transfer window. A latched
            # expiration still rejects the reservation, never grants dispatch.
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
                    if workflow is not None:
                        workflow.check_worker(worker, host, task)
                        workflow.intent(name, min(end, launch_end))
                        # The durable intent is not a start receipt. Recheck
                        # the original proof and every live horizon after I/O.
                        if not poll():
                            raise _Cancelled() if interrupted else Denied(3, 'INVALID_NATIVE_RESULT')
                        try:
                            _guard(ctx, name)
                        except Denied:
                            ledger.fail('GUARD_REJECTED')
                            raise
                        workflow.check_worker(worker, host, task)
                        require(worker is tqm._workers[slot], 3, 'INVALID_NATIVE_RESULT')
                        if not poll():
                            raise _Cancelled() if interrupted else Denied(3, 'INVALID_NATIVE_RESULT')
                    if producer_session is not None and producer_session.staged:
                        wave.lease.reserve(name, end)
                    isolation = (contextlib.nullcontext() if workflow is None else
                                 workflow.isolate_child(worker))
                    with isolation:
                        if workflow is not None:
                            launch_end = min(launch_end, end, active_phase_end, wave.limit(),
                                             wave.lease.limit(name))
                            remaining = launch_end - time.monotonic()
                            timer = signal.getitimer(signal.ITIMER_REAL)[0]
                            if interrupted:
                                raise _Cancelled()
                            if remaining <= 0 or timer <= 0:
                                raise _Deadline()
                            if remaining < timer:
                                signal.setitimer(signal.ITIMER_REAL, remaining)
                        fork_critical = True
                        try:
                            original_start(worker)
                        except BaseException:
                            if workflow is not None and worker.pid is None:
                                workflow.mark_failure('DISPATCH', 'START_UNCONFIRMED')
                            raise
                        finally:
                            fork_critical = False
                    if interrupted:
                        raise _Cancelled()
                    if time.monotonic() >= launch_end:
                        raise _Deadline()
                BaseProcess.start = start_worker
                boundary = (_worker_boundary(ctx, name, registry) if producer_session is None else
                            _worker_boundary(ctx, name, registry, producer_session.collect,
                                             (task._uuid, end, wave.lease) if producer_session.staged else None))
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
                    if workflow is not None:
                        workflow.check_registry(registry, ledger)
        except _Deadline:
            if not interrupted:
                raise Denied(3, 'BATCH_GUARD_TIMEOUT') from None
            raise _Cancelled()
        names = [n for n in ledger.targets if ledger.eligible[n]]
        if names:
            width = min(ctx._request['forks'], 2)
            budgets = {n: _GUARD_SECONDS + _SSH_SECONDS + (
                producer_session.budget(ledger.eligible[n]) if producer_session is not None else
                (_COMMAND_SECONDS + 1) * len(ledger.eligible[n]))
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
            if workflow is not None:
                try:
                    with phase():
                        workflow.reserve(ledger)
                except _Deadline:
                    workflow.reject('RESERVATION', 'STORAGE_DEADLINE')
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
                            _ProducerWorkerWave(ledger, queue, phase,
                                _PlatformLease(selected, deadline) if producer_session.staged else None))
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
        elif workflow is not None:
            try:
                with phase():
                    workflow.reserve(ledger)
            except _Deadline:
                workflow.reject('RESERVATION', 'STORAGE_DEADLINE')
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
        if workflow is not None:
            return producer_session.finish(ctx, ledger, lambda: interrupted, workflow=workflow)
        return producer_session.finish(ctx, ledger, lambda: interrupted)
    return _manifest(ctx, ledger.finish(), ledger.stop)


# I1a: the same guarded queue, worker deadlines and lifecycle, with a distinct
# private receipt path. V1 never consumes a V2 result or its reference limits.
def _v2_base_row(row):
    result = {k: v for k, v in row.items() if k != 'platform'}
    result['collectors'] = [{**c, 'collection_ids': [],
        'reason_code': ('COMMAND_IO_FAILED' if c['reason_code'] == 'COLLECTION_ERROR' else
                        'INVALID_ADAPTER_RESULT' if c['state'] == 'ERROR'
                        and c['collector_id'] in ('pqc_collect_packages', 'pqc_collect_openssl', 'pqc_collect_crypto_policy',
                                                  'pqc_collect_sshd', 'pqc_collect_ssh_host_keys', 'pqc_collect_system_certs')
                        and c['reason_code'] in ('GUARD_REJECTED', 'CONTROLLER_TIMEOUT')
                        else c['reason_code'])}
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
    if (reduced.get('state') == 'ERROR'
            and reduced.get('reason_code') in ('GUARD_REJECTED', 'CONTROLLER_TIMEOUT')):
        if (flag not in ('pqc-platform', 'pqc_collect_packages', 'pqc_collect_openssl', 'pqc_collect_crypto_policy',
                         'pqc_collect_sshd', 'pqc_collect_ssh_host_keys', 'pqc_collect_system_certs')
                or reduced.get('rc') is not None or ids):
            return False
        reduced['reason_code'] = 'INVALID_ADAPTER_RESULT'
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
        # V2 shape only: O2 fatal outcomes must follow retained Platform
        # evidence, not fabricate a standalone fatal SSL projection.
        ssl_rows = [c for c in row['collectors'] if c['collector_id'] in (bridge.PACKAGES, bridge.SSL)
                    and c['requested']]
        ssl_fatal = [c for c in ssl_rows if c['state'] == 'ERROR'
                     and c['reason_code'] in ('GUARD_REJECTED', 'CONTROLLER_TIMEOUT')]
        if ssl_fatal:
            require(row['attempted'] and row['reason_code'] in _FATAL
                    and row['platform']['collection_ids']
                    and len(ssl_fatal) == len(ssl_rows)
                    and len({c['reason_code'] for c in ssl_fatal}) == 1,
                    3, 'INVALID_TERMINAL_MANIFEST')
        # CP2-only fatal extension: no Policy references, with prior Platform
        # evidence and no later producer dispatch. V1's outcome grammar stays closed.
        policy_row = next(c for c in row['collectors'] if c['collector_id'] == bridge.POLICY_FLAG)
        if policy_row['state'] == 'ERROR' and policy_row['reason_code'] in ('GUARD_REJECTED', 'CONTROLLER_TIMEOUT'):
            # A selected O2 producer must have completed before Policy. Its
            # snapshot projects every requested flag with references; a clean
            # ordinary whole-producer failure instead projects the same error
            # and rc without references. Neither shape proves cleanup itself.
            ssl_complete = not ssl_rows or all(
                c['collection_ids'] and (c['state'] in ('COLLECTED', 'NOT_APPLICABLE', 'PARTIAL',
                                                        'UNKNOWN', 'PERMISSION_DENIED')
                    or (c['state'], c['reason_code']) in (('ERROR', 'COLLECTION_ERROR'),
                                                          ('NOT_SCANNED', 'ADAPTER_NOT_AVAILABLE')))
                for c in ssl_rows)
            ssl_ordinary_failure = bool(ssl_rows) and all(
                c['state'] == 'ERROR' and c['reason_code'] in bridge._STAGE_RPM_FAILURES
                and not c['collection_ids']
                and (c['reason_code'], c['rc']) == (ssl_rows[0]['reason_code'], ssl_rows[0]['rc'])
                for c in ssl_rows)
            require(row['attempted'] and row['reason_code'] in _FATAL
                    and row['platform']['collection_ids'] and (ssl_complete or ssl_ordinary_failure)
                    and all(c['state'] == 'NOT_SCANNED' and not c['collection_ids']
                            for c in row['collectors'] if c['collector_id'] in (bridge.SSHD, bridge.KEYS, bridge.CERT_FLAG)),
                    3, 'INVALID_TERMINAL_MANIFEST')
        # Only the new SSH guard/deadline terminal extension: prior selected
        # producers must have completed, not merely have a plausible state.
        # Existing generic V2 fatal outcomes and V1 retain their grammar.
        ssh_rows = [c for c in row['collectors'] if c['requested']
                    and c['collector_id'] in (bridge.SSHD, bridge.KEYS)]
        ssh_fatal = [c for c in ssh_rows if c['state'] == 'ERROR'
                     and c['reason_code'] in ('GUARD_REJECTED', 'CONTROLLER_TIMEOUT')]
        if ssh_fatal:
            def projected(c):
                return bool(c['collection_ids']) and (c['state'] in (
                    'COLLECTED', 'NOT_APPLICABLE', 'PARTIAL', 'UNKNOWN', 'PERMISSION_DENIED')
                    or (c['state'], c['reason_code']) in (('ERROR', 'COLLECTION_ERROR'),
                                                          ('NOT_SCANNED', 'ADAPTER_NOT_AVAILABLE')))
            ssl_complete = all(projected(c) and (len(c['collection_ids']) == 2 if c['collector_id'] == bridge.PACKAGES
                                                else len(c['collection_ids']) >= 5) for c in ssl_rows)
            ssl_ordinary = bool(ssl_rows) and all(
                c['state'] == 'ERROR' and c['reason_code'] in bridge._STAGE_RPM_FAILURES
                and not c['collection_ids'] and (c['reason_code'], c['rc']) ==
                (ssl_rows[0]['reason_code'], ssl_rows[0]['rc']) for c in ssl_rows)
            require(row['attempted'] and row['reason_code'] in _FATAL
                    and projected(row['platform']) and len(row['platform']['collection_ids']) == 10
                    and (ssl_complete or ssl_ordinary)
                    and (not policy_row['requested'] or (projected(policy_row) and len(policy_row['collection_ids']) == 9))
                    and len(ssh_fatal) == len(ssh_rows) and len({c['reason_code'] for c in ssh_fatal}) == 1
                    and all(c['state'] == 'NOT_SCANNED' and not c['collection_ids']
                            for c in row['collectors'] if c['collector_id'] in (bridge.SSHD, bridge.KEYS, bridge.CERT_FLAG)
                            and c not in ssh_fatal), 3, 'INVALID_TERMINAL_MANIFEST')
        cert_row = next(c for c in row['collectors'] if c['collector_id'] == bridge.CERT_FLAG)
        if cert_row['state'] == 'ERROR' and cert_row['reason_code'] in ('GUARD_REJECTED', 'CONTROLLER_TIMEOUT'):
            def projected(c):
                return bool(c['collection_ids']) and (c['state'] in (
                    'COLLECTED', 'NOT_APPLICABLE', 'PARTIAL', 'UNKNOWN', 'PERMISSION_DENIED')
                    or (c['state'], c['reason_code']) in (('ERROR', 'COLLECTION_ERROR'),
                                                          ('NOT_SCANNED', 'ADAPTER_NOT_AVAILABLE')))
            ssl_complete = all(projected(c) and (len(c['collection_ids']) == 2 if c['collector_id'] == bridge.PACKAGES
                                                else len(c['collection_ids']) >= 5) for c in ssl_rows)
            ssl_ordinary = bool(ssl_rows) and all(
                c['state'] == 'ERROR' and c['reason_code'] in bridge._STAGE_RPM_FAILURES
                and not c['collection_ids'] and (c['reason_code'], c['rc']) ==
                (ssl_rows[0]['reason_code'], ssl_rows[0]['rc']) for c in ssl_rows)
            require(row['attempted'] and row['reason_code'] in _FATAL
                    and projected(row['platform']) and len(row['platform']['collection_ids']) == 10
                    and (ssl_complete or ssl_ordinary)
                    and (not policy_row['requested'] or (projected(policy_row) and len(policy_row['collection_ids']) == 9))
                    and all(projected(c) and len(c['collection_ids']) ==
                            (1 if c['collector_id'] == bridge.KEYS else 7) for c in ssh_rows)
                    and not cert_row['collection_ids'], 3, 'INVALID_TERMINAL_MANIFEST')
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
        self.wires = {}
        self.wire_total = 0

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
            context = {'staged_openssl': True} if self.session.openssl_staged else {}
            if self.session.policy_staged and self.flags[n][self.session.bridge.POLICY_FLAG]:
                context['staged_policy'] = True
            if self.session.ssh_staged and any(self.flags[n][f] for f in (self.session.bridge.SSHD, self.session.bridge.KEYS)):
                context['staged_ssh'] = True
            if self.session.cert_staged and self.flags[n][self.session.bridge.CERT_FLAG]:
                context['staged_cert'] = True
            projection = self.session.bridge.normalize_handoff(envelope, self.session.run_id, n, self.flags[n],
                                                                self.session.started_at, self.session.rules, **context)
        except Exception:
            # Never send a raw parsing/normalizer exception or retained snapshot
            # through the queue. Known earlier valid hosts remain available.
            self.fail('INVALID_NATIVE_RESULT')
            raise Denied(3, 'INVALID_NATIVE_RESULT') from None
        wire = None
        if self.session.retain_wire:
            wire = self.session.bridge.wire_bytes(envelope)
            require(len(wire) == receipt['byte_count'] <= self.session.bridge.MAX_WIRE
                    and hashlib.sha256(wire).hexdigest() == receipt['sha256']
                    and n not in self.wires
                    and self.wire_total + len(wire) <= self.session.bridge.MAX_WIRE * self.session.bridge.MAX_HOSTS,
                    3, 'INVALID_NATIVE_RESULT')
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
            if wire is not None:
                self.wires[n] = wire
                self.wire_total += len(wire)
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
        self.staged = False
        self.openssl_staged = False
        self.policy_staged = False
        self.ssh_staged = False
        self.cert_staged = False
        self.retain_wire = False

    def _identity(self, ctx):
        import uuid
        self.run_id = ctx._request['run_id'] or 'i1a-' + uuid.uuid4().hex
        self.started_at = self.bridge.stamp()

    def prepare(self, ctx):
        self._identity(ctx)
        registry = self.bridge._producer_adapters()
        require(type(registry) is dict and registry.keys() <= set(self.bridge.PRODUCERS)
                and all((k == self.bridge.PLATFORM and callable(v.prepare))
                        if type(v) is self.bridge._PlatformStageAdapter else
                        (k == self.bridge.OPENSSL and callable(v.prepare))
                        if type(v) is self.bridge._OpenSSLStageAdapter else
                        (k == self.bridge.POLICY and callable(v.prepare))
                        if type(v) is self.bridge._PolicyStageAdapter else
                        (k == self.bridge.SSH and callable(v.prepare))
                        if type(v) is self.bridge._SSHStageAdapter else
                        (k == self.bridge.CERT and callable(v.prepare))
                        if type(v) is self.bridge._CertStageAdapter else callable(v)
                        for k, v in registry.items()),
                3, 'INVALID_ADAPTER_REGISTRY')
        self.staged = type(registry.get(self.bridge.PLATFORM)) is self.bridge._PlatformStageAdapter
        self.openssl_staged = type(registry.get(self.bridge.OPENSSL)) is self.bridge._OpenSSLStageAdapter
        self.policy_staged = type(registry.get(self.bridge.POLICY)) is self.bridge._PolicyStageAdapter
        self.ssh_staged = type(registry.get(self.bridge.SSH)) is self.bridge._SSHStageAdapter
        self.cert_staged = type(registry.get(self.bridge.CERT)) is self.bridge._CertStageAdapter
        require(not (self.openssl_staged or self.policy_staged or self.ssh_staged or self.cert_staged) or self.staged,
                3, 'INVALID_ADAPTER_REGISTRY')
        try:
            eligible = {n: self.bridge.requested(ctx._decisions[n]['requested_flags']) for n in ctx._targets}
        except self.bridge.BridgeError:
            raise Denied(2, 'UNSUPPORTED_PRODUCER') from None
        require(all(set(v) <= registry.keys() for v in eligible.values()), 2, 'PRODUCER_ADAPTER_NOT_AVAILABLE')
        # A staged CP2 host must not derive its ordered acquisition from a
        # generic OpenSSL surrogate when that same host requests O2.
        require(not self.policy_staged or self.openssl_staged or
                all(not {self.bridge.POLICY, self.bridge.OPENSSL} <= set(v)
                    for v in eligible.values()), 3, 'INVALID_ADAPTER_REGISTRY')
        require(not self.ssh_staged or all(
            self.bridge.SSH not in v or ((self.bridge.OPENSSL not in v or self.openssl_staged)
                                         and (self.bridge.POLICY not in v or self.policy_staged))
            for v in eligible.values()), 3, 'INVALID_ADAPTER_REGISTRY')
        require(not self.cert_staged or all(
            self.bridge.CERT not in v or ((self.bridge.OPENSSL not in v or self.openssl_staged)
                                         and (self.bridge.POLICY not in v or self.policy_staged)
                                         and (self.bridge.SSH not in v or self.ssh_staged))
            for v in eligible.values()), 3, 'INVALID_ADAPTER_REGISTRY')
        ledger = _ProducerLedger(ctx, self, eligible)
        targets = [n for n in ctx._targets if eligible[n]]
        if targets:
            self.handoff = self.bridge.Handoff(self.run_id, targets)
        return registry, ledger

    def cancelled_before_prepare(self, ctx):
        if self.run_id is None:
            self._identity(ctx)
        return _ProducerLedger(ctx, self, {n: () for n in ctx._targets})

    def budget(self, producers):
        return sum(_platform_budget() if self.staged and p == self.bridge.PLATFORM else
                   _openssl_budget() if self.openssl_staged and p == self.bridge.OPENSSL else
                   _policy_budget() if self.policy_staged and p == self.bridge.POLICY else
                   _ssh_budget() if self.ssh_staged and p == self.bridge.SSH else
                   _cert_budget() if self.cert_staged and p == self.bridge.CERT else
                   _COMMAND_SECONDS + 1 for p in producers)

    def collect(self, name, flags, registry):
        """Called only after the unchanged native per-dispatch/argv guard."""
        b = self.bridge
        flags = copy.deepcopy(flags)
        records = []
        worker = _PLATFORM_WORKER.get()
        if self.staged:
            require(type(worker) is _PlatformWorker and worker.name == name, 3, 'INVALID_NATIVE_RESULT')
        try:
            seconds = _SSH_SECONDS if worker is None else worker.limit(time.monotonic() + _SSH_SECONDS) - time.monotonic()
            with _deadline(seconds):
                connected = _restricted_connection(name)
        except (_Deadline, Exception):
            connected = 'REMOTE_CLEANUP_UNCONFIRMED'
        if connected not in b.CONNECTIONS:
            connected = 'INVALID_ADAPTER_RESULT'
        if connected == 'CONNECTED':
            platform_snapshot = None
            ssh_requested = self.ssh_staged and any(flags[f] for f in (b.SSHD, b.KEYS))
            cert_requested = self.cert_staged and flags[b.CERT_FLAG]
            for producer in b.requested(flags):
                value = None
                staged_producer = ((self.staged and producer == b.PLATFORM) or
                                   (self.openssl_staged and producer == b.OPENSSL) or
                                   (self.policy_staged and producer == b.POLICY) or
                                   (ssh_requested and producer == b.SSH) or
                                   (cert_requested and producer == b.CERT))
                try:
                    if self.staged and producer == b.PLATFORM:
                        worker.start(self.run_id)
                        value = registry[producer].collect(self.run_id, name, worker.task_uuid,
                                                           worker.invoke, worker.validate)
                        row = worker.validate(b.record, producer, value, flags, platform_snapshot, self.run_id, name)
                        if (((self.openssl_staged and b.OPENSSL in b.requested(flags))
                             or (self.policy_staged and flags[b.POLICY_FLAG]) or ssh_requested or cert_requested)
                                and row['snapshot'] is not None and not b.record_stop(row)):
                            worker.note_platform(row)
                    elif (self.openssl_staged and producer == b.OPENSSL
                          and b._platform_status(platform_snapshot) == 'UNVERIFIED'):
                        worker.start_openssl(self.run_id, flags, platform_snapshot)
                        value = registry[producer].collect(self.run_id, name, worker.task_uuid, flags,
                                                           platform_snapshot, worker.invoke, worker.validate)
                        row = worker.validate(b.record, producer, value, flags, platform_snapshot,
                                              self.run_id, name, staged_openssl=True)
                        require(row['snapshot'] is None or worker.ordinal == len(worker.plan),
                                3, 'INVALID_NATIVE_RESULT')
                        if ((self.policy_staged and flags[b.POLICY_FLAG]) or ssh_requested or cert_requested) and not b.record_stop(row):
                            worker.note_openssl(row)
                    elif self.policy_staged and producer == b.POLICY:
                        worker.start_policy(self.run_id, flags, platform_snapshot)
                        value = registry[producer].collect(self.run_id, name, worker.task_uuid, flags,
                                                           platform_snapshot, worker.invoke, worker.validate)
                        row = worker.validate(b.record, producer, value, flags, platform_snapshot,
                                              self.run_id, name,
                                              gap=value['reason_code'] == 'PLATFORM_GAP', staged_policy=True)
                        require(row['snapshot'] is None or
                                (worker.ordinal == len(worker.plan) and not worker.lease.pending(name)),
                                3, 'INVALID_NATIVE_RESULT')
                        worker.limit(worker.producer_end)
                        if (ssh_requested or cert_requested) and not b.record_stop(row):
                            worker.note_policy(row)
                    elif ssh_requested and producer == b.SSH:
                        worker.start_ssh(self.run_id, flags, platform_snapshot)
                        value = registry[producer].collect(self.run_id, name, worker.task_uuid, flags,
                                                           platform_snapshot, worker.invoke, worker.validate)
                        row = worker.validate(b.record, producer, value, flags, platform_snapshot,
                                              self.run_id, name, gap=value['reason_code'] == 'PLATFORM_GAP',
                                              staged_ssh=True)
                        if row['snapshot'] is not None:
                            worker.note_ssh(row)
                        worker.limit(worker.producer_end)
                    elif cert_requested and producer == b.CERT:
                        worker.start_cert(self.run_id, flags, platform_snapshot)
                        value = registry[producer].collect(self.run_id, name, worker.task_uuid, flags,
                                                           platform_snapshot, worker.invoke, worker.validate)
                        row = worker.validate(b.record, producer, value, flags, platform_snapshot,
                                              self.run_id, name, gap=value['reason_code'] == 'PLATFORM_GAP',
                                              staged_cert=True)
                        if not b.record_stop(row):
                            worker.note_cert(row)
                        worker.limit(worker.producer_end)
                    else:
                        # Legacy single-call surrogate budget unchanged. A
                        # staged host's later producers also observe the lease.
                        seconds = _COMMAND_SECONDS + 1
                        if worker is not None:
                            seconds = worker.limit(time.monotonic() + seconds) - time.monotonic()
                        with _deadline(seconds):
                            gap = producer != b.PLATFORM and b._platform_status(platform_snapshot) != 'UNVERIFIED'
                            if gap:
                                value = dict(reason_code='PLATFORM_GAP', rc=None, cleanup_confirmed=True,
                                             snapshot=b._gap_snapshot(producer, flags, b._platform_status(platform_snapshot)))
                            else:
                                value = registry[producer](name, copy.deepcopy(flags), copy.deepcopy(platform_snapshot))
                            row = b.record(producer, value, flags, platform_snapshot, self.run_id, name, gap=gap)
                        if worker is not None:
                            worker.limit(worker.host_end)
                        if (ssh_requested or cert_requested) and producer == b.OPENSSL:
                            # A selected noneligible O2 is an exact typed gap,
                            # not authorization to invoke a generic callable.
                            worker.note_openssl_gap(row, flags, platform_snapshot)
                except _Deadline:
                    clean = (staged_producer and not worker.lease.pending(name))
                    row = b.failed_record(producer, 'CONTROLLER_TIMEOUT' if clean else 'REMOTE_CLEANUP_UNCONFIRMED', cleanup=clean)
                except Exception:
                    # A malformed projection is not a successful acquisition.
                    # Only a genuine adapter cleanup receipt permits the less
                    # severe invalid-result classification.
                    clean = (not worker.lease.pending(name) if staged_producer else
                             type(value) is dict and value.get('cleanup_confirmed') is True)
                    row = b.failed_record(producer, 'INVALID_ADAPTER_RESULT' if clean else 'REMOTE_CLEANUP_UNCONFIRMED', cleanup=clean)
                records.append(row)
                if producer == b.PLATFORM:
                    platform_snapshot = row['snapshot']
                    if platform_snapshot is None:
                        break
                if b.record_stop(row, staged_ssh=ssh_requested) or b._host_local_stop(row, staged_ssh=ssh_requested):
                    break
        if worker is not None:
            worker.limit(worker.host_end)
        envelope = dict(handoff_version=b.WIRE_VERSION, run_id=self.run_id, target_id=name,
                        connection=connected, records=records)
        if self.cert_staged and flags[b.CERT_FLAG]:
            if worker is not None:
                with _deadline(worker.limit(worker.host_end) - time.monotonic()):
                    b._cert_handoff_budget(envelope)
            else:
                b._cert_handoff_budget(envelope)
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

    def finish(self, ctx, ledger, interrupted, *, workflow=None):
        if not self.close():
            ledger.fail('CONTROLLER_CLEANUP_UNCONFIRMED')
            for name in ledger.started:
                ledger.worker_failed(name, 'CONTROLLER_CLEANUP_UNCONFIRMED')
        # Freeze only after all original lifecycle and Handoff cleanup
        # decisions. The private path never enters the legacy aggregation.
        mask = None if workflow is None else signal.pthread_sigmask(
            signal.SIG_BLOCK, (signal.SIGINT, signal.SIGTERM))
        try:
            if interrupted() or (workflow is not None and
                    {signal.SIGINT, signal.SIGTERM} & signal.sigpending()):
                # At the masked terminal-freeze boundary, pending acquisition
                # signals belong to the original terminal decision. Consume
                # those exact pending signals so they are not counted twice.
                if workflow is not None:
                    for sig in {signal.SIGINT, signal.SIGTERM} & signal.sigpending():
                        signal.sigwait({sig})
                ledger.fail('INTERRUPTED')
            rows = ledger.finish()
            # Use the original B05 classification with platform excluded.
            rc, base = _manifest(ctx, [_v2_base_row(r) for r in rows], ledger.stop)
            manifest = {**base, 'batch_manifest_version': 2, 'hosts': rows}
            validate_producer_manifest(manifest, rc)
            if workflow is not None:
                workflow.freeze(rc)
        finally:
            if mask is not None:
                signal.pthread_sigmask(signal.SIG_SETMASK, mask)
        if workflow is not None:
            return workflow.persist(manifest, ledger)
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
