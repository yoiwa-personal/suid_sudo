# -*- python -*-
# Python library to simulate suid-script by sudo
#
# https://github.com/yoiwa-personal/suid_sudo/
#
# Copyright 2019 Yutaka OIWA <yutaka@oiwa.jp>.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Emulate behavior of set-uid binary when invoked via sudo(1).

This module enables Python scripts to perform most of its works in the
invoking user's non-root privilege, while employing root's power
for a part of its job.

Programmers using this module shall be aware of Uni* semantics
and techniques around the "setuid" feature.

The main function in this module is the "suid_emulate" function.

Functions/Features available:

     - Initialize: suid_emulate
     - Privilege Control: temporarily_as_root, temporarily_as_user,
       temporarily_as_real_root, drop_privileges_forever
     - Execution Helper: call_in_subprocess

Currently Linux 4.0+ is required.

SECURITY WARNING:

    Inappropriate use of this module will open up a huge security hole
    to ordinary users.  In the past obsolete "suidperl" feature of the
    Perl language, the special language interpreter takes care of
    various possible security pitfalls (e.g. limiting use of
    $ENV{PATH}).  This module, on the contrary, simply relies
    on the "sudo" generic wrapper for the most of the security
    features.  In other words, this module only "drops" the privilege
    given by sudo, not "acquires" any.  However, still there are
    several possible pitfalls which may grant root privileges to
    ordinary users.

    In general, the script must be safe enough to be run via sudo.
    That means:

      - the script should be owned by root and not modifiable by any
        ordinary users,

      - the script should be explicitly specified in sudoers(5) file
        with the full pathspec, and

      - the script must be careful about any environment variables and
        any other environmental properties which will affect Python,
        the script, and any subcommands invoked from it.

    Please read README.md for security details.
"""

from __future__ import print_function # for Python2
import sys
import os
import os.path
import pwd
import pickle
import base64
import binascii # for Error
import errno

# Python 2/3 bi-compatibility

_ispython2 = False
if sys.version_info[0] == 2:
    _ispython2 = True
    if sys.version_info < (2, 7, 13):
        raise RuntimeError("too old python2 version")
    else:
        pass
else:
    if sys.version_info < (3, 5, 3):
        raise RuntimeError("too old python3 version")
    else:
        pass

if _ispython2:
    import fcntl

# Exceptions

class SUIDHandlingError(RuntimeError):
    """Runtime error happened during processing by suid_sudo."""
    pass

class SUIDSetupError(SUIDHandlingError):
    """Runtime error happened during initial setup by suid_sudo."""
    pass

class SUIDPrivilegesSettingError(SUIDHandlingError):
    """Runtime error during changing privileges."""

class SUIDPrivilegesSettingFatalError(BaseException):
    """Fatal Runtime error during dropping privileges.

    Failure on dropping privileges (including reverting to the lower
    privileges after high-privilege code is run) is really
    security-critical.  Such an event is qute unlikely to happen in
    usual cases, but if improperly handled, it will cause dangerous
    security hole: some code to be run in higher-than-expected
    privileges.  To prevent this, this module treats such a failure
    like a call to sys.exit(), which event will not be captured by
    "try ... except RuntimeError: ..." or similar clauses.

    All finally clauses, and simple "try ... except:" clauses still
    catches this exception, so be careful what to do in these clauses.

    If you really need this case to be captured and treated, please
    write exception-handling code very carefully in the manner which
    can be run with unknown/unexpected privileges, then you can catch
    this "exception" by its name
    ("try: ... except SUIDPrivilegesSettingFatalError: ...").

    """

class SUIDSubprocessError(SUIDHandlingError):
    """Runtime error happened during handling of subprocesses."""
    pass

class SUIDSubprocessExecutionError(SUIDSubprocessError):
    """Runtime error happened due to bad code behavior inside child process.

    For example, a child process is gone (by exec) before returning a
    value.

    """
    pass

class WrappedSubprocessError(SUIDSubprocessError):
    """Error caused by execution of code inside sub-processes.
    Indicates that a non-builtin exception is raised within subprocess.

    The field klass contains a string representing a name of the
    exception class.

    """
    def __init__(self, module, klass, msg):
        self.module = module
        self.klass = klass
        self.msg = str(msg)
        super(SUIDSubprocessError,self).__init__(module, klass, msg)

# Module constants

# List of allowed sudo commands in full-path.
allowed_sudo = ("/bin/sudo", "/usr/bin/sudo")

# Internal-use classes

class _SuidStatus:
    """Class representing status of the running process under suid handling.

    A class variable "_status" contains a singleton instance
    representing the current process's status.

    """

    _status = None

    @classmethod
    def _make_status_now(self, *args, **kwargs):
        """Initialize internal status cache for the suid handling."""
        if self._status:
            raise SUIDSetupError("_make_status_now called twice")
        status = self._status = _SuidStatus(*args, **kwargs)
        return status

    def __init__(self, is_suid, via_sudo, signal_mode=None, uids=None, gids=None, groups=None, user_pwent=None):
        self.is_suid = is_suid
        self.suid_via_sudo = via_sudo
        self.signal_mode = signal_mode
        self.uid, self.euid, self.suid = uids  if uids       is not None else os.getresuid()
        self.gid, self.egid, self.sgid = gids  if gids       is not None else os.getresgid()
        self.groups = groups                   if groups     is not None else os.getgroups()
        self.user_pwent = user_pwent           if user_pwent is not None else pwd.getpwuid(self.uid)
        self.root_pwent = pwd.getpwuid(self.euid)

        assert (self.user_pwent.pw_uid == self.uid)
        assert (self.root_pwent.pw_uid == self.euid)
        return

    def __repr__(self):
        return "<%s: %s>" % (
            self.__class__.__name__,
            ",".join("%s=%r" % (k, getattr(self,k)) for k in
                     ("is_suid", "suid_via_sudo", "uid", "euid", "suid",
                      "gid", "egid", "sgid", "groups", "user_pwent", "root_pwent")))
    def __str__(self):
        return repr(self)

class _Surround_Info:
    _surrounds = None

    SUCCESS = object()
    ENOENT = object()
    EPERM = object()

    @classmethod
    def check_surround(self):
        """Acquire a "consistent" information on the parent process.

        A struct containing the following member is returned:
           status: a symbol representing the result combination
           ppid:   the process ID of the parrent process.
           p_path: the path of the executable.
           p_stat: the stat information of p_path.

        The following combinations will be availble.

        (1) If the parent is alive and accesible:
            (status: SUCCESS,
             ppid:   integer,
             p_path: string
             p_stat: a stat struct)

            These three pieces of information are guaranteed to be
            consistent and referring to the same "process" object,
            at some instant moment during this function was running.
            It might be different from the things "now".

        (2) If the parent is alive but not accessible:
            (e.g. running as non-root, parent has different privilege)
            (status: EPERM,
             ppid:   integer,
             p_path: either a string or an Error instance (EACCES or EPERM),
             p_stat: an Error instance (EACCES or EPERM))

            These three pieces of information are guaranteed to be
            consistent at some instant moment during this function was
            running.

        (3) If the parent has died early:

            (status: ENOENT,
             ppid:   integer or 1,
             p_path: nil,
             p_stat: nil)

            If the parent died before this function started examining,
            ppid will be 1.
            Otherwise, if the parent died during examining, ppid will be
            the first available value.

        Errors:
          Errno::EAGAIN:
             will be raised if the function fails to acquire a
             consistent information with several times of trials.
          RuntimeError:
             will be raised if things get something unexpected.

        Caveats: what happens if two executable ping-pongs altogether?
        (OK for suid_sudo because it will never happen when one side is sudo)
        """
        if self._surrounds: return _surrounds
        surrounds = self._surrounds = _Surround_Info()
        return surrounds

    _procexe_linkname = None
    @classmethod
    def procexe_linkname(self, pid):
        """Returns a path name of the "executable path" link for a given process ID.
        Existence of /proc file system is assumed."""
        if self._procexe_linkname == None:
            self_pid = os.getpid()
            for l in ("exe", "file"):
                f = "/proc/%d/%s" % (self_pid, l)
                if os.path.exists(f):
                    try:
                        os.readlink(f)
                        # exe link must be available and is a readable link
                    except OSError as e:
                        raise "/proc system is something bad"

                    self._procexe_linkname = l
                    break
            if self._procexe_linkname == None:
                raise SUIDSetupError("cannot read /proc to check sudo")

        return "/proc/%d/%s" % (pid, self._procexe_linkname)

    def __init__(self):

        def b(x):
            #print(x)
            pass

        # self status is reliable and stable.
        self.pid = pid = os.getpid()

        # all the following status values might change during execution.
        # ppid may change only once to 1 when the parent exits.
        self.ppid = ppid_0 = os.getppid()

        # is_root = Process::euid == 0
        # is_suid = Process::euid != Process::uid

        stat_proc = os.stat("/proc")
        # sanity check: existence of the proc file system
        if not (stat_proc.st_uid == 0 and stat_proc.st_gid == 0 and
                stat_proc.st_dev & 0xff00 == 0 and # non-device-backed file system
                stat_proc.st_mode == 0o40555):
            raise "/proc system is something bad"

        # sanity check: check for exe link

        _Surround_Info.procexe_linkname(pid)

        for xtimes in range(0,10):
            ppid_1 = path_1 = stat_1 = stat_2 = path_2 = ppid_2 = None
            self.status = None

            b("==== ppid_1 ==== (%d)" % (xtimes,))
            ppid_1 = os.getppid()
            if (ppid_1 == 1) :
                # parent exited
                self.status = self.ENOENT
                self.p_path = nil
                self.p_stat = nil
                return

            linkpath_1 = _Surround_Info.procexe_linkname(ppid_1)

            try:
                b("path_1")
                path_1 = os.readlink(linkpath_1)
            except OSError as e:
                if e.errno == errno.ENOENT:
                    # parent exited now
                    if os.getppid() != 1:
                        raise
                    else:
                        continue
                elif e.errno == errno.EPERM or e.errno == errno.EACCES:
                    # cannot read: different owner?
                    ppid_2 = os.getppid()
                    if ppid_2 == ppid_1:
                        # cannot read: different owner, still alive
                        if ppid_0 != ppid_1:
                            raise
                        self.status = self.EACCES
                        self.p_path = e
                        self.p_stat = e
                        return
                    elif ppid_2 == 1:
                # cannot read: because parent exited (and I am non-root)
                        continue
                    else:
                        raise

            try:
                b("stat_1")
                stat_1 = os.stat(linkpath_1)
            except OSError as e:
                if e.errno == errno.ENOENT:
                    # parent exited now
                    if os.getppid() != 1:
                        raise
                    continue
                elif e.errno == errno.EPERM or e.errno == errno.EACCES:
                    # cannot read: different owner?
                    ppid_2 = os.getppid()
                    if ppid_1 == ppid_2:
                        self.status = "EACCES"
                        stat_1 = e
                        # go through to "path_2" below to check path consistency
                    elif ppid_2 == 1:
                        # cannot read: because parent exited
                        continue
                    else:
                        raise e

            try:
                b("path_2")
                path_2 = os.readlink(linkpath_1)
                if path_1 != path_2: continue

            except OSError as e:
                if (e.errno == errno.ENOENT or e.errno == errno.EPERM or
                    e.errno == errno.EACCES):
                    continue
                else:
                    raise e

            b("ppid_2")
            ppid_2 = os.getppid()
            if ppid_1 != ppid_2: continue

            if (ppid_0 != ppid_1): raise

            self.status = self.SUCCESS if not self.status else self.status
            self.p_path = path_1
            self.p_stat = stat_1
            return

        raise OSError(errno.EAGAIN, "reading /proc not stable")

# Handling inter-process communication via sudo-wrapped invocation

def _keystr_encode(*a):
    l = [str(x) for x in a]
    if not _ispython2:
        l = [bytes(x, 'utf-8', 'surrogateescape') for x in l]
    b = base64.urlsafe_b64encode(b'\0'.join(l)).decode('ascii')
    return b

def _keystr_decode(s):
    try:
        if not _ispython2:
            s = bytes(s, 'ascii', 'error')
        v = base64.urlsafe_b64decode(s).split(b'\0')
        if not _ispython2:
            v = [str(x, 'utf-8', 'surrogateescape') for x in v]
        return v
    except (UnicodeError, ValueError, binascii.Error):
        raise SUIDSetupError("error: bad format wrapped invocation key")

def _encode_wrapper_info(envp):
    return _keystr_encode(os.getpid(), os.getuid(), os.getgid(), envp)

def _decode_wrapped_info(v, uid, gid, pass_env):
    ppid = os.getppid()
    if len(v) != 4 or str(ppid) != v[0] or str(uid) != v[1] or str(gid) != v[2]:
        raise SUIDSetupError("error: wrapped invocation key mismatch")
    return _decode_passenv(v[3], pass_env)

def _setup_passenv(pass_env):
    import random
    env_name = None
    p = None
    while (True):
        p = str(random.randint(0, 1000000000))
        env_name = "LC__SUDOWRAP_" + p # should be bigger than environment size limit
        if env_name not in os.environ:
            break
    out = []
    for k in pass_env:
        if ('=' in k):
            raise ValueError("key %s in pass_env contains = character")
        v = os.environ.get(k, None)
        if (v == None):
            out.append(k)
        else:
            out.append(k + "=" + v)
    os.environ[env_name] = _keystr_encode(*out)
    return p

def _decode_passenv(envp, pass_env):
    if envp == "": return {}
    env_name = "LC__SUDOWRAP_" + envp
    e_val = os.environ.pop(env_name, None)
    if e_val == None:
        import warnings
        warnings.warn("environment %s not found" % (env_name,))
        return {}
    e_val = _keystr_decode(e_val)
    if (len(e_val) != len(pass_env)):
        raise SUIDSetupError("bad pass_env values: length mismatch")
    for i, k in enumerate(pass_env):
        v = e_val[i]
        k2, sep, val = v.partition("=")
        if k2 != k:
            raise SUIDSetupError("bad pass_env values: key mismatch")
        if sep == "=":
            os.environ[k] = val
        else:
            #del os.environ[k]
            os.environ.pop(k, None) # ignore KeyError
    return None

# sudo-wrapped reinvocation

def _detect_wrapped_reinvoked():
    if len(sys.argv) == 1:
        return False
    arg = sys.argv[1]
    if arg[0:14] == "----sudo_wrap=":
        v = _keystr_decode(arg[14:])
        if v:
            del sys.argv[1]
            return v
        else:
            raise SUIDSetupError("error: bad format wrapped invocation key")
    else:
        return False

def _called_via_sudo():
    """Checks whether the script is called via sudo(1).

    Currently only works with Linux environments or similar.
    (It will check /proc/*/exe virtual symlink.)
    """

    ppid = os.getppid()
    has_root = (os.geteuid() == 0)

    try:
        surround_info = _Surround_Info.check_surround()
    except OSError as e:
        if e.errno == errno.EAGAIN:
            raise SUIDSetupError(e.message)
        raise e
    except RuntimeError as e:
        raise SUIDSetupError(e.message)

    if surround_info.status is _Surround_Info.ENOENT:
        if has_root:
            raise SUIDSetupError("cannot check parent process: #{surround_info.status}")
        else:
            return False
    elif surround_info.status is _Surround_Info.EPERM:
        if has_root:
            raise SUIDSetupError("cannot check parent process: #{surround_info.status}")
        if surround_info.p_path in allowed_sudo:
            return True
        # p_path may be error instance but it's OK
        return False
    elif surround_info.status is _Surround_Info.SUCCESS:
        if surround_info.p_path in allowed_sudo:
            return True
        if not has_root:
            return False

        try:
            s1 = surround_info.p_stat
            found = False
            for f_sudo in allowed_sudo:
                try:
                    s2 = os.stat(f_sudo)
                    found = True
                    if s1.st_dev == s2.st_dev and s1.st_ino == s2.st_ino:
                        # found a hardlink to known sudo
                        if True: # error or just accept
                            raise SUIDSetupError("Error: found a HARDLINK of system sudo %s at %s" % (f_sudo, surround_info.p_path))
                        return True
                except OSError as e:
                    if e.errno == errno.ENOENT:
                        pass
                    else:
                        raise e
            if r == False:
                raise SUIDSetupError("Error: no system sudo found?")
            return False
        except OSError as e:
            raise SUIDSetupError("Error: cannot check details of %s: %r" % (parent_exe, e))
        return False
    else:
        raise #notreached

def _process_python_flags(python_flags, inherit_flags):
    flags = []
    disallowed = ('c', 'i', 'm', 'h', 'V', 'd')
    ignored = []
    added = {}
    keys_to_flags = {"dont_write_bytecode": 'b',
                     "no_user_site": 's',
                     "no_site": 'S',
                     "ignore_environment": 'E',
                     "bytes_warning": 'v',
                     "isolated": 'I',
                     "quiet": 'q',
                     "hash_randomization": 'R'}
    def _add(f):
        if f in disallowed:
            raise SUIDSetupError("flag '%s' disallowed here" % f)
        elif f in ignored:
            pass
        elif f in added:
            pass
        elif _ispython2 and f == 'I':
            added[f] = True
            _add('s')
            _add('E')
        else:
            added[f] = True
            flags.append("-" + f)
    for f in python_flags:
        _add(f)
    if inherit_flags:
        for key in keys_to_flags:
            #print(key, getattr(sys.flags, key, None))
            if getattr(sys.flags, key, False):
                _add(keys_to_flags[key])
    return flags

def _construct_wrap_invoke_cmdline(use_shebang, python_flags, inherit_flags, wrapkey):
    scriptname = os.path.abspath(sys.argv[0])
    execname = sys.executable
    if not os.path.exists(scriptname):
        raise SUIDSetupError("error: could not reinvoke script: could not found myself")
    if not os.path.exists(execname):
        raise SUIDSetupError("error: could not reinvoke script: interpreter not found")
    if os.path.isdir(scriptname):
        use_shebang = False
    if use_shebang:
        execname = []
        flags = []
    else:
        execname = [execname]
        flags = _process_python_flags(python_flags, inherit_flags=inherit_flags)

    cmd = allowed_sudo[0]
    for c in allowed_sudo:
        if os.path.exists(c):
            cmd = c
            break
    args = [cmd] + execname + flags + [scriptname, "----sudo_wrap=%s" % (wrapkey,)]
    return cmd, args

def _wrap_invoke_sudo(use_shebang=False, python_flags="IR", inherit_flags=False, pass_env=[]):
    if pass_env:
        env_var = _setup_passenv(pass_env)
    else:
        env_var = ""
    wrapkey = _encode_wrapper_info(env_var)

    cmd, cmdline = _construct_wrap_invoke_cmdline(
        use_shebang=use_shebang, python_flags=python_flags,
        inherit_flags=inherit_flags,
        wrapkey=wrapkey)
    args = cmdline +  sys.argv[1:]
    #print(args)
    try:
        os.execv(cmd, args)
    except OSError as e:
        raise SUIDSetupError("could not invoke %s for wrapping: %s" % (cmd, e.strerror))
    assert False

def compute_sudo_commane_line_patterns(use_shebang, python_flags, inherit_flags, pass_env, user_str):
    """Returns the commandline pattern which is used for reinvocation via sudo.

    Returned value is a pair of strings to be displayed: the first is
    the sudo command line, and the second is a possible template for
    the sudoers configuration.

    Parameters use_shebang, python_flags, inherit_flags, pass_env are
    as same as suid_emulate().

    The parameter user_str is used in the position of the invoking
    user name in sudoers.
    """

    import re

    cmd, cmdline = _construct_wrap_invoke_cmdline(
        use_shebang=use_shebang, python_flags=python_flags,
        inherit_flags=inherit_flags,
        wrapkey='')

    cmdstr = " ".join(cmdline)

    cmdline_sudoers = [re.sub(r'([ =*\\])', r'\\\1', x) for x in cmdline]
    del cmdline_sudoers[0] # sudo itself
    sudoers = " ".join(cmdline_sudoers)
    sudoers = "%s ALL = (root:root) NOPASSWD: %s*" % (user_str, sudoers)

    return cmdstr, sudoers

def show_sudo_command_line(use_shebang, python_flags, inherit_flags, pass_env, check=False):

    """Show the commandline pattern which is used for reinvocation via sudo.

    Output is sent to stderr.

    Parameters use_shebang, python_flags, inherit_flags, pass_env are
    as same as suid_emulate().

    If check is a truth value, it will be compared with the first
    command line parameter.  if these are equal, it will show the
    information and terminate the self process automatically.
    Otherwise, do nothing.  A special value True is treated as
    "--show-sudo-command-line".

    If script want to use own logics or conditions for showing this
    information, call this function with check=False (default).

    """

    if check:
        if check is True:
            check = "--show-sudo-command-line"
        if len(sys.argv) <= 1 or sys.argv[1] != check:
            return

    cmdstr, sudoers = compute_sudo_commane_line_patterns(
        use_shebang=use_shebang, python_flags=python_flags,
        inherit_flags=inherit_flags, pass_env=pass_env, user_str=".user.")

    print("""
This command uses sudo internally. It will invoke itself as:

%s...

Corresponding sudoers line will be as follows:

%s

".user." should be replaced either by a user name or by "ALL".

Please check the above configuration is secure or not,
before actually adding it to /etc/sudoers.
    """ % (cmdstr, sudoers), file=sys.stderr)

    if check:
        exit(2)

# Detect and initialize sudo'ed and suid'ed environment

def _pick_environment(ename, type=None):
    if not type:
        type = ename
    valstr = os.environ.pop(ename, None)
    if valstr is None:
        raise SUIDSetupError("error: sudo did not set %s information: why?" % type)
    valint = int(valstr)
    if (("%d" % valint) != valstr):
        raise SUIDSetupError("error: malformed %s information from sudo: why?" % type)
    return valint

def suid_emulate(realroot_ok=False, nonsudo_ok=False,
                 sudo_wrap=False, use_shebang=False,
                 python_flags="IR", inherit_flags=False,
                 user_signal=None, pass_env=[],
                 showcmd_opts=None):
    """Emulate behavior of set-uid binary when invoked via sudo(1).

    This function is to be invoked as early as possible in the script
    intended to be invoked via sudo.

    It detects whether the script was invoked via sudo, and who
    invoked it, then it sets real uid and real gid appropriately.
    Effective uid and gid is kept as root.  It means that (a)
    os.setreuid/os.setregid can be used to switch between invoking
    users and root, and (b) os.access function will return file
    accessibility of the invoking user (beware of timing-based race
    condition, though).

    The function returns True when setuid is effective: False
    otherwise (invoked directly as either root or a non-root user).

    All arguments are optional and meaning as follows:

        realroot_ok:

            default False. Specify whether the script can be
            invoked as real root user (via sudo by root).

        nonsudo_ok:

            default False. Specify whether the script can be invoked
            by root user without sudo.  When enabled, misconfiguration
            might open security holes to ordinary users; be extremely
            careful.

        sudo_wrap:

            default False. If set to True, the script will try to
            invoke itself via sudo(1), when root privilege is not
            available.  Sudo must be configured appropriately so that
            required ordinary users can invoke this script (by its
            full-path with python command).

            A special command-line argument is used to communicate
            between invoking/self-invoked scripts, thus the function
            MUST be called before any command-line processing
            (e.g. argparse).

        use_shebang:

            default False; only meaningful when sudo_wrap=True.  If
            set to True, the module will directly invoke the script
            itself as an executable, expecting '#!'  feature of the
            underlying operating system to work.

            Use of this flag requires changes to the sudo
            configuration.

        python_flags:

            default "IR"; only meaningful when sudo_wrap=True and
            use_shebang=False.  A string containing one-character
            flags to be passed to the python interpreter called when
            sudo_wrap=True.

            In Python 2.7, "I" flag will be translated to combination
            of "-E -s" flags.

        inherit_flags:

            default False; only meaningful when sudo_wrap=True and
            use_shebang=False.  If set to True, it will pass some of
            the flags originally passed to the Python interpreter.

        pass_env:

            default []; list of names of environment variables which
            is passed the wrapped command.  Effective only with
            sudo_wrap=True.  Its value is encoded to special
            environmental variable; it exploits the fact that sudo
            passes all variables starts with "LC_".

            *Caution*: passing some system-defined variables such as
            IFS, LD_PRELOAD, LD_LIBRARY_PATH will lead to creation of
            a security hole.  This option can bypass security measures
            provided by sudo, if the script really tells this module
            to do so.  Use this feature only when it is really needed.

        showcmd_opts:

            default None; if a string is given, this function will
            compare it with first command-line argument.  If it
            matches, it shows the command line for the re-invocation
            and exit.  If "True" is passed, it is treated as if it
            were "--show-sudo-command-line".

    """
    if _SuidStatus._status:
        # already run
        return _SuidStatus._status.is_suid

    if showcmd_opts:
        show_sudo_command_line(
            use_shebang=use_shebang, python_flags=python_flags,
            inherit_flags=inherit_flags, pass_env=pass_env,
            check=showcmd_opts)

    uid, euid, suid = os.getresuid()
    wrapped_invocation_info = _detect_wrapped_reinvoked()
    is_sudoed = _called_via_sudo()

    if (not is_sudoed and wrapped_invocation_info):
        raise SUIDSetupError("Bad wrapper key found")

    if (uid != euid or euid != suid):
        # really suid-script (not supported in recent environment), or suid already set
        _SuidStatus._make_status_now(True, False)
        return True

    elif euid != 0:
        if sudo_wrap:
            if wrapped_invocation_info:
                raise SUIDSetupError("error: detected wrapping loop")
            _wrap_invoke_sudo(use_shebang=use_shebang,
                              python_flags=python_flags, inherit_flags=inherit_flags,
                              pass_env=pass_env)
        _SuidStatus._make_status_now(False, False)
        return False

    elif not is_sudoed:
        # really run by root?
        if (not realroot_ok) or (not nonsudo_ok):
            raise SUIDSetupError("This script must be invoked via sudo")
        _SuidStatus._make_status_now(False, False)
        return False

    else:
        sudo_uid = _pick_environment("SUDO_UID")
        sudo_gid = _pick_environment("SUDO_GID")

        if wrapped_invocation_info:
            wrapped_invocation_info = _decode_wrapped_info(wrapped_invocation_info, sudo_uid, sudo_gid, pass_env)

        if (not realroot_ok) and sudo_uid == 0:
            raise SUIDSetupError("This script must be run by non-root")

        sudo_username = os.environ.pop("SUDO_USER", None)
        if sudo_username is None:
            raise SUIDSetupError("error: sudo did not set username information: why?")
        del os.environ["SUDO_COMMAND"]
        del os.environ["MAIL"] # not worth to simulate

        try:
            pwdent = pwd.getpwnam(sudo_username)
        except KeyError:
            raise SUIDSetupError("error: bad username information from sudo: no corresponding user")
        if (pwdent.pw_uid != sudo_uid):
            raise SUIDSetupError("error: inconsistent user information from sudo: why?")

        # In sudo, command runs with UID=GID=0.
        # In "usual" setuid script, group list of original user is kept.
        # Simulating it here.
        os.initgroups(sudo_username, sudo_gid)
        #    sudo_groups = os.getgrouplist(sudo_username, sudo_gid)
        #    os.setgroups(sudo_groups)

        _SuidStatus._make_status_now(
            True, True, uids=(sudo_uid, 0, 0), gids=(sudo_gid, 0, 0),
            user_pwent=pwdent)

        os.setresgid(sudo_gid, 0, 0)
        os.setresuid(sudo_uid, 0, 0)
        if (os.getuid() != sudo_uid):
            raise SUIDSetupError("error: setresuid failed")
        if (os.getgid() != sudo_gid):
            raise SUIDSetupError("error: setresgid failed")

        return True

# Switch between privileges

def _raise_setting_error(to_be_root, msg):
    if to_be_root:
        raise SUIDPrivilegesSettingError(msg)
    else:
        raise SUIDPrivilegesSettingFatalError(msg)

class _UidContextRestorer:
    # helper for context-based restorations
    def __init__(self, restore_to_root, saveenv):
        self.u = os.getresuid()
        self.g = os.getresgid()
        self.groups = os.getgroups()
        self.to_root = restore_to_root
        if saveenv:
            self.env = {k: os.getenv(k, None) for k in ("LOGNAME", "USER", "USERNAME", "HOME")}
        else:
            self.env = {}

    def __enter__(self):
        return self

    def __exit__(self, *args):
        try:
            os.seteuid(s.euid)
            os.setgroups(self.groups)
            os.setresgid(*self.g)
            os.setresuid(*self.u)
            for k in self.env:
                os.putenv(k, self.env[k])
        except OSError as e:
            _raise_setting_error(self.to_root, repr(e))
        if os.geteuid() != self.u[1]:
            _raise_setting_error(self.to_root, "setresuid to %d failed" % to_u)

        return None

def _set_uids(to_be_root, completely, setenv=True):
    # returned value can be used as context manager
    s = _SuidStatus._status
    if s is None:
        raise SUIDSetupError("suid wrapper is not initialized")

    restorer = _UidContextRestorer(not to_be_root, saveenv=setenv)

    groups = s.groups
    if to_be_root:
        to_g, from_g, save_g = s.egid, s.gid, s.sgid
        to_u, from_u, save_u = s.euid, s.uid, s.suid
        pwent = s.root_pwent
    else:
        to_g, from_g, save_g = s.gid, s.egid, s.sgid
        to_u, from_u, save_u = s.uid, s.euid, s.suid
        pwent = s.user_pwent

    if completely:
        from_g = save_g = to_g
        from_u = save_u = to_u
        if to_be_root:
            groups = [s.egid]
    try:
        os.seteuid(s.euid)
        os.setgroups(groups)
        os.setresgid(from_g, to_g, save_g)
        os.setresuid(from_u, to_u, save_u)
    except OSError as e:
        _raise_setting_error(to_be_root, repr(e))
    if os.geteuid() != to_u:
        _raise_setting_error(to_be_root, "setresuid to %d failed" % to_u)
    if setenv:
        os.environ["LOGNAME"] = pwent.pw_name
        os.environ["USER"] = pwent.pw_name
        os.environ["USERNAME"] = pwent.pw_name
        os.environ["HOME"] = pwent.pw_dir
    return restorer

def temporarily_as_root(setenv=True):
    """Set effective user/group ID to the privileged user.

An optional parameter "setenv=False" will skip setting user-related
environmental variables accordingly.

It can be used either as an ordinary function, or as a context manager
in "with" statement.  As a context manager, it will revert the UID/GID
setting after execution.

It can also be used for a "preexec_fn" of subprocess module.

    """
    return _set_uids(True, False, setenv=setenv)

def temporarily_as_user(setenv=True):
    """
Set effective user/group ID to the ordinary user (the one invoking the script).

An optional parameter "setenv=False" will skip setting user-related
environmental variables accordingly.

It can be used either as an ordinary function, or as a context manager
in "with" statement.  As a context manager, it will revert the UID/GID
setting after execution.

If it is used as an ordinary function, the privilege can be regained later
by calling "temporarily_as_root" as either a function or a context manager.

It can also be used for a "preexec_fn" of subprocess module.

See SUIDPrivilegesSettingFatalError for special error handling
regarding this function.
"""
    return _set_uids(False, False, setenv=setenv)

def temporarily_as_real_root(setenv=True):
    """Set both real and effective user/group ID to the privileged user.
It is useful when invoking setuid-aware program (e.g. mount(8)) as root.

An optional parameter "setenv=False" will skip setting user-related
environmental variables accordingly.

It can be used either as an ordinary function, or as a context manager
in "with" statement.  As a context manager, it will revert the UID/GID
setting after execution.

It can also be used for a "preexec_fn" of subprocess module.
"""
    return _set_uids(True, True, setenv=setenv)

def drop_privileges_forever(setenv=True):
    """Set both real and effective user/group ID to an ordinary user,
dropping any privilege for all of the future.  After calling this,
the process can no longer call temporarily_as_root() or other similar
functions.

By default, it will set user-related environmental variables
(including $HOME) accordingly. An optional parameter "setenv=False"
will skip it.

It can be used to execute a command for which the calling user can do
whatever (e.g. shell, editor or language interpreter), or to perform
possibly-dangerous operation (e.g. eval or import) in Python.  It can
be used either as a usual function or as a "preexec_fn" of subprocess
module.

Using this as an context manager is meaningless, because it cannot
revert privileged status anymore.
If really needed, consider using os.fork() or call_in_subprocess()
to separate the unprivileged operations to a child process.

See SUIDPrivilegesSettingFatalError for special error handling
regarding this function.
"""
    return _set_uids(False, True, setenv=setenv)

# running (untrusted) code within subprocess

#   safe unpickler for subprocess communication
try:
    _UP = pickle._Unpickler
    # use "unoptimized" picker for more restrictive behavior
except AttributeError:
    _UP = pickle.Unpickler

class SafeUnpickler(_UP,object):

    safe_classes = {
        "builtins": {'range', 'complex', 'set', 'frozenset', 'slice',
                     'Exception', 'BaseException'},
        "__builtin__": {'range', 'complex', 'set', 'frozenset', 'slice'}, #PY2
        "collections": {'OrderedDict', 'defaultdict'},
        "datetime": {'date', 'time', 'datetime', 'timedelta', 'tzinfo', 'timezone'},
        "os": {'stat_result',
               '_make_stat_result'}, #PY2
        "time": {'struct_time'},
        "pwd": {'struct_passwd'},
        "grp": {'struct_group'},
    }

    @classmethod
    def is_safe_class(self, module, name):
        safe_classes = self.safe_classes
        if (module in safe_classes and
            name in safe_classes[module]):
            return True
        if (module == ("builtins" if not _ispython2 else "exceptions")
            and name.endswith("Error")):
            return True
        return False

    def find_class(self, module, name):
        if self.is_safe_class(module, name):
            return super(SafeUnpickler, self).find_class(module, name)
        raise pickle.UnpicklingError("global \"%s.%s\" is forbidden"
                                     % (module, name))

    @classmethod
    def wrap_exception(self,e):
        m, k = e.__class__.__module__, e.__class__.__name__
        if self.is_safe_class(m, k):
            return e
        return (m, k, str(e))

    def get_extension(self, code):
        raise pickle.UnpicklingError("extension is forbidden")

    def _disabled_instruction(self, c):
        def e(*s):
            raise pickle.UnpicklingError("encountered disabled instruction %r" % c)
        return e

    def __init__(self, *args, **kwargs):
        super(SafeUnpickler, self).__init__(*args, **kwargs)
        if getattr(self, "dispatch"):
            for v in b'01PQio\x81\x92':
                # POP, POP_MARK, PERSID, BINPERSID,
                # BUILD, INST, OBJ, NEWOBJ,
                # NEWOBJ_EX
                self.dispatch[v] = self._disabled_instruction(v)

def call_in_subprocess(func, *args, **kwargs):
    """call the given function within a forked subprocess.

    Return value of the called function is returned to caller, using
    the pickle library with restrictions. It means that values of only
    some simple builtin-types the value can be transferred back to the
    caller.

    Exceptions caused in the child is also propargated to the caller.
    However, non-builtin Exceptions are stringified and wrapped with
    WrappedSubprocessError.

    To evaluate arbitrary expression within a dropped privilege,
    either write:

        (clean way)
        def _():
            drop_privileges_forever()
            return what_to_do(...)
        rval = call_in_subprocess(_)

    or

        (dirty trick)
        @call_in_subprocess
        def rval():
            drop_privileges_forever()
            return what_to_do(...)

    The called function MUST return some value or raise an exception
    within Python.
    If you intend to exec() an external process, consider using
    subprocess.call() with an appropriate preexec_fn.

    """

    (rp, wp) = os.pipe()
    if _ispython2:
        # O_CLOEXEC flag is set in Python 3 only.
        for p in (rp, wp):
            fcntl.fcntl(p, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
    pid = os.fork()
    val, error = None, None
    if pid != 0:
        # parent
        os.close(wp)
        rp = os.fdopen(rp, "rb")
        try:
            (val, error) = SafeUnpickler(rp).load()
        except pickle.UnpicklingError as e:
            error = e
        except Exception as e:
            error = SUIDSubprocessExecutionError("call_in_subprocess: no value returned: %r" % e)
        rval = os.waitpid(pid, 0)[1]
        if rval != 0:
            raise SUIDSubprocessExecutionError("call_in_subprocess exited with failure: %r" % (
                rval >> 8 | (rval & 255) << 8,))
        if error:
            if isinstance(error, BaseException):
                raise error
            if isinstance(error, tuple):
                # see wrap_exception()
                raise WrappedSubprocessError(*error)
            else:
                raise SUIDSubprocessError("subprocess caused some unknown error")
        return val
    else:
        # child
        os.close(rp)
        wp = os.fdopen(wp, "wb")
        try:
            rval = (func(*args, **kwargs), False)
        except BaseException as e:
            rval = (None, SafeUnpickler.wrap_exception(e))
        pickle.dump(rval, wp)
        wp.flush()
        os._exit(0)

# Python version does not have spawn_in_privilege(), as all of its
# functionality can be done with builtin subprocess module.

# Exposed APIs

# list of public API functions.  Used with "from suid_sudo import *".
__all__ = [
    'suid_emulate',
    'drop_privileges_forever', 'temporarily_as_real_root',
    'temporarily_as_root', 'temporarily_as_user',
    'call_in_subprocess',
    'SUIDHandlingError', 'SUIDPrivilegesSettingError',
    'SUIDPrivilegesSettingFatalError', 'SUIDSetupError',
    'SUIDSubprocessError', 'SUIDSubprocessExecutionError',
    'WrappedSubprocessError',
]

if __name__ == '__main__':
    print ("run suid_sudo_test.py.")
