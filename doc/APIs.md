[-]: # " -*- mode: gfm; coding: utf-8 -*- "

# API functions of suid_sudo module

Some constants (e.g. `True` / `true`, `False` / `false`) will have
different symbols between Python and Ruby.  Please read it according
to each language.

In Perl, keyword arguments should be passed as a string-named hash,
and truth values are treated according to usual language semantics.
For example, you can write as:

    suid_emulate(use_shebang => 1);

## Loading

In Python,

    import suid_sudo

will import `suid_sudo` module.

    from suid_sudo import *

will import all public APIs below to the current module, useful for
short scripts.

In Ruby, use of

    require 'suid_sudo'

will load `SUID_SUDO` module. (capitalized for Ruby constant.)

If you want to use it without module prefix, write:

    require 'suid_sudo'
    include SUID_SUDO::INCLUDE

(Direct inclusion of `SUID_SUDO` module will import many internal
private symbols.)

in Perl,

    use SUID_SUDO;

will load the module into the SUID_SUDO package.

    use SUID_SUDO ":all";

will also import API functions into current package context.

## Set-up Routine

### suid_emulate

Emulate behavior of set-uid binary when invoked via sudo(1).

This function is to be invoked as early as possible in the script
intended to be invoked via sudo.

It detects whether the user invoking the script via sudo, and set real
uid and real gid appropriately.  In more detail,

 * Real user ID and real group ID are set to that of invoking users,
   obtained from the environmental variables set by SUDO.
 * Effective User ID and Group ID are set to root.
 * Secondary group list is initialized to the default setting of
   invoking users.  (`Sudo` set it to root, but it is not usually what
   people wants.  Unfortunately, it is hard to reset it to that before
   the `sudo` invoked.)

The function returns true when setuid is effective (either natively or
by emulation): false otherwise (invoked directly as either root or a
non-root user).

All arguments are optional and these meanings are as follows:

 * realroot_ok: default False. Specify whether the script can be
   invoked as real root user (via sudo by root).

 * nonsudo_ok: default False. Specify whether the script can be
   invoked by root user without sudo.  When enabled, misconfiguration
   might open security holes to ordinary users; _be extremely careful_
   and _do not use unless really required_; root users can still use
   script using this module by `realroot_ok`option above and
   invocation via explicit `sudo`.

 * sudo_wrap: default False. If set to True, the script will try to
   invoke itself via sudo(1), when root privilege is not available.
   Sudo must be configured appropriately so that required ordinary
   users can invoke this script (by its full-path with python
   command).

   A special command-line argument is used to communicate between
   invoking/self-invoked scripts, thus the function MUST be called
   before any command-line processing (e.g. argparse in Python).

 * use_shebang: default False; only meaningful when sudo_wrap=True.
   If set to True, the module will directly invoke the script itself
   as an executable, expecting "#!" feature of the underlying
   operating system to work.

   Use of this flag requires changes to the sudo configuration.

 * python_flags: (Python only) default "I"; only meaningful when
   sudo_wrap=True and use_shebang=False.  A string containing
   one-character flags to be passed to the python interpreter called
   when sudo_wrap=True.

   In Python 2.7, "I" flag will be translated to combination
   "-E -s" flags.

 * ruby_flags: (Ruby only) default "T"; only meaningful when
   sudo_wrap=True and use_shebang=False.  A string containing
   one-character flags to be passed to the Ruby interpreter called
   when sudo_wrap=true.

 * perl_flags: (Perl only) default "T"; only meaningful when
   sudo_wrap=True and use_shebang=False.  A string containing
   one-character flags to be passed to the Ruby interpreter called
   when sudo_wrap=true.

 * inherit_flags: default False; only meaningful when sudo_wrap=True
   and use_shebang=False.  If set to True, it will pass some of the
   flags originally passed to the Python/Ruby/Perl interpreter.
   It's always safer to specify explicitly using *_flags option.

 * env_pass: default []; list of names of environment variables which
   passed the wrapped command.  Effective only with sudo_wrap=True.
   Its value is encoded to special environmental variable; it exploits
   the fact that sudo passes all variables starts with "LC_".

   *Caution*: passing some system-defined variables such as IFS,
   LD_PRELOAD, LD_LIBRARY_PATH will lead to creation of a security
   hole.  This option can bypass security measures provided by sudo,
   if the script really tells this module to do so.  Use this feature
   only when it is really needed.

 * showcmd_opts:

   default None; if a string is given, this function will compare it
   with first command-line argument.  If it matches, it shows the
   command line for the re-invocation and exit.  If `True` (`1` in
   Perl) is passed, it is treated as `"--show-sudo-command-line"`.

## Privilege Switching Functions

There are four functions performing switching between privileges.
These functions will set user-ids and group-ids accordingly and
set some user-related environmental variables (e.g. HOME) as well.

An optional parameter "setenv=False" will skip setting user-related
environmental variables (not available in Perl).

See the "Exceptions" section for special handling of the errors
in these functions.

Each of these functions can be used either as an ordinary function, or
with a block of code, according to the syntax of each languages.
As an ordinary function, it will just change the UID/GID.
With a code block, it will revert the UID/GID setting after execution.

In Python, a code block can be specified using "with" statement.
The following two blocks are similar after call to `suid_emulate()`.

    temporarily_as_user()
    do_user_level_task...
    temporarily_as_root()

    with temporarily_as_user:
        ... do_user_level_task ...

In Ruby, a code block can be specified as a block parameter to
functions, as follows:

    temporarily_as_user
    do_user_level_task...
    temporarily_as_root

    temporarily_as_user {
        ... do_user_level_task ...
    }

In Perl, a code block can be specified as a code reference argument
to functions as follows:

    temporarily_as_user;
    ... do_user_level_task ...
    temporarily_as_root;

    temporarily_as_user {
        ... do_user_level_task ...
    };

In Ruby, you can also use system-builtin `Process::UID` and
`Process::GID` modules.  Please do not mix use of these modules and
the functions below.

### temporarily_as_root

Set effective user/group ID to the privileged user, and
real user/group ID to the unprivileged user.
Secondary groups are set to those of the unprivileged user.

### temporarily_as_real_root

Set both real and effective user/group IDs to the privileged user.
Secondary groups are set to [0].
It is useful when invoking setuid-aware program (e.g. mount(8)) as root.

### temporarily_as_user

Set effective user/group ID to the unprivileged user, and
real user/group ID to the privileged user.
Secondary groups are set to those of the unprivileged user.

It should not be used to run any untrusted code or programs,
because these can regain the root privilege by seteuid(2) or
`temporarily_as_root()` above.

### drop_privileges_forever

Set both real and effective user/group ID to an ordinary user,
dropping any privilege for all the future.

It can be used to execute a command for which the calling user can do
whatever (e.g. shell, editor or language interpreter), or to perform
possibly-dangerous operation (e.g. eval or import).

After calling this, the process can not call `temporarily_as_root()`
or other similar functions to revert the privileged status anymore.
Using this as an context manager (Python) / with a block argument
(Ruby/Perl) is also meaningless. If really needed, consider using
`fork()` or `{call/run}_in_subprocess()` described below to separate
the unprivileged operations to a child process.

## Calling an External Program

### in Python

In Python, if you need to call an external program with an altered
privilege, pass one of the above privilege-changing function to a
`preexec_fn` parameter of functions in subprocess built-in module.

    import subprocess
    subprocess.call(args=["vi", "/tmp/file"],
                    preexec_fn=drop_privileges_forever)

### in Ruby: spawn_in_privilege

In Ruby, a wrapper function `spawn_in_privilege` is provided.
It will take the argument similar to `exec` or `system` builtin,
with two additional arguments at the beginning:

 * The first argument is either a symbol `:system` or `:spawn`.
   If `:system` is given, the function will wait for the process
   termination and returns the return status of the called program.
   If `:spawn` is given, the function will return immediately when
   invoking the child program is succeeded, and its process ID is
   returned.

   In either case, if it cannot "exec" the child program, it will
   raise an appropriate OSError instance synchronously.

 * The second argument is either

   - a symbol corresponding to the names of the above four
     privilege-changing functions, representing what privilege will be
     passed to the called program;

   - A Method or Proc object, which is called before invoking the
     child program (similar to preexec_fn in Python).

 * The rest of arguments will be passed to the "exec" built-in.

The usage equivalent to above Python example is as follows:

    spawn_in_privilege(:system, :drop_privileges_forever,
                        "vi", "/tmp/file")

### in Perl: spawn_in_privilege

The function `spawn_in_privilege` for Perl is similar for that of
Ruby.  Differences are:

 * The type of the first argument is string.
 * The type of the second argument is either a string
   or a code reference (or code grob).
 * The rest arguments are passed to exec of the Perl.

Its semantics tends to be similar to `system()` in Perl; however,

  * SIGINT/QUIT signals are not ignored (at least currently).

  * If exec is failed, it will die instead of setting $? to -1.

  * The rest arguments are passed to `exec` of Perl builtin.  However,
    if it is a single array reference, it will be specially translated
    to bypass any shell interventions.  The arguments are translated as
    follows:

        spawn_in_privilege(..., ..., a) => exec(a)
        spawn_in_privilege(..., ..., a, b) => exec(a, b)
        spawn_in_privilege(..., ..., [a]) => exec a (a)
        spawn_in_privilege(..., ..., [a, b]) => exec a (a, b)
        spawn_in_privilege(..., ..., [[a, a0], b]) => exec a (a0, b)

If the first argument is "spawn" and the execution of command has
succeeded, it will return the process ID of the child.

Please do not use "child reaper" signal handlers with "system".

## Running Some Code in Sub-process

As said above, untrusted code should be run with "completely
untrusted" privilege.  It means that the result of such untrusted
computations cannot be used in any trusted operations later.

To resolve this, the module provides a helper function which
will evaluate some portion of program within a forked subprocess.

Return value of the evaluation is returned to caller, using
inter-process communications.  Such value is restricted to safe ones
presentable in JSON or a little more; it cannot be a class instances
with special methods (it obviously causes a security issue).  Simple
booleans, numbers, strings, or lists or hashes of those values are all
OK.

Exceptions are also propagated to the caller in a limited manner.
Most of the built-in exceptions (especially system-call errors)
are transparently passed to the parent; non-builtin Exceptions are
either coerced to a parent built-in exception or wrapped with
WrappedSubprocessError exception.

The called function MUST return some value or raise an exception
within Python.
If you intend to exec() an external process, consider using
other functions.

### call_in_subprocess (for Python)

In Python, call_in_subprocess function takes a one function
pointing to a function closure.

To evaluate arbitrary expression within a dropped privilege,
either write:

    # clean way
    def _():
        drop_privileges_forever()
        return what_to_do(...)
    result = call_in_subprocess(_)

or

    # dirty trick
    @call_in_subprocess
    def result():
        drop_privileges_forever()
        return what_to_do(...)

Current implementation uses a safe subset of Pickle bytecode
for return value communication in Python.

### run_in_subprocess (for Ruby)

In Ruby, run_in_subprocess function takes a block argument.

To evaluate arbitrary expression within a dropped privilege,
write:

    result = run_in_subprocess {
        drop_privileges_forever()
        what_to_do(...)
    }

Current implementation uses `YAML.safe_load` for return value
communication in Ruby.

### run_in_subprocess (for Perl)

In Perl, run_in_subprocess can be similarly used as Ruby.
All exceptions are propagated as a simple string.
Current implementation uses `JSON` (`JSON::PP`) for return value
communication in Perl.

## Misc functions

Functions in this section are not exported; these should be called via
an explicit module reference.

### show_sudo_command_line

It displays how the script will be re-invoked via sudo, to standard
error stream (usually a console).

Parameters `use_shebang`, `{python|ruby|perl}_flags`, `inherit_flags`,
`pass_env` are as same as `suid_emulate()`.

### compute_sudo_commane_line_patterns

It returns strings representing the command-line patterns for
re-invocation.  It returns a pair; the first element is a descriptive
string for re-invocation pattern, and the second element is one
used as an entry in `sudoers` file.

Parameters `use_shebang`, `{python|ruby|perl}_flags`, `inherit_flags`,
`pass_env` are as same as `suid_emulate()`.

A string given in `user_str` parameter is used for users specification
in `sudoers` patterns.

## Defined Exceptions

The following exceptions are implemented for Python and Ruby.

### SUIDHandlingError

A general runtime error raised during processing by suid_sudo module.
It is derived from `RuntimeError` in Python and Ruby.

### SUIDSetupError

A runtime error raised during initial setup of this module.

### SUIDPrivilegesSettingError

A runtime error raised when "gaining" some privileges is failed.

### SUIDPrivilegesSettingFatalError

A _fatal_ runtime error raised when "dropping" privileges is failed.

Failure on dropping privileges (including reverting to the lower
privileges after high-privilege code is run) is really
security-critical.  Such an event is quite unlikely to happen in usual
cases, but once happened and if improperly handled, it will cause
dangerous security issue: some code to be run in privileges higher
than expected.

To mitigate this, for an extra caution, such failure is treated not
like a usual exception, but like a call to `exit()`; its event will
not be captured by `try: ... except RuntimeError: ...` in Python or
simple `begin ... rescue ...` in Ruby.  (Internally,
`SUIDPrivilegesSettingFatalError` is derived from `BaseException` in
Python or `SecurityError` in Ruby.)

Any `finally` clauses, as well as the simplest `try: ... except: ...`
clause in Python still cover these cases, so be careful what to write
in these clauses.

If you really need this case to be handled, you must be very careful
to write exception-handling code in the manner which can be run with
unknown/unexpected privileges; then, you can capture this "exception"
explicitly by its name.

### SUIDSubprocessError

A runtime error raised when `call_in_subprocess` or
`run_in_subprocess` had a failure.  Most common cause of
this error is that the given code did not return a value
(e.g. by calling "`exec()`").

### WrappedSubprocessError

A runtime error raised when the code called with `call_in_subprocess`
or `run_in_subprocess` raised a non-builtin exception.
It is a subclass of `SUIDSubprocessError`.

### Errors in Perl

In Perl, a blessed object defined in SUID_SUDO:: package hierarchy
will be thrown (by `die`) when any error has occurred.  See `perlfunc`
manual page for details on how to handle these in an object-oriented
way.  `SUIDPrivilegesSettingFatalError` is not provided in Perl, as
exception handling constructs of Perl are very simple.

## Reference

 * suid_sudo: https://github.com/yoiwa-personal/suid_sudo/

## Author

Yutaka OIWA <yutaka@oiwa.jp>.

This file should be treated as a part of suid_sudo module,
distributed under Apache License 2.0.
