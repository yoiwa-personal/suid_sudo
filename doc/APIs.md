[-]: # " -*- mode: gfm; coding: utf-8 -*- "

# API functions of suid_sudo module

Some constants (e.g., `True` / `true`, `False` / `false`) have different syntax between Python, Ruby, and Perl. Please adapt the examples according to each language.

In Perl, keyword arguments should be passed as a string-named hash, and truth values follow standard Perl semantics.
For example:

    suid_emulate(use_shebang => 1);

## Loading

In Python:

    import suid_sudo

will import the `suid_sudo` module.

    from suid_sudo import *

will import all public APIs listed below into the current namespace, which is useful for short scripts.

In Ruby:

    require 'suid_sudo'

will load the `SUID_SUDO` module (capitalized as a Ruby constant).

If you want to use functions without the module prefix, write:

    require 'suid_sudo'
    include SUID_SUDO::INCLUDE

(Note: Direct inclusion of `SUID_SUDO` will import many internal private symbols.)

In Perl:

    use SUID_SUDO;

will load the module into the `SUID_SUDO` package.

    use SUID_SUDO ":all";

will import API functions into the current package context.

## Setup Routine

### suid_emulate

Emulates the behavior of a setuid binary when invoked via `sudo(1)`.

This function should be called as early as possible in any script intended to be run via `sudo`.

It detects whether the script was invoked via `sudo` and sets the real UID and GID appropriately:

 * Real user ID and real group ID are set to those of the invoking user, obtained from environment variables set by `sudo`.
 * Effective user ID and group ID are set to `root`.
 * The supplementary group list is initialized to the default settings of the invoking user. (`sudo` sets this to `root`, which is usually unintended. Unfortunately, resetting it to the state prior to `sudo` invocation is difficult.)

The function returns `true` when setuid emulation is active (either natively or via emulation), and `false` otherwise (if invoked directly as either root or an unprivileged user).

All arguments are optional:

 * `realroot_ok`: default `False`. Specifies whether the script can be invoked as the real `root` user (via `sudo` run by `root`).

 * `nonsudo_ok`: default `False`. Specifies whether the script can be invoked by the `root` user without `sudo`. When enabled, misconfiguration might open security vulnerabilities to ordinary users; *be extremely careful* and *do not use unless strictly necessary*. Root users can still run scripts using this module via the `realroot_ok` option and explicit `sudo` invocation.

 * `sudo_wrap`: default `False`. If set to `True`, the script will attempt to re-invoke itself via `sudo(1)` when root privileges are not available. `sudo` must be configured properly so that targeted ordinary users can invoke the script (by its full path along with the interpreter command).

   A special command-line argument is used to coordinate between the invoking and self-invoked scripts; therefore, this function MUST be called before any command-line parsing (e.g., `argparse` in Python).

 * `use_shebang`: default `False`; only meaningful when `sudo_wrap=True`.
   If set to `True`, the module will directly invoke the script as an executable, relying on the `#!` feature of the underlying operating system.

   Enabling this flag requires adjustments to the `sudo` configuration.

 * `python_flags`: (Python only) default `"I"`; only meaningful when `sudo_wrap=True` and `use_shebang=False`. A string containing single-character flags passed to the Python interpreter when `sudo_wrap=True`.

   In Python 2.7, the `"I"` flag is translated to the combination `-E -s`.

 * `ruby_flags`: (Ruby only) default `"T"`; only meaningful when `sudo_wrap=True` and `use_shebang=False`. A string containing single-character flags passed to the Ruby interpreter when `sudo_wrap=True`.
   
   In Ruby 3.0 and later, the `"T"` flag is translated to `-disable=rubyopt`. In Ruby 2.7, if deprecation warnings for `-T` are undesirable, set this to `""` with extra caution given to code safety.

 * `perl_flags`: (Perl only) default `"T"`; only meaningful when `sudo_wrap=True` and `use_shebang=False`. A string containing single-character flags passed to the Perl interpreter when `sudo_wrap=True`.

 * `inherit_flags`: default `False`; only meaningful when `sudo_wrap=True` and `use_shebang=False`. If set to `True`, it passes select flags originally supplied to the interpreter. It is always safer to specify flags explicitly using the `*_flags` options.

 * `env_pass`:
 
   default `[]`; a list of environment variable names passed to the wrapped command. Effective only with `sudo_wrap=True`. By default, passed environment variables are visible only when user privileges are explicitly set via `temporarily_as_user` or `drop_privileges_forever`.
   
   Technically, these values are encoded into special environment variables, exploiting the fact that `sudo` preserves environment variables starting with `LC_`.

   *Caution*: Passing certain system environment variables, such as `IFS`, `LD_PRELOAD`, or `LD_LIBRARY_PATH`, can introduce severe security vulnerabilities. This option bypasses security measures provided by `sudo` if configured to do so. Use this feature only when strictly required.

   Note: When using this option, you must use the privilege-switching functions provided by this module; otherwise, the environment will not be updated properly (unless `env_pass_to_root` is also specified).

 * `env_pass_to_root`: default `False`. Setting this to `True` applies `env_pass` variables to the `root` privilege state as well. The above *Caution* strongly applies.

 * `sudo_allow_cached_cred`: default `False`; only meaningful when `sudo_wrap=True`.
   If set to `True`, it allows `sudo` to reuse cached credentials for the invoking user, skipping password prompts.
 
   This module is designed for use with explicit `sudoers` configurations. However, if the invoking user (typically an administrator) is permitted to run any command via `sudo`, this module will function without explicit script-specific entries.

   The default value of `False` protects users with global `sudo` privileges from accidentally running the script with setuid emulation.

   Setting this value to `-1` enforces an even stricter restriction: `sudo` invocation will fail if no explicit configuration exists.

   Note: This protection serves as a safeguard against user error, not a cryptographic security boundary. Executing untrusted commands with global `sudo` access remains inherently risky.

 * `showcmd_opts`:

   default `None`. If a string is provided, this function compares it with the first command-line argument. If it matches, the module prints the command line required for re-invocation and exits. Passing `True` (`1` in Perl) is equivalent to passing `"--show-sudo-command-line"`.

## Privilege-Switching Functions

There are four functions to handle privilege switching.
These functions configure user and group IDs accordingly and update user-related environment variables (e.g., `HOME`).

An optional parameter, `setenv=False`, skips updating environment variables (unavailable in Perl).

See the "Exceptions" section for details on error handling within these functions.

Each function can be used either as a standalone call or with a block/closure, depending on language syntax.
Called directly, it alters process UID/GID state globally.
Used with a block/closure, it automatically restores previous UID/GID state upon completion.

In Python, code blocks use `with` statements. The following two patterns behave identically after invoking `suid_emulate()`:

    temporarily_as_user()
    do_user_level_task()
    temporarily_as_root()

    with temporarily_as_user:
        do_user_level_task()

In Ruby, code blocks are passed as block arguments:

    temporarily_as_user
    do_user_level_task
    temporarily_as_root

    temporarily_as_user {
        do_user_level_task
    }

In Perl, code blocks are passed as code references:

    temporarily_as_user;
    do_user_level_task;
    temporarily_as_root;

    temporarily_as_user {
        do_user_level_task;
    };

In Ruby, you can also use standard `Process::UID` and `Process::GID` module functions. Do not mix built-in process methods with the functions in this module.

### temporarily_as_root

Sets effective user/group IDs to the privileged user (`root`), and real user/group IDs to the unprivileged user.
Supplementary groups are set to those of the unprivileged user.

### temporarily_as_real_root

Sets both real and effective user/group IDs to the privileged user (`root`).
Supplementary groups are reset to `[0]`.
Useful when invoking setuid-aware programs (e.g., `mount(8)`) as `root`.

### temporarily_as_user

Sets effective user/group IDs to the unprivileged user, and real user/group IDs to the privileged user (`root`).
Supplementary groups are set to those of the unprivileged user.

Do not use this function to execute untrusted code or programs directly, as untrusted code can regain `root` privileges via `seteuid(2)` or `temporarily_as_root()`.

### drop_privileges_forever

Sets both real and effective user/group IDs permanently to the ordinary user, dropping all root privileges for the remaining process lifecycle.

Use this before executing arbitrary commands under user control (e.g., shells, text editors, or script interpreters) or evaluating risky logic (e.g., `eval` or dynamic imports).

After calling this function, the process cannot revert to root privileges via `temporarily_as_root()` or related functions. Using this function as a context manager (Python) or with a block (Ruby/Perl) is ineffective. If temporary privilege reduction is required for untrusted operations, use `fork()` or `{call/run}_in_subprocess()`.

## Calling External Programs

### In Python

To execute an external program with altered privileges in Python, pass one of the privilege-switching functions as the `preexec_fn` parameter to functions in the `subprocess` module:

    import subprocess
    subprocess.call(args=["vi", "/tmp/file"],
                    preexec_fn=drop_privileges_forever)

### In Ruby: spawn_in_privilege

In Ruby, the wrapper function `spawn_in_privilege` is provided.
It accepts arguments similar to `exec` or `system`, with two leading arguments:

 * The first argument is either `:system` or `:spawn`.
   If `:system` is passed, the function waits for process termination and returns the exit status.
   If `:spawn` is passed, the function returns immediately after spawning the child process and returns its PID.

   In both cases, if the process cannot be executed, an `OSError` exception is raised synchronously.

 * The second argument is either:

   - A symbol corresponding to one of the four privilege-switching functions, defining the privileges applied to the child process; or

   - A `Method` or `Proc` object executed before invoking the child program (similar to `preexec_fn` in Python).

 * The remaining arguments are passed to the built-in `exec` call.

The Ruby equivalent of the Python example above is:

    spawn_in_privilege(:system, :drop_privileges_forever,
                       "vi", "/tmp/file")

### In Perl: spawn_in_privilege

The `spawn_in_privilege` function in Perl is structured similarly to Ruby, with the following differences:

 * The first argument is a string (`"system"` or `"spawn"`).
 * The second argument is either a function name string or a code reference.
 * Remaining arguments are passed to Perl's `exec`.

Its semantics mirror Perl's built-in `system()`, except:

  * If `exec` fails, it calls `die` instead of setting `$?` to `-1`.

  * Arguments are passed to Perl's built-in `exec`. Passing a single array reference explicitly bypasses shell invocation:

        spawn_in_privilege(..., ..., a) => exec(a)
        spawn_in_privilege(..., ..., a, b) => exec(a, b)
        spawn_in_privilege(..., ..., [a]) => exec a (a)
        spawn_in_privilege(..., ..., [a, b]) => exec a (a, b)
        spawn_in_privilege(..., ..., [[a, a0], b]) => exec a (a0, b)

When the first argument is `"spawn"` and process execution succeeds, the function returns the child PID.

Do not use custom signal handlers for child process reaping alongside `"system"`.

## Running Code in a Sub-process

Untrusted code should run under fully restricted privileges to prevent it from affecting privileged operations.

To accomplish this safely, the module provides helper functions that evaluate code blocks inside a isolated forked sub-process.

Return values are serialized and returned to the parent process over IPC. Values are restricted to safe types representable in JSON (or simple extensions); passing complex class instances with custom methods is prohibited for security reasons. Booleans, numbers, strings, lists, and key-value maps of these types are fully supported.

Exceptions are also propagated to the parent process in a restricted manner.
Standard built-in exceptions (e.g., system call errors) pass through transparently. Non-built-in exceptions are coerced into built-in parent exceptions or wrapped in a `WrappedSubprocessError`.

The target function MUST return a value or raise an exception in Python.
If you intend to execute an external process via `exec()`, use `subprocess` functions instead.

### call_in_subprocess (for Python)

In Python, `call_in_subprocess` accepts a single function object or closure.

To execute arbitrary logic under dropped privileges:

    # Recommended
    def _():
        drop_privileges_forever()
        return what_to_do(...)
    result = call_in_subprocess(_)

or:

    # Alternative syntax
    @call_in_subprocess
    def result():
        drop_privileges_forever()
        return what_to_do(...)

It uses a secure subset of `pickle` bytecodes for IPC response serialization.

### run_in_subprocess (for Ruby)

In Ruby, `run_in_subprocess` accepts a block argument:

    result = run_in_subprocess {
        drop_privileges_forever
        what_to_do(...)
    }

It uses `YAML.safe_load` for IPC response serialization.

### run_in_subprocess (for Perl)

In Perl, `run_in_subprocess` operates similarly to Ruby.
Exceptions are propagated as plain text strings.
It uses `JSON` (`JSON::PP`) for IPC response serialization.

## Utility Functions

Functions in this section are not exported by default and should be called via explicit module references.

### show_sudo_command_line

Prints the re-invocation `sudo` command line to standard error (usually the terminal).

Parameters `use_shebang`, `{python|ruby|perl}_flags`, `inherit_flags`, `pass_env`, and `sudo_allow_cached_cred` mirror those in `suid_emulate()`.

### compute_sudo_command_line_patterns

Returns a pair of strings representing command-line patterns for script re-invocation: the first element is a descriptive pattern string, and the second is formatted for direct inclusion in a `sudoers` file.

Parameters `use_shebang`, `{python|ruby|perl}_flags`, `inherit_flags`, `pass_env`, and `sudo_allow_cached_cred` mirror those in `suid_emulate()`.

The `user_str` parameter specifies the user/group string in the generated `sudoers` pattern.

## Defined Exceptions

The following exceptions are implemented for Python and Ruby:

### SUIDHandlingError

A general runtime error raised during operations in the `suid_sudo` module. Inherits from `RuntimeError` in Python and Ruby.

### SUIDSetupError

A runtime error raised during initial setup of this module.

### SUIDPrivilegesSettingError

A runtime error raised when attempting to elevate privileges fails.

### SUIDPrivilegesSettingFatalError

A *fatal* runtime error raised when dropping privileges fails.

Failing to drop privileges (or failing to drop privileges after executing a root block) is a critical security risk. While rare, unhandled privilege-drop failures can leave code executing with unintended elevated permissions.

To prevent unsafe execution, privilege-drop failures trigger process termination similar to `exit()`. These errors are not caught by standard `try: ... except RuntimeError:` blocks in Python or simple `begin ... rescue ...` blocks in Ruby. (Internally, `SUIDPrivilegesSettingFatalError` inherits from `BaseException` in Python and `SecurityError` in Ruby.)

`finally` clauses and bare `try: ... except:` blocks in Python will still execute on fatal exceptions, so exercise caution when defining cleanup blocks.

If handling this exception is required, structure exception handlers carefully to account for unknown or unexpected privilege states, and catch `SUIDPrivilegesSettingFatalError` explicitly by name.

### SUIDSubprocessError

A runtime error raised when `call_in_subprocess` or `run_in_subprocess` fails. The most common cause is code terminating without returning a value (e.g., calling `exec()`).

### WrappedSubprocessError

A runtime error raised when code invoked via `call_in_subprocess` or `run_in_subprocess` raises a non-built-in exception. Inherits from `SUIDSubprocessError`.

### Errors in Perl

In Perl, errors throw blessed objects from the `SUID_SUDO::` package hierarchy via `die`. Refer to the `perlfunc` documentation for details on object-oriented exception handling. `SUIDPrivilegesSettingFatalError` is omitted in Perl due to Perl's simpler exception model.

## References

 * suid_sudo: https://github.com/yoiwa-personal/suid_sudo/

## Author and License

Yutaka OIWA <yutaka@oiwa.jp>.

This document is part of the `suid_sudo` module, distributed under the Apache License 2.0.
