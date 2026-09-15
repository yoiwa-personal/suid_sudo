[-]: # " -*- mode: gfm; coding: utf-8 -*- "

# SUID_SUDO: Emulate behavior of set-uid binaries when invoked via sudo(1)

https://github.com/yoiwa-personal/suid_sudo/

## Overview

This module enables Python, Ruby, and Perl scripts to perform most of their
work with the invoking user's non-root privileges, while leveraging
root privileges for specific tasks.

In Unix-like systems, this kind of operation is possible via the
"setuid" feature for binary executables; however, many operating systems
ignore "setuid" for interpreted scripts (e.g., Python, Ruby, or Perl)
for well-known security reasons.
This module emulates the "setuid" feature in cooperation with
the `sudo` tool installed on many systems.

Programmers using this module should be familiar with Unix-like semantics
and techniques surrounding the "setuid" feature.

The main function in this module is `suid_emulate`.

Functions and features available:

 - Initialization
 - Privilege control
 - Helpers for executing unprivileged code/sub-processes

Requirements:
 - Python 3.5.13 or later
 - Ruby 2.3 or later
 - Perl 5.24.1 or later

## History

Unix-like environments have long featured "setuid" execution,
allowing ordinary users to launch commands that run with higher privileges.
Such higher-privileged commands know the ID of the invoking user provided by
the operating system and can perform user-dependent operations.
For example, the `passwd` command invoked by an ordinary user can only change
that user's password; `mount` and `sudo` restrict their capabilities based
on the invoking user and system configuration. However, in some operating systems,
such capabilities are only granted to compiled binaries and not to scripts,
due to technical and security-related reasons.

Once upon a time, a utility helper called `suidperl` existed to emulate the
behavior of "setuid scripts" for Perl, overcoming this technical limitation.
However, many vulnerabilities were found surrounding that tool (some related to
the helper itself, but most caused by complex interactions with the underlying
operating system - such as detecting the `nosuid` mount option on filesystems).
As a result, it was deprecated in Perl 5.6.1 and completely removed in Perl 5.12.

The Perl 5.6.1 manual stated:

    Use of suidperl is highly discouraged. If you
    think you need it, try alternatives such as sudo first.

However, the manual did not explain *how* to do so. While `sudo` is useful
for assigning `root` privileges to scripts and tools, it is not well-suited for
writing tools that vary their actions based on the invoking user's identity.

This module was implemented to address that gap.

## SECURITY WARNING

Inappropriate use of this module can create a major security vulnerability
(potentially leading to privilege escalation) for ordinary users. In the past,
when the obsolete `suidperl` feature handled setuid Perl execution, the specialized
interpreter took care of various security pitfalls (e.g., restricting the use of `$ENV{PATH}`).
By contrast, this module relies on `sudo` as a generic wrapper for most security checks.
In other words, this module only *drops* privileges granted by `sudo`; it does not *raise* any.
Nevertheless, several potential pitfalls remain that could grant root privileges to ordinary users.

In general, the script must be secure enough to be safely run as root via `sudo`.
This means:

  - The script and its parent/ancestor directories should be owned by `root`
    and not writable by ordinary users.

  - The script should be explicitly specified in the `sudoers(5)` file
    using its full path.

  - The script must carefully handle environment variables and other environmental
    properties that could affect the language interpreter, the script itself,
    or any subcommands it invokes.

For **Python**, we strongly recommend that:

  - The script includes the `-I` (`-Es` in Python 2.7) flag in its shebang line.

  - When the `sudo_wrap` option is enabled, keep `python_flags="IR"` intact.

  - When transmitting data between processes with different privilege levels,
    the privileged process must use secure data decoders (e.g., `SafeUnpickler`
    provided in this module, or `JSON`).

For **Ruby**, we strongly recommend that:

  - In Ruby versions prior to 2.7, the script includes the `-T` flag in the shebang
    line to ignore environment variables. (Note: `-T` was removed in Ruby 3.0.)
    This requires writing the script in a taint-aware manner.

  - When the `sudo_wrap` option is enabled, keep `ruby_flags='T'` intact.

  - When transmitting data between processes with different privilege levels,
    the privileged process must use secure data decoders (e.g., `YAML.safe_load`).

For **Perl**, we strongly recommend that:

  - The script includes the `-T` (or at least `-t`) flag in the shebang line
    to ignore environment variables. This requires writing the script in a taint-aware manner.

  - When the `sudo_wrap` option is enabled, keep `perl_flags='T'` intact.

  - When transmitting data between processes with different privilege levels,
    the privileged process must use secure data decoders (e.g., `JSON`).

When invoking subcommands from the script, we strongly recommend that:

  - The `secure_path` option in `sudo` is enabled.

  - Sudo's global `env_reset` and per-command `NOSETENV` options are enabled,
    and the use of `env_keep` in `sudoers` is avoided as much as possible.
    If `env_keep` is strictly required, the `-I` (or `-T`) option described above
    must remain enabled at all times, and the script should construct a clean
    environment internally after reading necessary variables.

## THREADING (NOT SUPPORTED)

Avoid using threads with this module.

At least four conflict scenarios exist regarding threading in this module:

 - Changing user IDs (or effective UID/GID) at the OS level is inherently not thread-safe.
   Changing process privileges affects all running threads in the process.

 - The implementation of this module is not thread-safe. Executing functions
   from this module concurrently will corrupt internal state management.
   All API calls must be serialized.

 - All functions in this module that restore context after execution assume that
   entry and exit of contexts are strictly nested in serialized order across all threads.

 - The `call_in_subprocess` and `run_in_subprocess` functions use `fork`,
   which may cause deadlocks in the interpreter or internal libraries when used with threads.

## Programmer's Usage

See [API documentation](doc/APIs.md) and
[packaging/install instructions](doc/INSTALL.md) for more details.

### Initialization

Call `suid_emulate` at the very beginning of the script. It checks whether the process
has root privileges. If the `sudo_wrap` option is set to true, the function will
re-invoke the script via `sudo` if root privileges are not present.

When root privileges are available, it determines which user invoked the script via `sudo`
and emulates the environment of a "setuid program": it sets the real user ID
to the invoking user while preserving the effective user ID as root.

After initialization, the script can switch between the real and root user IDs as needed.
This module provides the following functions for this purpose:

### Switching Between Users

The following four functions configure the effective and real user IDs (as well as group IDs) accordingly:

- `temporarily_as_user`: Sets the effective user ID to the ordinary user while keeping root privileges attached to the real user ID.

- `temporarily_as_root`: Sets the effective user ID to root and the real user ID to the ordinary user (undoes `temporarily_as_user`).

- `temporarily_as_real_root`: Sets both the effective and real user IDs to root. Useful when calling external programs that are setuid-aware (e.g., `mount(8)`).

- `drop_privileges_forever`: Sets both the effective and real user IDs to the ordinary user permanently. Once called, privileges cannot be restored. Required before executing untrusted programs, such as text editors.

These functions automatically update and restore user-related environment variables (such as `HOME` and `LOGNAME`).

They can be used either as ordinary functions or as context managers (Python) / iterators (Ruby/Perl):

    # Python
    with temporarily_as_user:
        do_user_level_task()

    # Ruby/Perl
    temporarily_as_user {
        do_user_level_task
    }

### Calling Sub-programs with Specific Privileges

In Python, to execute external programs with specific privileges, pass one of the above
functions to the `preexec_fn` argument of functions in the `subprocess` module:

    # Python
    import subprocess
    subprocess.call(args=["vi", "/tmp/file"],
                    preexec_fn=drop_privileges_forever)

In Ruby and Perl, this module provides wrapper functions for `spawn`/`system` with privilege settings:

    # Ruby
    spawn_in_privilege(:system, :drop_privileges_forever,
                       "vi", "/tmp/file")

The first argument is either `:system` or `:spawn`, and the second argument is a symbol
corresponding to one of the four privilege functions.

### Running Code in a Sub-process

To perform untrusted work under restricted privileges while needing to return to root
privileges afterward, run that code in a sub-process. If `temporarily_as_user` is used
directly in the main process, untrusted code could potentially regain root privileges
by calling `temporarily_as_root` or `seteuid`.

The `call_in_subprocess` and `run_in_subprocess` functions are provided for this purpose.
Both functions spawn a sub-process, execute the provided code within it, and send the return value
back to the parent process.

In Python, `call_in_subprocess` is used as follows:

    def job_to_do():
        drop_privileges_forever()
        # ... untrusted code ...
        return result

    retvalue = call_in_subprocess(job_to_do)

In Ruby/Perl, `run_in_subprocess` is used as follows:

    retvalue = run_in_subprocess {
        drop_privileges_forever
        # ... untrusted code ...
        # (return value)
    }

For security, values returned from the sub-process are limited to those serializable in JSON
(or slightly extended types). Exceptions are also propagated to the caller with value restrictions:
built-in exceptions are preserved, while custom exceptions are mapped to `WrappedSubprocessError`
or generic parent exception classes.

## User-Side Usage

Users should invoke scripts via `sudo`. If the program enables the `sudo_wrap` option,
direct invocation is also supported. In either case, `sudo` must be configured properly to allow user execution.

For security reasons, the script will refuse to run directly from the `root` user by default.
If the program enables the `realroot_ok` option, root invocation can be allowed when explicitly called via `sudo`
(e.g., an ordinary user calling `sudo sudo scriptname`).

### SUDO Configuration

If the `sudo_wrap` option is enabled, the script re-executes itself with a specific command-line structure.
Accordingly, `sudo` must be configured in `sudoers` to match that pattern:

 - If `use_shebang` is enabled, add an entry like:

        user ALL = (root:root) NOPASSWD: /full/path/to/script

 - If `use_shebang` is disabled, add an entry like:

        user ALL = (root:root) NOPASSWD: /usr/bin/python3 -I -R /full/path/to/script *

   Replace the interpreter path according to your system installation. The `user` field
   can be replaced with a group (e.g., `%group`) or `ALL`. The `NOPASSWD:` tag can be omitted
   if password prompts are desired.

   Interpreter flags specified in `sudoers` must match those set in `python_opts` (or equivalent options)
   within the script.

   If `inherit_flags` is enabled, the list of options will vary based on conditions. If `show_sudo_command_line`
   is enabled, running the script with `--show-sudo-command-line` will print the exact `sudoers` line required.

To explicitly limit unintentional direct execution via `sudo`, you can specify entries such as:

     user ALL = (root:root) NOPASSWD: /usr/bin/python3 -I -R /full/path/to/script ----sudo_wrap\=*

     user ALL = (root:root) NOPASSWD: /full/path/to/script ----sudo_wrap\=*

Note, however, that determined users can circumvent command-line pattern restrictions.

## PORTING

This module currently relies on the Linux `/proc` filesystem implementation to determine whether
a script was invoked directly by `sudo`. Porting to other POSIX.1-compliant Unix-like systems
is straightforward.

The Linux-dependent logic is isolated within the `called_via_sudo` function.

## Copyright and License

Copyright 2019 Yutaka OIWA <yutaka@oiwa.jp>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
