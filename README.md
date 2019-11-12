[-]: # " -*- mode: gfm; coding: utf-8 -*- "

# SUID_SUDO: Emulate behavior of set-uid binary when invoked via sudo(1).

https://github.com/yoiwa-personal/suid_sudo/

## Overview

This module enables Python/Ruby scripts to perform most of its
works in the invoking user's non-root privilege, while employing
root's power for a part of its job.

In Unix-like systems, this kind of operation is achievable via
"setuid" feature for the binary executables; however, there are
operating systems which ignores "setuid" for interpreted scripts
(e.g. Python, Ruby or Perl) for well-known security reasons.
This module emulates the "setuid" feature in cooperation with
the "sudo" tool installed in many systems.

Programmers using this module shall be aware of Unix-like semantics
and techniques around the "setuid" feature.

The main function in this module is the "suid_emulate" function.

Functions/Features available:

 - Initialization
 - Privilege control
 - Helpers for executing unprivileged codes/sub-processes

Python 2.7.13 or later, or 3.5.13 or later is required.
Ruby 2.3 or later is required.
Perl 5.24.1 or later is required.

## History

Unix-like environment has a feature of "setuid" execution from long
ago, allowing ordinary users to start a command which are to be run
with a higher privilege.  Such higher privileged commands knows the ID
of the invoking user told from the operating system, and be able to
perform a "user-dependent" operation.  For example, "passwd" command
invoked by an ordinary user can only change the password of that user;
"mount" and "sudo" are limiting the ability by itself based on the
invoking user and system configuration.  However, in some operating
systems, such an ability is only provided for a binary compiled
program and not for those written in scripting languages, due to a
technical, security-related reason.

Once upon a time, there was a utility helper called "suidperl" to
emulate behavior or the "setuid script" for the Perl language,
overcoming this technical limitation.  However, there found so many
vulnerabilities around that tool (some are the problem of the helper
itself, but most are caused by complexity of interactions with the
underlying operating system (e.g. detecting "nosudo" option of
filesystem mounts is not straight forward), and it was deprecated in
Perl 5.6.1 then removed completely in Perl 5.12.

The manual of the Perl 5.6.1 says:

    Use of suidperl is highly discouraged.  If you
    think you need it, try alternatives such as sudo first.

However, the manual did not tell "how" to do that.  In fact, the
"sudo" tool is useful for simply assigning the "root" privilege to
scripts and other tools, but not well-powered to write a tool which
changes actions based on the invoking user's difference.

This is why the module is implemented.

## SECURITY WARNING

Inappropriate use of this module will open up a huge security hole
(possibly privilege escalation) for ordinary users.  In the past,
obsolete "suidperl" feature of the Perl language, the special language
interpreter takes care of various possible security pitfalls
(e.g. limiting use of $ENV{PATH}).  This module, on the contrary,
simply relies on the "sudo" generic wrapper for the most of the
security checks.  In other words, this module only "drops" the
privilege given by sudo, not "raises" any.  However, still there are
several possible pitfalls which may grant root privileges to ordinary
users.

In general, the script must be safe enough to be run as root via sudo.
That means:

  - the script and its parent/ancestor directories should be owned by
    root and not modifiable by any ordinary users,

  - the script should be explicitly specified in sudoers(5) file
    with the full path specification, and

  - the script must be careful about any environment variables and any
    other environmental properties which will affect the language
    intepreter, the script, and any subcommands invoked from it.

Regarding the Python specifically, we strongly recommend that

  - The script will have `-I` (`-Es` in Python 2.7) flag in the
    she-bang line.

  - When sudo_wrap option is enabled, keep `python_flags="I"`
    intact.

  - When there are data communications between processes of different
    privileges, the high-privilege side must use "secure" data
    decoders, for example "SafeUnpickler" in this module or "JSON".

Regarding the Ruby, we strongly recommend that

  - The script will have `-T` flag in the shebang line to ignore
    environment variables.
    
    It means that the script must be written in taint-aware way.
    (Recent Ruby versions allows dropping the security level from the
    script, but it is not recommended for just avoiding taint-aware
    programming.)

  - When sudo_wrap option is enabled, keep `ruby_flags='T'` intact.

  - When there are data communications between processes of different
    privileges, the high-privilege side must use "secure" data
    decoders, for example "yaml.safe_load".

Regarding the Perl, we strongly recommend that

  - The script will have `-T` (or at least `-t`) flag in the shebang
    line to ignore environment variables.
    
    It means that the script must be written in an taint-aware way.

  - When sudo_wrap option is enabled, keep `perl_flags='T'` intact.

  - When there are data communications between processes of different
    privileges, the high-privilege side must use "secure" data
    decoders, for example "JSON".

Regarding calling sub-commands from the script, we strongly recommend
that

  - secure_path option of sudo is enabled,

  - sudo's global env_reset and per-command NOSETENV options are
    enabled, and use of env_keep in sudoers is avoided as far as
    possible; if it is really needed, `-I` (or `-T`) option described
    above is strictly enabled at all time, and the script should
    set-up sane environment by itself, after reading the required
    environment variables.

## THREADING (NOT):

Avoid use of threads as far as possible, with this module.

There are at least four possible conflict cases regarding threading
with this module.

 - OS's changing user-id (or effective uid/gid) feature is inherently
   not thread-safe.  Changing process privilege will affect all
   running threads.

 - Implementation of this module is also not thread-safe.  Running
   functions of this module concurrently will break consistency of the
   internal state management.  At least, all invocation of API
   functions must be serialized.

 - All functions that will revert the context after execution in this
   module assume that entry and exit of contexts are properly nested
   in the serialized running order, considering all threads.

 - The function call_in_subprocess() or run_in_subprocess() uses
   `fork`, which may cause dead-locking of the whole interpreter or
   internal libraries when used with threads.

## Programmer's Usage

See [API documentation](doc/APIs.md) and
[packaging/install instructions](doc/INSTALL.md) for more details.

### Initialization

In the very beginning of the script, call `suid_emulate`.  It will
check whether it has a root privilege.  If `sudo_wrap` option is set
to true, the function will re-invokes itself via `sudo` when the
privilege is not available.

When the root privilege is available, It will find out which user has
invoked the script via `sudo`, and imitates the condition when the
script were called as a "setuid program"; That is, it will set the
real user-id to the invoking user, while keeping the effective user-id
as root.

After that, the script can switching between real and root user-ids as
it wants.  In Ruby, you can use the utility functions in the "Process"
module to do that.  This module also provides the following
convenience functionalities.

### Switching between users:

The following four functions will set-up effective and real user-ids
(as well as group ids) as appropriately:

- temporarily_as_user: set effective user-id to the ordinary user, and
  keep root privilege to the real user-id.

- temporarily_as_root: set effective user-id to the root, and set real
  user-id to the ordinary user; effectively undoes other settings.

- temporarily_as_real_root: set both effective user-id and real user-id
  to the root.  Useful when the script calls external programs which are
  "setuid-aware" (e.g. mount(8)).

- drop_privileges_forever: set both effective user-id and real user-id
  to the ordinary user;  there will be no way to revert to the set-uid
  status.  Required to call any untrusted programs such as editors.

It can be used either as an ordinary function or as a context manager
(Python) / iterator (Ruby/Perl). For example, either

    temporarily_as_user()
    do_user_level_task...
    temporarily_as_root()

or

    # Python
    with temporarily_as_user:
        do_user_level_task...

    # Ruby/Perl
    temporarily_as_user {
        do_user_level_task...
    }

is possible.

### Calling sub-program with privilege setting

In Python, to call external programs with a specific privilege,
pass one of the above functions to the `preexec_fn` argument of
library functions in the "subprocess" module.  For example,

    # Python
    import subprocess
    subprocess.call(args=["vi", "/tmp/file"],
                    preexec_fn=drop_privileges_forever)

In Ruby/Perl, this module provides a wrapper function to spawn/system
with privilege setting.

    # Ruby
    spawn_in_privilege(:system, :drop_privileges_forever,
                        "vi", "/tmp/file")

The first argument is a symbol either `:system` or `:spawn`,
and the second argument is a symbol corresponding to the above
four functions.

### Running some code in a sub-process

To perform a bit of untrusted works under restricted privilege and
still need to continue other work with the root privilege, you need to
run that code in sub-process.  Otherwise, `temporarily_as_user` is
used for that purpose, such an untrusted code can regain the root
privilege by calling `temporarily_as_root` or `seteuid`.

For that purpose, `call_in_subprocess` or `run_in_subprocess` function
is available.  Both functions create a sub-process, run the given code
in that sub-process, and send back a return value of that code to the
parent.

In Python, `call_in_subprocess` is useful in the following way:

    ... calling code ...
    
    def job_to_do():
        drop_privileges_forever()
        ... untrusted code ...
        return (...)
    retvalue = call_in_subprocess(job_to_do)

In Ruby/Perl, `run_in_subprocess` is available as follows:

    retvalue = run_in_subprocess {
        drop_privileges_forever
        ... untrusted code ...
        (return value)
    }

For security keeping, values transported from the sub-process are
limited to those presentable in JSON or little more.  Exceptions are
also propagated to the caller, with value limitations: built-in
exceptions are supported, and others are mapped to
`WrappedSubprocessError` or some super-class exceptions.

## User-side usage

Users should invoke scripts via sudo.  If the program uses `sudo_wrap`
option, the script will also support direct invocation.  In either
case, `sudo` must be correctly configured to allow user invocation.

For safety purpose, the script will refuse to be called directly
from the root user by default.
If the program has enabled `realroot_ok` options, it can be
overcome by explicitly calling via sudo. (From the ordinary user,
call as `sudo sudo scriptname`.)

### SUDO configuration

If the `sudo_wrap` option is enabled, the script will execute itself
with a specific pattern of command line.  Accordingly, `sudo` must be
configured to match that invocation pattern.

 - If the `use_shebang` is not enabled, put something like the
   following entry:

        user ALL = (root:root) NOPASSWD: /usr/bin/python3 -I /full/path/to/script *

   The path to the interpreter should be replaced according to the
   system installation.  The part `user` may be replaced by group
   specification (like `%group`) or by `ALL`. The tag `NOPASSWD:`
   may be removed, if you wish to let sudo ask user's passwords.

   The options specified for the interpreter shall be the same as that
   specified in the `python_opts` or similar options inside the
   script.

 - If the `use_shebang` is enabled, put something like the
   following entry:

        user ALL = (root:root) NOPASSWD: /full/path/to/script

You can limit _unintentional_ invocation of script explicitly via sudo
by specifying something like:

     user ALL = (root:root) NOPASSWD: /usr/bin/python3 -I /full/path/to/script ----sudo_wrap\=*

     user ALL = (root:root) NOPASSWD: /full/path/to/script ----sudo_wrap\=*

but it can be easily circumvented by moderately clever users.

## PORTING

This module currently relies on the Linux implementation of the
`/proc` filesystem to find out whether the script is called directly
by "sudo".  Porting to other POSIX.1 compilient Unix-like systems
should be easy.

The Linux dependent code is inside the "called_via_sudo" function.

## Copyright

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
