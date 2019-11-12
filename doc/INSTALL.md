[-]: # " -*- mode: gfm; coding: utf-8 -*- "

# Installation instruction of suid_sudo

## Package-based installation

Please notice that the packages should be installed into the
system-wide package installation.  This module will invoke the script
via sudo, which may change the library search paths.

If it is not, please consider the per-program installation below.

### Python

Run `python3 setup.py bdist_egg` (or python2).
It will generate a egg file inside the `dist` directory.

### Ruby

Run `gem build package.gemspec`.  It will generate a gem file at
the top diretory.

### Python

Run `perl Makefile.PL` then `make dist`.  It will generate a tar.gz
package file at the top directory.

## Manual system-wide installation

The module files `suid_sudo.py`, `suid_sudo.rb`, `SUID_SUDO.pm` are
self-contained.
Put each of these files into the language's system library path.

Note on the system-wide installation above will apply, too.

## Per-program inclusion

Each of these module files may be copied into the directory where your
program package lives.  Library search paths of underlying scripting
language should be *carefully* modified before loading this module,
using an absolute path specification (or, at least, an absolute path
computed relatively from the main script's location).  *NEVER add the
current directory to the library path, which will lead to root
exploits!*

Embedding the module to the main script is not adviced (as it is too
long), but if the script really needs to be a single file, please
clearly mark the copied part of this module.
