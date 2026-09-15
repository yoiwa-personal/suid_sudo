[-]: # " -*- mode: gfm; coding: utf-8 -*- "

# Installation Instructions for suid_sudo

## Package-Based Installation

Please note that packages should be installed into the system-wide package directory. This module invokes scripts via `sudo`, which may alter library search paths.

If system-wide installation is not possible, consider the per-program installation methods described below.

### Python

Run `python3 setup.py bdist_egg` (or Python 2).
This will generate an `.egg` file inside the `dist` directory.

### Ruby

Run `gem build suid_sudo.gemspec`. This will generate a `.gem` file in the root directory.

### Perl

Run `perl Makefile.PL` followed by `make dist`. This will generate a `.tar.gz` package file in the root directory.

## Manual System-Wide Installation

The module files `suid_sudo.py`, `suid_sudo.rb`, and `SUID_SUDO.pm` are self-contained.
Copy the relevant file into your language's system library search path.

The note above regarding system-wide versus user-local installation also applies here.

## Per-Program Inclusion

### For Multi-File Programs

You can copy the relevant module file into the directory where your application package resides. The library search path of the underlying scripting language must be *carefully* modified before loading this module, using an absolute path specification (or an absolute path derived relative to the main script's location).

*NEVER add the current working directory (`"."`) to the library search path, as doing so introduces critical privilege escalation risks!*

 * **Python:** The runtime automatically adds the directory containing the executed script to `sys.path`. This default behavior is sufficient for most cases. Because this module re-invokes the script via `sudo` using an absolute path, the loaded path will also become absolute.

 * **Ruby:** Using the following snippet is recommended:

        require File.absolute_path("./suid_sudo", File.dirname(__FILE__)).untaint

   Note: The built-in `require_relative` function does not work in taint mode, although that is what we need.

 * **Perl:** Refer to the documentation for the `FindBin` package.

   Using taint mode (`perl -T`) is strongly encouraged to prevent loading modules from the current working directory. Otherwise, require Perl 5.26 or higher, or add:

        BEGIN { pop @INC if $INC[-1] eq '.'; }

   before calling `use` for any modules.

You may also consider the zip-based application solutions described below.

### For Single-File Programs

For Python, using the built-in `zipapp` module is highly recommended.

For Ruby and Perl, embedding the module directly into a main script is not recommended due to file length. However, if necessary, clearly comment and delineate the embedded module code.

Alternatively, consider using:
[ziprubyapp](https://github.com/yoiwa-personal/ziprubyapp) or
[zipperlapp](https://github.com/yoiwa-personal/zipperlapp),
which provide `zipapp`-equivalent functionality for Ruby and Perl.
