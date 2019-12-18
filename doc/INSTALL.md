[-]: # " -*- mode: gfm; coding: utf-8 -*- "

# Installation instruction for suid_sudo

## Package-based installation

Please notice that the packages should be installed into the
system-wide package installation.  This module will invoke the script
via sudo, which may change the library search paths.

If it is not possible, please consider per-program installation below.

### Python

Run `python3 setup.py bdist_egg` (or python2).
It will generate a egg file inside the `dist` directory.

### Ruby

Run `gem build suid_sudo.gemspec`.  It will generate a gem file at
the top directory.

### Python

Run `perl Makefile.PL` then `make dist`.  It will generate a tar.gz
package file at the top directory.

## Manual system-wide installation

The module files `suid_sudo.py`, `suid_sudo.rb`, `SUID_SUDO.pm` are
self-contained.
Put each of these files into the language's system library path.

The notice above on the system-wide installation about user's local
installation will apply, too.

## Per-program inclusion

### For multi-file programs

Each of these module files (shown above) may be copied into the
directory where your program package lives.  Library search paths of
underlying scripting language should be *carefully* modified before
loading this module, using an absolute path specification (or, at
least, an absolute path computed relatively from the main script's
location).  *NEVER add the current directory (".") to the library
path, which will lead to root exploits!*

 * In Python, the system will introduce the directory containing the
   invoked script into the load path.  This setting is sufficient for
   most cases. This module re-invokes the script via sudo with an
   absolute path, so such loading paths will also become absolute.

 * In Ruby,

        require File.absolute_path("./suid_sudo", File.dirname(__FILE__)).untaint

   is useful.

   The builtin `require_relative` does not work in taint mode,
   although it is what we actually need.

 * In Perl, see FindBin package's documentation.

   Use of the taint mode (perl -T) is strongly encouraged to avoid
   loading any module from the current directory; otherwise, either
   require Perl 5.26 or higher, or put

        BEGIN { pop @INC if $INC[-1] eq '.'; }

   before calling `use` for any modules.

You can also consider "zip-based" solutions described below.

### For single-file programs

If you're using Python, use of `zipapp` built-in module is highly
recommended for this purpose.

For Ruby and Perl, embedding the module to a main script is not 
advised (as it is too long), but if you really need to do so,
please clearly mark the copied part of this module.

Alternatively, you can try 
[ziprubyapp](https://github.com/yoiwa-personal/ziprubyapp) and
[zipperlapp](https://github.com/yoiwa-personal/zipperlapp),
which we have implemented as an equivalent of Python's zipapp for
Ruby and Perl.
