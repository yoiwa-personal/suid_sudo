# -*- perl -*-
# Perl library to simulate suid-script by sudo
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

=pod

=head1 NAME

SUID_SUDO: Emulate behavior of set-uid binary when invoked via sudo(1).

=head1 DESCRIPTION

This module enables Perl scripts to perform most of its works in the
invoking user's non-root privilege, while employing root's power
for a part of its job.

Programmers using this module shall be aware of Uni* semantics
and techniques around the "setuid" feature.

The main function in this module is the "suid_emulate" function.

Functions/Features available:

=over

=item *

Initialize: suid_emulate

=item *

Privilege Control: temporarily_as_root, temporarily_as_user,

=item *

temporarily_as_real_root, drop_privileges_forever

=item *

Execution Helper: call_in_subprocess

=back

Currently Linux 4.0+ is required.

=head1 SECURITY WARNING

Inappropriate use of this module will open up a huge security hole
to ordinary users.  In the past obsolete "suidperl" feature of the
Perl language, the special language interpreter takes care of
various possible security pitfalls (e.g. limiting use of
$ENV{PATH}).  This module simply, on the contrary, simply relies
on the "sudo" generic wrapper for the most of the security
features.  In other words, this module only "drops" the privilege
given by sudo, not "acquires" any.  However, still there are
several possible pitfalls which may grant root privileges to
ordinary users.

In general, the script must be safe enough to be run via sudo.
That means:

=over

=item *

the script should be owned by root and not modifiable by any
ordinary users,

=item *

the script should be explicitly specified in sudoers(5) file
with the full pathspec, and

=item *

the script must be careful about any environment variables and
any other environmental properties which will affect Perl,
the script, and any subcommands invoked from it.

=back

Please read F<README.md> for security details.

=head1 FUNCTIONS

=cut

use v5.24;
package SUID_SUDO;

### Exceptions

# Runtime error happens during processing by suid_sudo
package SUID_SUDO::SUIDHandlingError;
{
    use overload ( '""' => \&to_str );

    sub new( $$ ) {
	my ($class, $str) = @_;
	my ($package, $filename, $line) = ("", "<unknown>", "<unknown>");
	my $add = "";
	for (my $n = 0; 1; $n++) {
	    my ($p, $f, $l, $s) = caller($n);
	    last unless defined $p;
	    next if $p =~ /^SUID_SUDO::/s;
	    if ($p eq 'SUID_SUDO') {
		next if $add;
		next if ($f != '_set_ids' && $f =~ /^_/s);
		$add = " (@ $f:$l)";
		next;
	    }
	    ($package, $filename, $line) = ($p, $f, $l);
	    last;
	}
	bless ["$str$add at $filename line $line.\n"], $class;
    }

    sub to_str ( $ ) {
	return $_[0]->[0];
    }
}

# Runtime error happens during initial setup by suid_sudo
package SUID_SUDO::SUIDSetupError;
{
    our @ISA = ('SUID_SUDO::SUIDHandlingError');

    sub new( $$ ) {
	my ($class, $str) = @_;
	bless SUID_SUDO::SUIDHandlingError->new("Error during SUID_SUDO setup: $str"),
	  $class;
    }

    sub SUID_SUDO::SUIDSetupError( $ ) {
	SUID_SUDO::SUIDSetupError->new(@_);
    }
}

# Runtime error during changing privileges
package SUID_SUDO::SUIDPrivilegesSettingError;
{
    our @ISA = ('SUID_SUDO::SUIDHandlingError');

    sub new( $$ ) {
	my ($class, $str) = @_;
	bless SUID_SUDO::SUIDHandlingError->new("Error during privilege switching: $str"),
	  $class;
    }

    sub SUID_SUDO::SUIDPrivilegesSettingError( $ ) {
	SUID_SUDO::SUIDPrivilegesSettingError->new(@_);
    }
}

# Runtime error happens during handling of subprocesses
package SUID_SUDO::SUIDSubprocessError;
{
    our @ISA = ('SUID_SUDO::SUIDHandlingError');

    sub new( $$ ) {
	my ($class, $str) = @_;
	bless SUID_SUDO::SUIDHandlingError->new("Error during subprocess processing: $str"),
	  $class;
    }

    sub SUID_SUDO::SUIDSubprocessError( $ ) {
	SUID_SUDO::SUIDSubprocessError->new(@_);
    }
}

package SUID_SUDO;

use Exporter 'import';
our @EXPORT_OK = qw(suid_emulate
		    temporarily_as_user temporarily_as_root
		    temporarily_as_real_root drop_privileges_forever
                    run_in_subprocess spawn_in_privilege);
our %EXPORT_TAGS = (all => [@EXPORT_OK]);

use English;
use strict;
use POSIX;
use File::stat;
use User::grent;
use User::pwent;
use Config;
use Data::Dumper;
use File::Spec;
use IO::Pipe;
use Carp;
use MIME::Base64 ();

### module constants

# List of allowed sudo commands in full-path.
our @ALLOWED_SUDO_ = ("/bin/sudo", "/usr/bin/sudo");
our %ALLOWED_SUDO_ = ();
for my $sudo (@ALLOWED_SUDO_) { $ALLOWED_SUDO_{$sudo} = 1; }

### utility functions

sub _merge_options ( $@ ) {
    my ($default, %args) = @_;

    my %ret = ();

    for my $k (keys %$default) {
	$ret{$k} = $default->{$k};
    }

    for my $k (keys %args) {
	croak "unknown option $k passed" unless exists $ret{$k};
	$ret{$k} = $args{$k};
    }
    return %ret;
}

sub getgrouplist( $$ ) {
    # for missing initgroups
    my ($user, $group) = @_;
    my $ret = "";
    setgrent();
    while(my $ent = User::grent::getgrent()) {
	my @users = @{$ent->members};
	for my $n (@users) {
	    if ($n eq $user) {
		$ret .= $ent->gid . " ";
		last;
	    }
	}
    }
    endgrent();
    $ret .= ($group + 0);
    return $ret;
}

sub _untaint( $ ) {
    $_[0] =~ /^(.*)$/s or die;
    return $1;
}

### Internal-use data

# A singleton hash data representing the current process's status.
our $_status = undef;

# Set up an singleton instance representing process status.
# Called automatically from suid_emulate.
sub _make_status_now ($$%) {
    my ($is_suid, $suid_via_sudo, @options) = @_;
    die SUIDSetupError("_make_status_now called twice") if $_status;
    my %options = _merge_options {
	uids => undef, gids => undef,
	  groups => undef, pwent => undef }, @options;

    $_status = {is_suid => $is_suid, via_sudo => $suid_via_sudo};

    if ($options{uids}) {
	($_status->{uid}, $_status->{euid}) = @{$options{uids}};
    } else {
	$_status->{uid} = $REAL_USER_ID;
	$_status->{euid} = $EFFECTIVE_USER_ID;
    }
    if ($options{gids}) {
	($_status->{gid}, $_status->{egid}) = @{$options{gids}};
    } else {
	$_status->{gid} = $REAL_GROUP_ID + 0;
	$_status->{egid} = $EFFECTIVE_GROUP_ID + 0;
    }
    if ($options{groups}) {
	$_status->{groups} = $options{groups}
    } else {
	$_status->{groups} = (split(" ", $REAL_GROUP_ID, 2))[1];;
    }
    my $user_pwent;
    if ($options{user_pwent}) {
	$user_pwent = $options{user_pwent}
    } else {
        $user_pwent = User::pwent::getpwuid($_status->{uid});
    }
    die unless ($user_pwent->uid == $_status->{uid});
    $_status->{user_pwent} = $user_pwent;
    my $root_pwent = User::pwent::getpwuid($_status->{euid});
    die unless ($root_pwent->uid == $_status->{euid});
    $_status->{root_pwent} = $root_pwent;
    #print Dumper($_status);
    return $_status;
}

# A singleton hash data representing surrounding conditions for the current process.

our $_surrounds = undef;
our $_procexe_linkname = undef;

sub _check_surround () {
    return $_surrounds if $_surrounds;
    return $_surrounds = _create_surround_init();
}

sub _procexe_linkname ($) {
    unless ($_procexe_linkname) {
	for my $l ("exe", "file") {
	    my $f = "/proc/$PID/$l"; # use pid of myself
	    if (-e $f) {
		readlink $f or die "/proc system is something bad: $!";
		$_procexe_linkname = $l;
		last;
	    }
	}
        die "cannot read /proc to check sudo" unless $_procexe_linkname;
    }

    my $p = $_[0] + 0;
    return ("/proc/$p/$_procexe_linkname");
}

sub _create_surround_init () {
    # Acquire a "consistent" information on the parent process.
    #
    # A struct containing the following member is returned:
    #    status: a symbol representing the result combination
    #    ppid:   the process ID of the parrent process.
    #    p_path: the path of the executable.
    #    p_stat: the stat information of p_path.
    #
    # The following combinations will be availble.
    #
    # (1) If the parent is alive and accesible:
    #     {status: "success",
    #      ppid:   integer,
    #      p_path: string
    #      p_stat: a stat struct}
    #
    #     These three pieces of information are guaranteed to be
    #     consistent and referring to the same "process" object,
    #     at some instant moment during this function was running.
    #     It might be different from the things "now".
    #
    # (2) If the parent is alive but not accessible:
    #     (e.g. running as non-root, parent has different privilege)
    #     (status: "EPERM",
    #      ppid:   integer,
    #      p_path: either a string or an Error instance (EACCES or EPERM),
    #      p_stat: an Error instance (EACCES or EPERM))
    #
    #     These three pieces of information are guaranteed to be
    #     consistent at some instant moment during this function was
    #     running.
    #
    # (3) If the parent is died early:
    #
    #     {status: "ENOENT",
    #      ppid:   integer or 1,
    #      p_path: nil,
    #      p_stat: nil}
    #
    #     If the parent died before this function started examining,
    #     ppid will be 1.
    #     Otherwise, if the parent died during examining, ppid will be
    #     the first available value.
    #
    # Errors:
    #   Errno::EAGAIN:
    #      will be raised if the function fails to acquire a
    #      consistent information with several times of trials.
    #   RuntimeError:
    #      will be raised if things get something unexpected.
    #
    # Caveats: what happens if two executable ping-pongs altogether?
    # (OK for suid_sudo because it will never happen when one side is sudo)

      #b = lambda {|x| p x}
    my $b = sub {print @_, "\n" if 0};

    my $s = {};
    # self status is reliable and stable.
    my $pid = $s->{pid} = $PID;

    # all the following status values might change during execution.
    # ppid may change only once to 1 when the parent exits.
    my $ppid_0 = $s->{ppid} = getppid();

    # is_root = Process::euid == 0
    # is_suid = Process::euid != Process::uid

    # sanity check: existence of the proc file system
    my $stat_proc = stat("/proc");

    die "/proc system is something bad" unless \
      ($stat_proc and
       $stat_proc->uid == 0 and $stat_proc->gid == 0 and
       $stat_proc->dev & 0xff00 == 0 and # non-device-backed file system
       $stat_proc->mode == 040555);

    # exe link must be available and is a readable link
    readlink _procexe_linkname($pid) or
      die "/proc system is something bad: $!";

    # fragile information
    for my $xtimes (0 .. 9) {
        my ($ppid_1, $path_1, $stat_1, $stat_2, $path_2, $ppid_2);
        my ($status);

        &$b("==== ppid_1 ==== (${xtimes})");
        $ppid_1 = getppid();
        if ($ppid_1 == 1) {
	    # parent exited
	    $s->{status} = "ENOENT";
	    $s->{p_path} = undef;
	    $s->{p_stat} = undef;
	    return $s;
	}

	my $ppid1_linkname = _procexe_linkname($ppid_1);
	&$b("path_1");
	$path_1 = readlink($ppid1_linkname);
	unless (defined $path_1) {
	    if ($!{ENOENT}) {
		# parent exited now
		die unless getppid() == 1;
		next;
	    } elsif ($!{EPERM} || $!{EACCES}) {
		# cannot read: different owner?
		$ppid_2 = getppid();
		if ($ppid_2 == $ppid_1) {
		    # cannot read: different owner, still alive
		    die unless $ppid_0 == $ppid_1;
		    $s->{status} = "EACCES";
		    $s->{p_path} = undef;
		    $s->{p_stat} = undef;
		    $s->{error} = $!;
		    $_surrounds = $s;
		    return $s;
		} elsif ($ppid_2 == 1) {
		    # cannot read: because parent exited (and I am non-root)
		    next;
		} else {
		    die "can't happen (@ readlink_EPERM)"
		}
	    } else {
		die "readlink: $!";
	    }
	}

	&$b("stat_1");
	$stat_1 = stat($ppid1_linkname);
	unless (defined $stat_1) {
	    if ($!{ENOENT}) {
		# parent exited now
		die unless getppid() == 1;
		next;
	    } elsif ($!{EPERM} || $!{EACCES}) {
		# cannot stat: different owner?
		$ppid_2 = getppid();
		if ($ppid_2 == $ppid_1) {
		    # cannot stat: different owner, still alive
		    die unless $ppid_0 == $ppid_1;
		    $stat_1 = undef;
		    $s->{status} = "EACCES";
		    $s->{error} = $!;
		    $_surrounds = $s;
		    # go through to "path_2" below to check path consistency
		} elsif ($ppid_2 == 1) {
		    # cannot stat: because parent exited (and I am non-root)
		    next;
		} else {
		    die "can't happen (@ stat_EPERM)"
		}
	    } else {
		die "readlink: $!";
	    }
	}

	&$b("path_2");
	$path_2 = readlink($ppid1_linkname);
	unless (defined $path_2) {
	    if ($!{ENOENT} || $!{EPERM} || $!{EACCES}) {
		next;
	    } else {
		"readlink (2): $!";
	    }
        }
	next if $path_1 ne $path_2;

        &$b("ppid_2");
        $ppid_2 = getppid();
        next if $ppid_1 != $ppid_2;
	die unless $ppid_0 == $ppid_1;

        $s->{status} ||= "success";
        $s->{p_path} = $path_1;
        $s->{p_stat} = $stat_1;
        return $s;
    }
    die "cannot get stable surrounding status"
}

### Handling inter-process communication via sudo-wrapped invocation

sub _keystr_encode(@) {
    my $l = join("\0", @_);
    my $b = MIME::Base64::encode_base64url($l);
    return $b;
}

sub _keystr_decode($) {
    my ($s) = @_;
    my $v = MIME::Base64::decode_base64url($s);
    my @v = split(/\0/, $v, -1);
    return @v;
}

sub _encode_wrapper_info($) {
    my ($envp) = @_;
    return _keystr_encode($PID, $REAL_USER_ID, $REAL_GROUP_ID + 0, $envp);
}

sub _decode_wrapped_info($$$$) {
    my ($v, $uid, $gid, $pass_env) = @_;
    my @v = @$v;
    if (scalar @v != 4 or sprintf("%d", getppid()) ne $v[0] or "$uid" ne $v[1] or "$gid" ne $v[2]) {
	die SUIDSetupError("wrapped invocation key mismatch")
    }
    return _decode_passenv($v[3], $pass_env);
}

sub _setup_passenv($) {
    my ($pass_env) = @_;
    my $p;
    my $env_name;
    do {
	$p = int(rand(1000000000)) . "";
	$env_name = "LC__SUDOWRAP_$p";
    } while exists $ENV{$env_name};
    my @out = ();
    for my $k (@$pass_env) {
	($k =~ /=/) and die "names in pass_env should not contain =";
	if (exists $ENV{$k}) {
	    push @out, "$k=$ENV{$k}";
	} else {
	    push @out, "$k";
	}
    }
    $ENV{$env_name} = _keystr_encode(@out);
    return $p
}

sub _decode_passenv($$) {
    my ($envp, $pass_env) = @_;
    my @pass_env = @$pass_env;
    return undef if $envp eq "";
    my $env_name = "LC__SUDOWRAP_$envp";
    unless (exists $ENV{$env_name}) {
	carp "environment $env_name missing";
	return undef;
    }
    my @e_val = _keystr_decode($ENV{$env_name});
    delete $ENV{$env_name};
    if (scalar @e_val != scalar @pass_env) {
	die SUIDSetupError("bad pass_env values: length mismatch")
    }
    for my $i (0 .. $#pass_env) {
	my $k = $pass_env[$i];
	my $k2 = $e_val[$i];
	my $val = undef;
	if ($k2 =~ /^([^=]+)=(.*)$/s) {
	    ($k2, $val) = ($1, $2);
	}
	if ($k2 ne $k) {
	    die SUIDSetupError("bad pass_env values: key mismatch")
	}
	if (defined $val) {
	    $ENV{$k} = $val;
	} else {
	    delete $ENV{$k}
	}
    }
    return {}
}

### sudo-wrapped reinvocation

sub _detect_wrapped_reinvoked() {
    if (scalar @ARGV == 0) {
	return 0;
    }
    my $arg = $ARGV[0];
    if ($arg =~ /\A----sudo_wrap=(.+)\z/) {
	my @v = _keystr_decode($1);
	if (@v) {
	    shift @ARGV;
	    return \@v;
	} else {
	    die SUIDSetupError("bad format wrapped invocation key");
	}
    }
    return 0;
}

sub called_via_sudo() {
    my $ppid = getppid();
    my $has_root = ($EFFECTIVE_USER_ID == 0);

    my $s = _check_surround();
    #print Dumper($s);

    if ($s->{status} eq 'ENOENT') {
	if ($has_root) {
	    die SUIDSetupError("cannot check parent process: #{surround_info.status}");
	} else {
	    return undef;
	}
    } elsif ($s->{status} eq 'EPERM') {
	if ($has_root) {
	    die SUIDSetupError("cannot check parent process: #{surround_info.status}");
	} else {
	    return (defined $s->{p_path} && $ALLOWED_SUDO_{$s->{p_path}});
	}
    } elsif ($s->{status} eq 'success') {
	return 1 if $ALLOWED_SUDO_{$s->{p_path}};
	return undef unless $has_root;

	# We're running in root. We must be more careful.
	
	my $s1 = $s->{p_stat} or die;
	my $found = 0;

	for my $k (@ALLOWED_SUDO_) {
	    my $s2 = stat($k) or next;
	    $found = 1;
	    if ($s1->dev == $s2->dev and $s1->ino == $s2->ino) {
		die SUIDSetupError("Error: found a HARDLINK of system sudo $k at " . $s->{p_path});
		return 1;
	    }
	}
	die SUIDSetupError("no system sudo found?") unless $found;
	return 0;
    } else {
	die # notreached
    }
}

sub _process_perl_flags( $$ ) {
    my ($perl_flags, $inherit_flags) = @_;
    my @ret = ();
    my %done = ();
    sub p {
	my $p = $_[0];
	unless ($done{$p}) {
	    $done{$p} = 1;
	    push @ret, "-$p";
	}
    }
    for my $p (split("", $perl_flags)) { p($p) }
    if ($inherit_flags) {
	p('-T') if ${^TAINT} == 1;
	p('-t') if ${^TAINT} == -1;
    }
    return @ret;
}

sub _wrap_invoke_sudo ( % ) {
    my %options = _merge_options {
	use_shebang => 0,
	perl_flags => 'T', inherit_flags => 0,
	pass_env => []
    }, @_;

    my $scriptname = _untaint(File::Spec->rel2abs($PROGRAM_NAME));
    #my $execname = $EXECUTABLE_NAME;
    use Config;
    my $execname = $Config{perlpath};

    die SUIDSetupError("error: could not reinvoke script: could not found myself")
      unless -f $scriptname;
    die SUIDSetupError("error: could not reinvoke script: interpreter not found")
      unless -x $execname;

    my @execname;
    my @flags;

    if ($options{use_shebang}) {
	@execname = ();
	@flags = ()
    } else {
	@execname = ($execname);
        @flags = _process_perl_flags($options{perl_flags}, $options{inherit_flags})
    }

    my $envp;
    my $pass_env = $options{pass_env};
    if (! $pass_env or scalar @$pass_env == 0) {
	$envp = "";
    } else {
	$envp = _setup_passenv($pass_env);
    }

    my $cmd = $ALLOWED_SUDO_[0];
    for my $c (@ALLOWED_SUDO_) {
	if (-f $c) {
	    $cmd = $c;
	    last;
	}
    }
    my @args;
    @args = ("----sudo_wrap=" . _encode_wrapper_info($envp), map { _untaint $_ } @ARGV);
    @args = ($cmd, @execname, @flags, $scriptname, @args);
    exec(@args);
    die SUIDSetupError("could not invoke $cmd for wrapping: $!");
    exit(1)
}

### Detect and initialize sudo'ed and suid'ed environment

sub _pick_environment( $ ) {
    my ($name) = @_;
    if ($ENV{$name} =~ /\A(\d+)\z/) {
	my $id = $1 + 0;
	delete $ENV{$name};
	return $id if ("$id" eq $1);
    }
    die SUIDSetupError("malformed or missing environment $name");
}

=pod

=head2 suid_emulate( [option => value, ...] )

Emulate behavior of set-uid binary when invoked via sudo(1).

This function is to be invoked as early as possible in the script
intended to be invoked via sudo.

It detects whether the script was invoked via sudo, and who invoked
it, then it sets real uid and real gid appropriately.  Effective uid
and gid is kept as root.  It means that (a) Perl special variables $<,
$>, $(, $) can be used to switch privileges between the invoking user
and root, and (b) filetest operators with capital characters (-R, -W,
-X, -O) will return file accessibility of the invoking user (beware of
timing security hole, though).

The function returns true when setuid is effective: false otherwise
(invoked directly as either root or a non-root user).

All arguments are optional and specified as a hash parameter.  These
means as follows:

=over 4

=item realroot_ok:

default false. Specify whether the script can be invoked as real
root user (via sudo by root).

=item nonsudo_ok:

default false. Specify whether the script can be invoked by root
user without sudo.  When enabled, misconfiguration might open
security holes to ordinary users; be extremely careful.

=item sudo_wrap:

default false. If set to true, the script will try to invoke
itself via sudo(1), when root privilege is not available.  Sudo
must be configured appropriately so that required ordinary users
can invoke this script (by its full-path with python command).

A special command-line argument is used to communicate between
invoking/self-invoked scripts, thus the function MUST be called
before any command-line processing (e.g. argparse).

=item use_shebang:

default false; only meaningful when sudo_wrap is true.  If set to
True, the module will directly invoke the script itself as an
executable, expecting '#!' feature of the underlying operating system
to work.

Use of this flag requires changes to the sudo configuration.

=item ruby_flags:

default "T"; only meaningful when sudo_wrap is true and use_shebang is
false.  A string containing one-character flags to be passed to the
python interpreter called when sudo_wrap=True.

=item inherit_flags:

default false; only meaningful when sudo_wrap is true and use_shebang
is false.  If set to True, it will pass some of the flags originally
passed to the Perl interpreter.

=item pass_env:

default []; a reference to a list of names of environment variables
which is passed to the wrapped command.  Effective only when sudo_wrap
is true.  Its value is encoded to special environmental variable; it
cheats the fact that sudo passes all variables starts with "LC_".

B<*Caution*>: passing some system-defined variables such as IFS,
LD_PRELOAD, LD_LIBRARY_PATH will lead to creation of a security hole.
This option can bypass security measures provided by sudo, if the
script really tells this module to do so.  Use this feature only when
it is really needed.

=back

=cut

sub suid_emulate( % ) {
    my $uid = $REAL_USER_ID;
    my $euid = $EFFECTIVE_USER_ID;

    my %options = _merge_options {
	sudo_wrap => 0, use_shebang => 0,
	  perl_flags => 'T', inherit_flags => 0,
	  realroot_ok => 0, nonsudo_ok => 0,
	  pass_env => []
      }, @_;

    my $wrapped_invocation_info = _detect_wrapped_reinvoked();
    my $is_sudoed = called_via_sudo();

    unless ($is_sudoed || ! $wrapped_invocation_info) {
	die;
    }

    #if _status
    #  return _status.is_suid
    #end

    if ($uid != $euid) {
	_make_status_now(1, 0);
	return 1;
    }

    if ($euid != 0) {
	if ($options{sudo_wrap}) {
	    if ($wrapped_invocation_info) {
		die SUIDSetupError("error: detected wrapping loop");
	    }
	    _wrap_invoke_sudo(use_shebang => $options{use_shebang},
			      perl_flags => $options{perl_flags},
			      inherit_flags => $options{inherit_flags},
			      pass_env => $options{pass_env}
			     );
	}
	_make_status_now(0, 0);
	return 0
    }

    if (! $is_sudoed) {
	# really run by root?
	if (! $options{realroot_ok} || ! $options{nonsudo_ok}) {
	    die SUIDSetupError("This script must be invoked via sudo");
	}
	_make_status_now(0, 0);
	return 0
    }

    # sudoed.
    my $sudo_uid = _pick_environment("SUDO_UID");
    my $sudo_gid = _pick_environment("SUDO_GID");

    if ($wrapped_invocation_info) {
	$wrapped_invocation_info = _decode_wrapped_info($wrapped_invocation_info, $sudo_uid, $sudo_gid, $options{pass_env})
    }

    if (! $options{realroot_ok} && $sudo_uid == 0) {
	die SUIDSetupError("This script must be run by non-root");
    }

    my $sudo_username = $ENV{"SUDO_USER"};
    unless ($sudo_username) {
	die SUIDSetupError("error: sudo did not set username information");
    }
    delete $ENV{SUDO_COMMAND};
    delete $ENV{MAIL}; # not worth to simulate

    my $pwdent = User::pwent::getpwnam($sudo_username) or
      die SUIDSetupError("error: bad username information from sudo: no corresponding user");

    if ($pwdent->uid != $sudo_uid) {
	die SUIDSetupError("error: inconsistent user information from sudo: why?");
    }
    #Process::initgroups(sudo_username, sudo_gid);
    my $groups = getgrouplist($sudo_username, $sudo_gid);
    #print "$groups\n";
    ($GID, $EGID) = ($sudo_gid, "0 $groups");
    if ($! or $GID + 0 != $sudo_gid) {
	die SUIDSetupError("error: setresgid failed");
    }
    ($UID, $EUID) = ($sudo_uid, 0);
    if ($! or $UID != $sudo_uid) {
	die SUIDSetupError("error: setresuid failed");
    }

    _make_status_now(1, 1, pwent => $pwdent);
    return 1;
}

### Switch between privileges

sub _set_ids($$$) {
    my ($to_root, $completely, $proc) = @_;

    my $restorer =
      {
       u => [$UID, $EUID],
       g => [$GID, $EGID],
       env => {}
      };
    for my $e ("LOGNAME", "USER", "USERNAME", "HOME") {
	$restorer->{env}->{$e} = $ENV{$e};
    }

    my ($to_u, $from_u, $to_g, $from_g, $groups);
    $groups = $_status->{groups};
    my $pwent = $_status->{user_pwent};
    if ($to_root) {
	($to_u, $from_u) = $_status->{euid}, $_status->{uid};
 	($to_g, $from_g) = $_status->{egid}, $_status->{gid};
    } else {
	($to_u, $from_u) = $_status->{uid}, $_status->{euid};
 	($to_g, $from_g) = $_status->{gid}, $_status->{egid};
    }
    if ($completely) {
	$from_g = $to_g;
	$from_u = $to_u;
	$groups = "$to_g" if $to_root;
	$pwent = $_status->{root_pwent};
    }

    $! = 0;
    $EFFECTIVE_USER_ID = $_status->{euid}; # be root to change gids
    $! and die SUIDPrivilegesSettingError("_set_ids failed (0): $!");
    ($REAL_GROUP_ID, $EFFECTIVE_GROUP_ID) = ($from_g, "$to_g $groups");
    $! and die SUIDPrivilegesSettingError("_set_ids failed (1): $!");
    ($REAL_USER_ID, $EFFECTIVE_USER_ID) = ($from_u, $to_u);
    $! and die SUIDPrivilegesSettingError("_set_ids failed (2): $!");

    if ($from_u == $to_u and ! $to_root) {
	# In Perl on POSIX systems, above code calls
	# setresuid(2) with saved-id = -1,
	# keeping the root privilege in the saved UID.
	$REAL_GROUP_ID = $from_g;
	$! and die SUIDPrivilegesSettingError("_set_ids failed (3-1): $!");
	$REAL_USER_ID = $from_u;
	$! and die SUIDPrivilegesSettingError("_set_ids failed (3-2): $!");
    }

    $ENV{LOGNAME} = $pwent->name;
    $ENV{USER} = $pwent->name;
    $ENV{USERNAME} = $pwent->name;
    $ENV{HOME} = $pwent->dir;

    if ($proc) {
	my ($r, $e);
	eval {
	    $r = &$proc;
	};
	$e = $@;

	#print "restoring\n";
	#print Dumper($restorer);

	$EFFECTIVE_USER_ID = $_status->{euid}; # be root to change gids
	$! and die SUIDPrivilegesSettingError("resoring privilege failed (1): $!");
	($REAL_GROUP_ID, $EFFECTIVE_GROUP_ID) = @{$restorer->{g}};
	$! and die SUIDPrivilegesSettingError("resoring privilege failed (2): $!");
	($REAL_USER_ID, $EFFECTIVE_USER_ID) = @{$restorer->{u}};
	$! and die SUIDPrivilegesSettingError("resoring privilege failed (1): $!");
	for my $k (keys(%{$restorer->{env}})) {
	    my $v = $restorer->{env}->{$k};
	    if (defined($v)) {
		$ENV{$k} = $v;
	    } else {
		delete $ENV{$k};
	    }
	}

	die $e if $e;
	return $r
    }
}

=pod

=head2 temporarily_as_root [{ block }]

Set effective user/group ID to the privileged user.

It can be used either as an ordinary function, or with a code block (a
subroutine reference).  If a block is given, it will revert the
UID/GID setting after evaluating the block.

=cut

sub temporarily_as_root ( ;& ) {
    _set_ids(1, 0, $_[0])
}

=pod

=head2 temporarily_as_user [{ block }]

Set effective user/group ID to the ordinary user (the one invoking the
script).

It can be used either as an ordinary function, or with a code block (a
subroutine reference).  If a block is given, it will revert the
UID/GID setting after evaluating the block.

=cut

sub temporarily_as_user ( ;& ) {
    _set_ids(0, 0, $_[0])
}

=pod

=head2 temporarily_as_real_root [{ block }]

Set both real and effective user/group ID to the privileged user.
It is useful when invoking setuid-aware program (e.g. mount(8)) as
root.

It can be used either as an ordinary function, or with a code block (a
subroutine reference).  If a block is given, it will revert the
UID/GID setting after evaluating the block.

=cut

sub temporarily_as_real_root ( ;& ) {
    _set_ids(1, 1, $_[0])
}

=head2 temporarily_as_real_root [{ block }]

Set both real and effective user/group ID to an ordinary user,
dropping any privilege for all of the future.  After calling this, the
process can no longer call temporarily_as_root() or other similar
functions.

It can be used to execute a command for which the calling user can do
whatever (e.g. shell, editor or language interpreter), or to perform
possibly-dangerous operation (e.g. eval or import) in Perl code.

Passing a block to this function is meaningless, because it can not
revert privileged status anymore.  If such a functionality is really
needed, consider using fork() or run_in_subprocess() to separate the
unprivileged operations to a child process.

=cut

sub drop_privileges_forever ( ;& ) {
    _set_ids(0, 1, $_[0])
}

### Running (untrusted) code within subprocess

=pod

=head2 run_in_subprocess { block }

Evaluate the given block (subroutine reference) within a forked
subprocess.

Return value of the block is returned to caller, using a JSON
encoding. It means that values of only some simple builtin types can
be transferred back to the caller.

Exceptions caused within the block the child is also propargated to
the caller.

The block MUST return some value or raise an exception within Perl.
If you intend to exec() an external process, consider using
spawn_in_privilege() in this module.

=cut

sub run_in_subprocess( & ) {
    eval {
	require JSON;
    };
    if ($@) {
	eval {
	    package JSON;
	    use JSON::PP;
	};
	die if $@;
    }

    my ($proc) = @_;

    my ($pid, $ret, $rete, $json) = undef;

    my $pipe = IO::Pipe->new() or die "pipe failed: $!";

    $pid = fork();
    defined $pid or die "fork failed: $!";

    if ($pid == 0) {
	#child
	$pipe->writer();

	eval {
	    $ret = &$proc();
	    $rete = undef;
	};
	if ($@) {
	    $ret = undef;
	    $rete = "$@";
	}
	eval {
	    $json = JSON::encode_json([$ret,$rete]);
	};
	if ($@) {
	    $json = JSON::encode_json([undef,"$@"]);
	}
	print $pipe $json;
	$pipe->flush();
	POSIX::_exit(0);
    } else {
	#parent
	$pipe->reader();
	my $len = $pipe->read($json, 10485760);
	$len or die SUIDHandlingError->new("run_in_subprocess: error reading from subprocess");
	waitpid($pid, 0) == $pid or die("waitpid failed: $!");
	$? != 0 and die SUIDHandlingError->new("run_in_subprocess: subprocess exited with status != 0");
	eval {
	    ($ret, $rete) = @{JSON::decode_json($json)};
	};
	$@ and die SUIDHandlingError->new("run_in_subprocess: value passing failed: $@");
	if ($rete) {
	    die $rete;
	} else {
	    return $ret;
	}
    }
}

#### Sub-process invocation

=pod

=head2 spawn_in_privilege(mode, privilege, args...)

Invoke a sub-command, with privileges modified.

Parameters:

=over 2

=item *

mode:

=over 2

The first argument is either a string 'system' or 'spawn'.

=over 2

=item *

If 'system' is given, the function will wait for the process
termination and returns the exit status of the called program.

=item *

If 'spawn' is given, the function will return immediately when
execution the child program is started, and its process ID is
returned.

=back

In either case, if it cannot "exec" the child program, it will die
synchronously. (This behavior differs from the built-in C<system>
function.)

=back

=item *

privilege:

=over 2

The second argument is either

=over 2

=item *

a string corresponding to the names of the four privilege-changing
functions provided in this module, representing what privilege will be
passed to the called program;

=item *

a subroutine reference or a glob, which is called before invoking the
child program, after a sub-process is forked (similar to C<preexec_fn>
in the C<subprocess.run> in Python).

=back

=back

=item *

args:

=over 2

The rest of arguments will be passed to the C<exec> built-in.

However, if there are only a single array reference, its content will
be passed to C<exec>, with any shell escapes suppressed.
This can be used to invoke a sub-command safely, even if an argument
to the sub-command can be empty.

Furthermore, if the first element of that array is also a two-element
array, its elements will be used as a program path and a new argv[0]
respectively.

=back

=back

=cut

sub spawn_in_privilege( $$@ ) {
    my ($mode, $priv, @args) = @_;

    # check mode and priv here
    unless (grep { $_ eq $mode } qw(system spawn)) {
	croak("invalid mode for spawn_in_privilege");
    }
    my $priv_proc;
    if (ref $priv eq 'CODE' or ref $priv eq 'GLOB') {
	$priv_proc = $priv;
    } else {
	unless (grep { $_ eq $priv }
	    qw(temporarily_as_real_root temporarily_as_root temporarily_as_user drop_privileges_forever)) {
	    croak("invalid privilege for spawn_in_privilege");
	}
	$priv_proc = $::SUID_SUDO::{$priv}; # GLOB
    }

    my ($pid, $ret, $rete, $json) = undef;

    my $pipe = IO::Pipe->new() or die "pipe failed: $!";

    $pid = fork();
    defined $pid or die "fork failed: $!";

    if ($pid == 0) {
	#child
	$pipe->writer();
	eval {
	    &{$priv_proc}();

	    if (scalar @args == 1 and ref($args[0]) eq 'ARRAY') {
		@args = @{$args[0]};
		my $execname = $args[0];
		if (ref($args[0]) eq 'ARRAY') {
		    $execname = $args[0][0];
		    $args[0] = $args[0][1];
		}
		exec $execname @args or 1;
	    } else {
		exec @args or 1;
	    }
	    $ret = "can't exec: $!";
	};
	if ($@) {
	    # should not happen
	    $ret = "$@";
	}
	print $pipe $ret, "\n";
	$pipe->flush();
	POSIX::_exit(1);
    } else {
	#parent
	$pipe->reader();
	my $len = $pipe->read($ret, 10485760);
	if ($len) {
	    waitpid($pid, 0) == $pid or die("waitpid failed: $!");
	    chomp $ret;
	    die SUIDSubprocessError($ret);
	}
	if ($mode eq 'system') {
	    waitpid($pid, 0) == $pid or die("waitpid failed: $!");
	    return $?
	} elsif ($mode eq 'spawn') {
	    return $pid
	} else {
	    die
	}
    }
}

package main;

1;

=pod

=head1 AUTHOR/COPYRIGHT

(c) 2019 Yutaka OIWA.

=cut
