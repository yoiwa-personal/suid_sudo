#!/usr/bin/perl -T
use FindBin;
BEGIN {"$FindBin::RealBin/.." =~ /(.*)/; our $Lib = $1}; # $RealBin is tainted
use lib $Lib;

use SUID_SUDO ":all";
use Data::Dumper;

$ENV{PATH} = '/usr/bin:/bin';

sub print_ids () {
    print Dumper([$<, $>, $(, $)]);
}

my $r = suid_emulate(sudo_wrap => 1, use_shebang => 1, pass_env => [qw(TESTVAR)],
		     showcmd_opts => 1);
print "suid_emulate -> $r\n";

my $cmd = $ARGV[0] || "0";

if ($cmd eq "0") {
    print_ids;
    print Dumper([@ARGV]);
    for my $k (keys %ENV) {
	print "$k=$ENV{$k}\n";
    }
} elsif ($cmd eq "setuid_p") {
    temporarily_as_user {
	system("grep -i 'id' /proc/self/status");
	system("grep -i 'Groups' /proc/self/status");
	system("id");
	print "$ENV{HOME}\n";
    };

    system("grep -i 'id' /proc/self/status");
    system("grep -i 'Groups' /proc/self/status");
    system("id");
    print "$ENV{HOME}\n";

    drop_privileges_forever {
	system("grep -i 'id' /proc/self/status");
	system("grep -i 'Groups' /proc/self/status");
	system("id");
	print "$ENV{HOME}\n";
    };
} elsif ($cmd eq "subproc") {
    my $ret = run_in_subprocess {
	drop_privileges_forever;
	[1,2,3];
    };
    print Dumper($ret);
} elsif ($cmd eq "subproc_e0") {
    my $ret = run_in_subprocess {
	drop_privileges_forever;
	die "child error";
    };
    print Dumper($ret);
} elsif ($cmd eq "system") {
    print spawn_in_privilege("system", "drop_privileges_forever", "id")
} elsif ($cmd eq "system_ref") {
    print spawn_in_privilege("system", \&drop_privileges_forever, "id")
} elsif ($cmd eq "system_e1") {
    print spawn_in_privilege("system", "drop_privileges_forever", "/dev/null")
} elsif ($cmd eq "system_e2") {
    print spawn_in_privilege("system", "drop_privileges_forever", "/dev/nonexistent")
} elsif ($cmd eq "system_e3_0") {
    print spawn_in_privilege("system", "drop_privileges_forever", "/dev/null >/dev/null")
} elsif ($cmd eq "system_e3") {
    print spawn_in_privilege("system", "drop_privileges_forever", ["/dev/null >/dev/null"])
      # should be ENOENT, not EPERM or exited(2).
} elsif ($cmd eq "system_argv0") {
    print spawn_in_privilege("system", "drop_privileges_forever", [["/bin/cat", "hoge"], "/proc/self/cmdline"])
      # should be ENOENT, not EPERM or exited(2).
} elsif ($cmd eq "system_r") {
    print spawn_in_privilege("system", "temporarily_as_real_root", "id")
} else {
    print "unknown command \"\Q$cmd\E\"\n";
}
