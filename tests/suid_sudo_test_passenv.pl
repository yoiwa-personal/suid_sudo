#!/usr/bin/perl -T
use FindBin;
BEGIN {"$FindBin::RealBin/.." =~ /(.*)/; our $Lib = $1}; # $RealBin is tainted
use lib $Lib;

use SUID_SUDO ":all";
use Data::Dumper;

$ENV{PATH} = '/usr/bin:/bin';

sub print_ids () {
    print Dumper([$<, $>, $(, $)]);
    for my $k (keys %ENV) {
	print "$k=$ENV{$k}\n";
    }
}

my $r = suid_emulate(sudo_wrap => 1, use_shebang => 1, pass_env => [qw(TESTVAR)],
		     showcmd_opts => 1);
print "suid_emulate -> $r\n";

my $cmd = $ARGV[0] || "0";

if ($cmd eq "0") {
    print_ids;
    print Dumper([@ARGV]);
} elsif ($cmd eq "1") {
    drop_privileges_forever;
    print_ids;
    print Dumper([@ARGV]);
} elsif ($cmd eq "s") {
    print Dumper($SUID_SUDO::_status);
} elsif ($cmd eq "p") {
    print "HOME=$ENV{HOME}\nTESTVAR=$ENV{TESTVAR}\n";
    print "temporarily_as_user\n";
    temporarily_as_user;
    print_ids();
    system("id");
    print "HOME=$ENV{HOME}\nTESTVAR=$ENV{TESTVAR}\n";

    print "temporarily_as_real_root\n";
    temporarily_as_real_root;
    print_ids();
    system("id");
    print "HOME=$ENV{HOME}\nTESTVAR=$ENV{TESTVAR}\n";

    print "drop_privileges_forever\n";
    drop_privileges_forever;
    print_ids();
    system("id");
    print "HOME=$ENV{HOME}\nTESTVAR=$ENV{TESTVAR}\n";

} elsif ($cmd eq "pb") {
    print "temporarily_as_user\n";
    temporarily_as_user {
	print_ids();
	system("id");
	print "HOME=$ENV{HOME}\nTESTVAR=$ENV{TESTVAR}\n";
    };

    print "restored\n";
    print_ids();
    system("id");
    print "HOME=$ENV{HOME}\nTESTVAR=$ENV{TESTVAR}\n";

    print "temporarily_as_real_root\n";
    temporarily_as_real_root {
	print_ids();
	system("id");
	print "HOME=$ENV{HOME}\nTESTVAR=$ENV{TESTVAR}\n";
    };

    print "drop_privileges_forever\n";
    drop_privileges_forever {
	print_ids();
	system("id");
	print "HOME=$ENV{HOME}\nTESTVAR=$ENV{TESTVAR}\n";
    }; # error will occur
} else {
    print "unknown command \"\Q$cmd\E\"\n";
}
