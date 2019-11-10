use 5.024001;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

WriteMakefile(
	      NAME              => 'SUID_SUDO',
	      VERSION           => '0.1',
	      ABSTRACT          => 'A library for emulating setuid by sudo',
	      AUTHOR            => 'Yutaka OIWA <yutaka@oiwa.jp>',
	      LICENSE           => 'apache',
	      DISTNAME => 'SUID_SUDO',
	      PM => {'SUID_SUDO.pm' => '$(INST_LIBDIR)/SUID_SUDO.pm', "MANIFEST.perl" => "MANIFEST"},
);
