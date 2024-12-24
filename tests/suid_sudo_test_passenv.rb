#!/usr/bin/ruby
if __FILE__ != $0
  p "run directly."
  exit(1)
end
require File.absolute_path("../suid_sudo", File.dirname(__FILE__)).untaint
# require_relative claims insecure operation

include SUID_SUDO::INCLUDE
p suid_emulate(sudo_wrap:true, use_shebang:false, pass_env:['TESTVAR'], showcmd_opts:true)

cmd = ARGV[0] || "0"

def _ids
  p [[Process::Sys::getuid, Process::Sys::geteuid],
     [Process::Sys::getgid, Process::Sys::getegid],
     Process.groups]
end
def _print_ids
  p _ids
end
def _print_ids_env
  p _ids
  ENV.each {|k,v| print "#{k}=#{v}\n" }
end

case cmd
when 's'
  p SUID_SUDO.const_get(:SUID_STATUS_)::_status
when 'p'
  print ("\nbe USER\n")
  temporarily_as_user()
  _print_ids_env

  print ("\nbe ROOT\n")
  temporarily_as_root()
  _print_ids_env

  print ("\nbe REAL_ROOT\n")
  temporarily_as_real_root()
  _print_ids_env

  print ("\nbe USER\n")
  temporarily_as_user()
  _print_ids_env

  print ("\ndrop to USER\n")
  drop_privileges_forever()
  _print_ids_env

  begin
    print ("\nbe ROOT\n")
    temporarily_as_root()
    _print_ids_env
    print ("SHOULD FAILED!\n")
  rescue SUIDPrivilegesSettingError => e
    print("...good to be failed: #{e}\n")
  end
when 'pb'
  print "\ntemporary_in_user\n"
  temporarily_as_user {
    _print_ids_env
  }
  print "\nreturned\n"
  _print_ids_env
  print "temporary_in_root\n"
  temporarily_as_root {
    _print_ids_env
  }
  print "\nreturned\n"
  _print_ids_env
end
