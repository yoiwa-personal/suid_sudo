#!/usr/bin/ruby -T
if __FILE__ != $0
  p "run directly."
  exit(1)
end
require File.absolute_path("../suid_sudo", File.dirname(__FILE__)).untaint
# require_relative claims insecure operation

include SUID_SUDO::INCLUDE
p suid_emulate(sudo_wrap:true, use_shebang:false, pass_env:['TESTVAR'])

cmd = ARGV[0] || "0"

def _ids
  p [[Process::Sys::getuid, Process::Sys::geteuid],
     [Process::Sys::getgid, Process::Sys::getegid],
     Process.groups]
end
def _print_ids
  p _ids
end

case cmd
when '0'
  _print_ids
  p ARGV
  ENV.each {|k,v| print "#{k}=#{v}\n" }
when '1'
  drop_privileges_forever
  _print_ids
  p ARGV
  ENV.each {|k,v| print "#{k}=#{v}\n" }
when 'setuid'
  print ("be USER ")
  temporarily_as_user()
  _print_ids

  print ("be ROOT")
  temporarily_as_root()
  _print_ids

  print ("be REAL_ROOT")
  temporarily_as_real_root()
  _print_ids

  print ("be USER")
  temporarily_as_user()
  _print_ids

  print ("drop to USER")
  drop_privileges_forever()
  _print_ids

  begin
    print ("be ROOT")
    temporarily_as_root()
    _print_ids
    print ("SHOULD FAILED!\n")
  rescue SUIDPrivilegesSettingError => e
    print("...good to be failed: #{e}\n")
  end
when 'temp'
  p "temporary_in_user"
  temporarily_as_user {
    _print_ids
  }
  p "returned"
  _print_ids
when 'temp_root'
  p "temporary_in_root"
  temporarily_as_root {
    _print_ids
  }
  p "returned"
  _print_ids
when 'system'
  p "system"
  p spawn_in_privilege(:system, :drop_privileges_forever, "/usr/bin/id")
when 'system_ba'
  p "system"
  p spawn_in_privilege(:system, :drop_privileges_foreverr, "/usr/bin/id")
when 'system_proc'
  p "system"
  p spawn_in_privilege(:system, method(:drop_privileges_forever), "/usr/bin/id")
when 'system_e'
  p "system"
  p spawn_in_privilege(:system, :drop_privileges_forever, "/dev/null")
when 'system_e2'
  p "system"
  p spawn_in_privilege(:system, :drop_privileges_forever, "/bin/false", exception:true)
when 'system_e2c'
  p system("/bin/false", exception:true)
when 'spawn'
  p "spawn"
  r = spawn_in_privilege(:spawn, :drop_privileges_forever, "/usr/bin/id")
  p r
  p Process.waitpid2(r)
when 'spawn_e'
  p "spawn"
  p spawn_in_privilege(:spawn, :drop_privileges_forever, "/dev/null")
when 'subproc'
  p "call_in_subprocess"
  result = run_in_subprocess {
    drop_privileges_forever
    _print_ids
    _ids
  }
  p ["result", result]
  _print_ids
when 'subproc_fd'
  p "call_in_subprocess"
  begin
    result = run_in_subprocess {
      exec("ls", "-lL", "/proc/self/fd")
      raise "BAD"
    }
    p result
  rescue SUIDSubprocessExecutionError => e
    p "OK #{e}"
  end
when 'subproc_fd_e1'
  # ensure above raise "BAD" is not captured
  p "call_in_subprocess"
  begin
    result = run_in_subprocess {
      raise "BAD"
    }
    p result
  rescue SUIDSubprocessExecutionError => e
    exit "BAD #{e.inspect}"
  rescue RuntimeError => e
    p "OK #{e.inspect}"
  end
when 'subproc_cs'
  p "call_in_subprocess"
  result = run_in_subprocess {
    [1, {2 => 3, 4 => 5}, "abc \u3001\u3002 cde"]
  }
  p result
when 'subproc_error1'
  p "call_in_subprocess"
  begin
    result = run_in_subprocess {
      ([1,2]).fetch(2)
      return "BAD"
    }
    p result
  rescue IndexError => e
    p "OK #{e}"
  end
when 'subproc_error1e'
  p "call_in_subprocess"
  begin
    result = run_in_subprocess {
      raise SUIDHandlingError::new("test") # non-wrappable exception
    }
    p result
  rescue WrappedSubprocessError => e
    p "OK #{e.inspect}"
  end
when 'subproc_error1e2'
  p "call_in_subprocess"
  begin
    result = run_in_subprocess {
      Math::sqrt(-4)
    }
    p result
  rescue Math::DomainError => e
    p "OK #{e.inspect}"
  end
when 'subproc_error2'
  begin
    result = run_in_subprocess {
      exit(255)
    }
  rescue SUIDSubprocessExecutionError => e
    p "OK #{e.inspect}"
  end
when 'subproc_error2_1'
  begin
    result = run_in_subprocess {
      exit!(255)
    }
  rescue SUIDSubprocessExecutionError => e
    p "OK #{e.inspect}"
  end
when 'subproc_error3'
  begin
    result = run_in_subprocess {
      drop_privileges_forever()
      exec("/usr/bin/id")
    }
  rescue SUIDSubprocessExecutionError => e
    p "OK #{e.inspect}"
  end
when 'subproc_error4'
  begin
    result = run_in_subprocess {
      exec("/dev/null")
    }
  rescue SystemCallError => e
    p "OK #{e.inspect}"
  end
when 'subproc_error5'
  begin
    result = run_in_subprocess {
      drop_privileges_forever()
      break
    }
  rescue SUIDSubprocessExecutionError => e
    p "OK #{e.inspect}"
  end
else
  p "unknown command"
end

