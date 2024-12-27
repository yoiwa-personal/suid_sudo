# -*- ruby -*-
# Ruby library to simulate suid-script by sudo
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

=begin rdoc
= Emulate behavior of set-uid binary when invoked via sudo(1).

This module enables Ruby scripts to perform most of its works in the
invoking user's non-root privilege, while employing root's power
for a part of its job.

Programmers using this module shall be aware of Uni* semantics
and techniques around the "setuid" feature.

The main function in this module is the "suid_emulate" function.

Functions/Features available:

*  Initialize: suid_emulate
*  Privilege Control: temporarily_as_root, temporarily_as_user,
*  temporarily_as_real_root, drop_privileges_forever
*  Execution Helper: call_in_subprocess

Currently Linux 4.0+ is required.

== SECURITY WARNING:

Inappropriate use of this module will open up a huge security hole
to ordinary users.  In the past obsolete "suidperl" feature of the
Perl language, the special language interpreter takes care of
various possible security pitfalls (e.g. limiting use of
$ENV{PATH}).  This module, on the contrary, simply relies
on the "sudo" generic wrapper for the most of the security
features.  In other words, this module only "drops" the privilege
given by sudo, not "acquires" any.  However, still there are
several possible pitfalls which may grant root privileges to
ordinary users.

In general, the script must be safe enough to be run via sudo.
That means:

* the script should be owned by root and not modifiable by any
  ordinary users,

* the script should be explicitly specified in sudoers(5) file
  with the full pathspec, and

* the script must be careful about any environment variables and
  any other environmental properties which will affect Ruby,
  the script, and any subcommands invoked from it.

Please read README.md for security details.
=end

module SUID_SUDO
  require 'etc'
  require 'base64'

  ### Exceptions

  # Runtime error happens during processing by suid_sudo
  class SUIDHandlingError < RuntimeError
  end

  # Runtime error happens during initial setup by suid_sudo
  class SUIDSetupError < SUIDHandlingError
  end

  # Runtime error during changing privileges
  class SUIDPrivilegesSettingError < SUIDHandlingError
  end

  # Fatal Runtime error during dropping privileges.
  #
  # Failure on dropping privileges (including reverting to the lower
  # privileges after high-privilege code is run) is really security
  # critical.  Such an event is qute unlikely to happen in usual
  # cases, but if improperly handled, it will cause dangerous security
  # hole: some code to be run in higher-than-expected privileges.  To
  # prevent this, this module treats such a failure like a call to
  # exit(), which will not be captured by "begin ... rescue ..."
  # clauses.
  #
  # Any "begin ... ensure" clauses still catch this case, so be
  # careful what to do in these clauses.
  #
  # If you really need this case to be covered, and if you write
  # exception-handling code in a very careful manner (that code might
  # be run in unknown/unexpected privileges), you can catch this
  # "exception" by this name ("begin ... rescue
  # SUIDPrivilegesSettingFatalError ...").
  class SUIDPrivilegesSettingFatalError < SecurityError
  end

  # Runtime error during handling of sub-processes
  class SUIDSubprocessError < SUIDHandlingError
  end

  # Error caused during execution of code in sub-processes.  For
  # example, it will be raised when the subprocess vanished (by
  # exec(), exit!()) before returning a result.
  class SUIDSubprocessExecutionError < SUIDSubprocessError
  end

  # Wrapped exception raised from code inside sub-processes.
  # Indicates that a non-builtin exception is raised within
  # subprocess.
  class WrappedSubprocessError < SUIDSubprocessError
  end

  ### module constants

  # List of allowed sudo commands in full-path.
  ALLOWED_SUDO_ = ['/bin/sudo', '/usr/bin/sudo']

  # A pattern matching suppressed call stack entries on error
  ERROR_FILTER_REGEXP = %r"#{Regexp.quote(__FILE__)}:\d+:in \`\_"

  ### some common functions

  #def self.dp(*a)
    #p(*a)
  #end

  module COMMON_FUNCTIONS_
    module_function
    def _env_from_pwent(pwent)
      return {"LOGNAME" => pwent.name,
              "USER" => pwent.name,
              "USERNAME" => pwent.name,
              "HOME" => pwent.dir}
    end
    def _save_envs(l)
      r = {}
      l.each { |k|
        r[k] = ENV.fetch(k, nil)
      }
      return r
    end
    def _apply_envs(l)
      l.each { |k, v|
        if v != nil
          ENV[k] = v
        else
          ENV.delete(k)
        end
      }
    end
    IS_RUBY2 = RUBY_VERSION =~ /\A[12]\./
    IS_RUBY2_7 = RUBY_VERSION =~ /\A2\.7\./
    if IS_RUBY2
      def _untaint(o)
        o.dup.untaint
      end
    else
      def _untaint(o)
        o
      end
    end
  end
  include COMMON_FUNCTIONS_
  extend COMMON_FUNCTIONS_

  ### Internal-use classes

  # Class representing status of the running process under suid handling.
  #
  # The class method "_status" returns a singleton instance representing
  # the current process's status.
  class SUID_STATUS_
    include COMMON_FUNCTIONS_

    @@status = nil

    # Set up an singleton instance representing process status.
    # Called automatically from suid_emulate.
    def self._make_status_now(*args, **kwargs)
      raise SUIDSetupError.new("_make_status_now called twice")  if @@status
      @@status = SUID_STATUS_.new(*args, **kwargs)
      return @@status
    end
    # Returns the singleton instance representing process status.
    def self._status
      return @@status
    end
    private
  
    def initialize(is_suid, via_sudo, uids:nil, gids:nil, groups:nil, user_pwent:nil, passed_env:{})
      @is_suid = is_suid
      @suid_via_sudo = via_sudo

      uids = [Process::uid, Process::euid] if uids == nil
      @uid, @euid = uids

      gids = [Process::gid, Process::egid] if gids == nil
      @gid, @egid = gids

      groups = Process::groups if groups == nil
      @groups = groups

      user_pwent = Etc::getpwuid(uid) if user_pwent == nil
      @user_pwent = user_pwent
      root_pwent = Etc::getpwuid(euid)
      @root_pwent = root_pwent

      raise unless (user_pwent.uid == uid)
      raise unless (root_pwent.uid == euid)

      root_envs = _save_envs(passed_env.keys)
      root_envs.update(_env_from_pwent(root_pwent))
      @root_envs = root_envs

      user_envs = _env_from_pwent(user_pwent)
      user_envs.update(passed_env)
      @user_envs = user_envs
    end
    public
    attr_reader :is_suid, :suid_via_sudo, :uid, :euid, :gid, :egid
    attr_reader :groups, :user_pwent, :root_pwent, :root_envs, :user_envs
  end

  # Class representing the process's surrounding environment,
  # especially its parent.
  #
  # The class method "surrounds" returns a singleton instance
  # representing the current process's status.
  class SURROUND_INFO_
    @@surrounds = nil
    def self.check_surround()
      return @@surrounds if @@surrounds
      return @@surrounds = SURROUND_INFO_.new()
    end

    def self.surrounds()
      return @@surrounds
    end

    @@procexe_linkname = nil
    def self.procexe_linkname(pid)
      unless (@@procexe_linkname)
        self_pid = Process::pid
        ["exe", "file"].each { |l|
          f = "/proc/#{self_pid}/#{l}" # use pid of myself
          if File.exists?(f)
            begin
              File::readlink(f)
              # exe link must be available and is a readable link
            rescue Errno::ENOENT
              raise "/proc system is something bad"
            end
            @@procexe_linkname = l
            break
          end
        }
        raise "cannot read /proc to check sudo" if @@procexe_linkname == nil
      end

      return "/proc/#{pid}/#{@@procexe_linkname}"
    end

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
    #     (status: :success,
    #      ppid:   integer,
    #      p_path: string
    #      p_stat: a stat struct)
    #
    #     These three pieces of information are guaranteed to be
    #     consistent and referring to the same "process" object,
    #     at some instant moment during this function was running.
    #     It might be different from the things "now".
    #
    # (2) If the parent is alive but not accessible:
    #     (e.g. running as non-root, parent has different privilege)
    #     (status: :EPERM,
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
    #     (status: :ENOENT,
    #      ppid:   integer or 1,
    #      p_path: nil,
    #      p_stat: nil)
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
    private
    def initialize()
      #b = lambda {|x| p x}
      b = lambda {|x|}

      # self status is reliable and stable.
      @pid = pid = Process::pid

      # all the following status values might change during execution.
      # ppid may change only once to 1 when the parent exits.
      @@ppid = ppid_0 = Process::ppid

      # is_root = Process::euid == 0
      # is_suid = Process::euid != Process::uid

      stat_proc = File::stat("/proc")

      # sanity check: existence of the proc file system
      raise "/proc system is something bad" unless (
        stat_proc.uid == 0 && stat_proc.gid == 0 &&
        stat_proc.dev_major == 0 && # non-device-backed file system
        stat_proc.mode == 0o40555
      )

      # sanity check: check for exe link
      self.class.procexe_linkname(pid)

      # fragile information
      10.times { |xtimes|
        ppid_1 = path_1 = stat_1 = stat_2 = path_2 = ppid_2 = nil
        @status = nil

        b.("==== ppid_1 ==== (#{xtimes})")
        ppid_1 = Process::ppid
        if (ppid_1 == 1)
          # parent exited
          @status = :ENOENT
          @p_path = nil
          @p_stat = nil
          return
        end

        ppid1_linkname = self.class.procexe_linkname(ppid_1)

        begin
          b.("path_1")
          path_1 = File::readlink(ppid1_linkname)
        rescue Errno::ENOENT
          # parent exited now
          raise unless Process::ppid == 1
          next
        rescue Errno::EPERM, Errno::EACCES => e
          # cannot read: different owner?
          case Process::ppid
          when ppid_1
            # cannot read: different owner, still alive
            raise unless ppid_0 == ppid_1
            @status = :EACCES
            @p_path = e
            @p_stat = e
            return
          when 1
            # cannot read: because parent exited (and I am non-root)
            next
          else
            raise
          end
        end

        begin
          b.("stat_1")
          stat_1 = File::stat(ppid1_linkname)
        rescue Errno::ENOENT
          # parent exited now
          raise unless Process::ppid == 1
          next
        rescue Errno::EPERM, Errno::EACCES => e
          # cannot read: different owner?
          case Process::ppid
          when ppid_1
            @status = :EACCES
            stat_1 = e
            # go through to "path_2" below to check path consistency
          when 1
            # cannot read: because parent exited
            next
          else
            raise
          end
        end

        begin
          b.("path_2")
          path_2 = File::readlink(ppid1_linkname)
          next if path_1 != path_2
        rescue Errno::ENOENT, Errno::EPERM, Errno::EACCES
          next
        end

        b.("ppid_2")
        ppid_2 = Process::ppid
        next if ppid_1 != ppid_2

        raise unless ppid_0 == ppid_1
        @status ||= :success
        @p_path = path_1
        @p_stat = stat_1
        return
      }
      raise Errno::EAGAIN
    end
    public
    attr_reader :status, :p_path, :p_stat

    def self.test_main()
      wait = (ARGV[0] || 20).to_i
      pid_1 = fork {
        fork {
          p check_surround()
        }
        sleep(wait)
        if ARGV[2]
          p "parent swap"
          exec("sudo", "sleep", ARGV[2])
        elsif ARGV[1]
          p "parent swap"
          exec("sleep", ARGV[1])
        else
          p "parent exit"
          exit(0)
        end
      }
      Process::waitpid(pid_1)
    end
  end

  private

  ### Handling inter-process communication via sudo-wrapped invocation

  def self._keystr_encode(*a)
    begin
      l = [ a.map {|x| x.to_s.encode("utf-8").force_encoding('ascii-8bit') } ]
      b = Base64.urlsafe_encode64(l.join("\0"))
      return b
    rescue EncodingError
      raise SUIDSetupError::new("cannot encode wrapper key due to encoding error")
    end
  end

  def self._keystr_decode(s)
    begin
      v = Base64.urlsafe_decode64(s)
      v = v.split(/\0/, -1) # -1: do not discard trailing empty entries
      v = v.map {|x| x.encode('utf-8', 'utf-8')}
      return v
    rescue ArgumentError, EncodingError => e
      raise SUIDSetupError::new("cannot decode wrapper key: #{e}")
    end
  end

  def self._encode_wrapper_info(envp)
    return _keystr_encode(Process::pid, Process::uid, Process::gid, envp)
  end

  def self._decode_wrapped_info(v, uid, gid, pass_env)
    if v.length != 4 or Process::ppid.to_s != v[0] or uid.to_s != v[1] or gid.to_s != v[2]
      raise SUIDSetupError::new("wrapped invocation key mismatch")
    end
    return {passed_env: _decode_passenv(v[3], pass_env)}
  end

  def self._setup_passenv(pass_env)
    while(true)
      p = rand(10000000000).to_s # not needed to be secure, but larger than max env size
      env_name = "LC__SUDOWRAP_" + p
      break unless ENV.include?(env_name)
    end
    out = []
    pass_env.each { |k|
      if k.include?('=')
          raise ArgumentError.new("names in pass_env should not contain =")
      end
      v = ENV[k]
      if v == nil
        out << k
      else
        out << "#{k}=#{v}"
      end
    }

    ENV[env_name] = _untaint(_keystr_encode(*out))
    return p
  end

  def self._decode_passenv(envp, pass_env)
    return {} if envp == ""
    retval = {}
    env_name = "LC__SUDOWRAP_" + _untaint(envp)
    e_val = ENV.delete(env_name) {
      # not found
      warn("environment #{env_name.inspect} missing")
      return {}
    }
    e_val = _keystr_decode(e_val)
    if (e_val.length != pass_env.length)
        raise SUIDSetupError.new("bad pass_env values: length mismatch")
    end
    pass_env.zip(e_val) { |k, v|
      k2, sep, val = v.partition("=")
      if k2 != k
        raise SUIDSetupError::new("bad pass_env values: key mismatch")
      elsif sep == "="
        retval[k] = _untaint(val)
      else
        retval[k] = nil
      end
    }
    return retval
  end

  ### sudo-wrapped reinvocation

  def self._detect_wrapped_reinvoked()
    return nil if ARGV.length == 0
    arg = ARGV[0]

    if /\A----sudo_wrap=(.+)\z/ =~ arg
      v = _keystr_decode($1)
      if v
        ARGV.shift
        return v
      else
        raise SUIDSetupError::new("bad format wrapped invocation key")
      end
    end
    return nil
  end

  def self.called_via_sudo()
    ppid = Process::ppid
    has_root = (Process::euid == 0)

    surround_info = SURROUND_INFO_::check_surround()

    case surround_info.status
    when :ENOENT
      if has_root
        raise SUIDSetupError::new("cannot check parent process: #{surround_info.status}")
      else
        return false
      end
    when :EPERM
      if has_root
        raise SUIDSetupError::new("cannot check parent process: #{surround_info.status}")
      else
        return true if ALLOWED_SUDO_.include?(surround_info.p_path)
        # p_path may be error instance but it's OK
        return false
      end
    when :success
      return true if ALLOWED_SUDO_.include?(surround_info.p_path)
      return false if ! has_root

      # We're running in root. We must be more careful.
      begin
        found = false
        s1 = surround_info.p_stat
        ALLOWED_SUDO_.each {|f_sudo|
          if File.exists?(f_sudo)
            found = true
            s2 = File::stat(f_sudo)
            if (s1.dev == s2.dev && s1.ino == s2.ino)
              raise SUIDSetupError::new("found a LINK of system sudo #{f_sudo} at #{parent_exe}")
              return true
            end
          end
        }
        raise SUIDSetupError::new("no system sudo found") unless found
        return false
      rescue SystemCallError => e
        raise SUIDSetupError::new("cannot check detail of parent process #{parent_exe}: #{e}")
      end
    else
      raise #notreached
    end
  end

  def self._get_ruby_interpreter()
    pid = Process::pid
    exe = File.readlink(SURROUND_INFO_::procexe_linkname(pid))
    # sanity check
    if ! (%r(\A/..*/ruby(\d[^/]*)*\z) =~ exe)
      raise SUIDSetupError::new("unknown ruby interpreter #{exe}")
    end
    return exe
  end

  def self._process_ruby_flags(ruby_flags, inherit_flags:false)
    l = []
    done = {}
    re = proc { |x|
      unless done[x]
        done[x] = true
        if x == 'T' && !IS_RUBY2
          l << '--disable=rubyopt'
        else
          l << "-#{x}"
        end
      end
    }
    ruby_flags.each_char {|x|
      re.(x)
    }
    if inherit_flags
      re.("T") if $SAFE > 0
    end
    return l
  end

  def self._construct_wrap_invoke_cmdline(use_shebang:false, ruby_flags:"T", inherit_flags:false,
                                          sudo_allow_cached_cred:false,
                                          wrapkey:nil)
    if not $0 or $0 == "-e"
      raise SUIDSetupError.new("can not reinvoke script: not running a script?")
    end
    scriptname = _untaint(File.absolute_path($0))
    execname = _untaint(_get_ruby_interpreter())
    flags = []
    if not File.exists?(scriptname)
      raise SUIDSetupError.new("can not reinvoke script: could not found myself")
    end
    if not File.exists?(execname)
      raise SUIDSetupError.new("can not reinvoke script: interpreter not found")
    end
    if use_shebang
      execname = []
      flags = []
    else
      execname = [execname]
      flags = _process_ruby_flags(ruby_flags, inherit_flags:inherit_flags)
    end

    cmd = ALLOWED_SUDO_[0]
    ALLOWED_SUDO_.each { |c|
      if File.exists?(c)
        cmd = c
      end
    }

    if sudo_allow_cached_cred == -1
      sudo_flags = ["-k", "-n"]
    elsif sudo_allow_cached_cred
      sudo_flags = []
    else
      sudo_flags = ["-k"]
    end
    sudocmd = [cmd] + sudo_flags
    args = execname + flags + [scriptname, "----sudo_wrap=" + wrapkey]
    return sudocmd, args
  end

  def self._wrap_invoke_sudo(use_shebang:false,
                             ruby_flags:"", inherit_flags:false,
                             sudo_allow_cached_cred:false,
                             pass_env:[])
    if ! pass_env || pass_env.length == 0
      env_var = ""
    else
      env_var = _setup_passenv(pass_env)
    end
    wrapkey = _encode_wrapper_info(env_var)

    sudocmd, args = _construct_wrap_invoke_cmdline(
           use_shebang:use_shebang,
           ruby_flags:ruby_flags,
           inherit_flags:inherit_flags,
           sudo_allow_cached_cred:sudo_allow_cached_cred,
           wrapkey:wrapkey)

    args = sudocmd + args + ARGV.map {|x| _untaint(x)}

    begin
      exec(*args)
    rescue SystemCallError => e
      raise SUIDSetupError::new("could not invoke #{cmd} for wrapping: #{e.inspect}")
    end
    assert false
  end

  # Returns the commandline pattern which is used for reinvocation via sudo.
  #
  # Returned value is a pair of strings to be displayed: the first is
  # the sudo command line, and the second is a possible template for
  # the sudoers configuration.
  #
  # Parameters use_shebang, ruby_flags, inherit_flags, pass_env are
  # as same as suid_emulate().
  #
  # The parameter user_str is used in the position of the invoking
  # user name in sudoers.
  def compute_sudo_commane_line_patterns(use_shebang:false, ruby_flags:"T",
                                         inherit_flags:false,
                                         sudo_allow_cached_cred:false,
                                         pass_env:[], user_str:".user.")
    sudocmd, cmdline = _construct_wrap_invoke_cmdline(
        use_shebang:use_shebang, ruby_flags:ruby_flags,
        inherit_flags:inherit_flags,
        sudo_allow_cached_cred:sudo_allow_cached_cred,
        wrapkey:'')

    cmdstr = (sudocmd + cmdline).join(" ")

    cmdline_sudoers = cmdline.map {|x|
      x.gsub(/([ =*\\])/) { |s| "\\" + s }
    }

    sudoers = cmdline_sudoers.join(" ")
    sudoers = "#{user_str} ALL = (root:root) NOPASSWD: #{sudoers}*"

    return cmdstr, sudoers
  end

  # Show the commandline pattern which is used for reinvocation via sudo.
  #
  # Output is sent to stderr.
  #
  # Parameters use_shebang, ruby_flags, inherit_flags, pass_env are
  # as same as suid_emulate().
  #
  # If check is a truth value, it will be compared with the first
  # command line parameter.  if these are equal, it will show the
  # information and terminate the self process automatically.
  # Otherwise, do nothing.  A special value "true" is treated as
  # "--show-sudo-command-line".
  #
  # If script want to use own logics or conditions for showing this
  # information, call this function with check:false (default).
  def show_sudo_command_line(use_shebang:false, ruby_flags:"T", inherit_flags:false,
                             sudo_allow_cached_cred:false,
                             pass_env:[], check:false)
    if check
      if check == true
        check = '--show-sudo-command-line'
      end
      if ARGV.length < 1 or ARGV[0] != check
        return
      end
    end

    cmdstr, sudoers = compute_sudo_commane_line_patterns(
              use_shebang:false, ruby_flags:"T",
              inherit_flags:false,
              sudo_allow_cached_cred:sudo_allow_cached_cred,
              pass_env:[], user_str:".user.")

    $stderr.printf('
This command uses sudo internally. It will invoke itself as:

%s...

Corresponding sudoers line will be as follows:

%s

".user." should be replaced either by a user name or by "ALL".

Please check the above configuration is secure or not,
before actually adding it to /etc/sudoers.
', cmdstr, sudoers)

    if check
      exit(2)
    end
  end

  ### Detect and initialize sudo'ed and suid'ed environment

  def self._pick_environment(ename, type=nil)
    type ||= ename
    valstr = ENV.delete(ename) {
      # not found
      raise SUIDSetupError::new("sudo did not set #{type} information")
    }
    valint = valstr.to_i
    if valint.to_s != valstr
      raise SUIDSetupError::new("sudo set malformed #{type} information")
    end
    return valint
  end

  public
  # Emulate behavior of set-uid binary when invoked via sudo(1).
  #
  # This function is to be invoked as early as possible in the script
  # intended to be invoked via sudo.
  #
  # It detects whether the script was invoked via sudo, and who
  # invoked it, then it sets real uid and real gid appropriately.
  # Effective uid and gid is kept as root.  It means that (a) methods
  # in the Process module (and its submodules) can be used to switch
  # between invoking user and root, and (b) os.access function will
  # return file accessibility of the invoking user (beware of timing
  # security hole, though).
  #
  # The function returns true when setuid is effective; false
  # otherwise (invoked directly as either root or a non-root user).
  #
  # All arguments are optional and having meanings as follows:
  #
  # [realroot_ok]
  #
  #  default False. Specify whether the script can be invoked as real
  #  root user (via sudo by root).
  #
  # [nonsudo_ok]
  #
  #  default false. Specify whether the script can be invoked by root
  #  user without sudo.  When enabled, misconfiguration might open
  #  security holes to ordinary users; be extremely careful.
  #
  # [sudo_wrap]
  #
  #  default false. If set to true, the script will try to invoke
  #  itself via sudo(1), when root privilege is not available.  Sudo
  #  must be configured appropriately so that required ordinary users
  #  can invoke this script (by its full-path with ruby command).
  #
  #  A special command-line argument is used to communicate between
  #  invoking/self-invoked scripts, thus the function MUST be called
  #  before any command-line processing (e.g. argparse).
  #
  # [use_shebang]
  #
  #  default false; only meaningful when sudo_wrap=true.  If set to
  #  true, the module will directly invoke the script itself as an
  #  executable, expecting '#!' feature of the underlying operating
  #  system to work.
  #
  #  Use of this flag requires changes to the sudo configuration.
  #
  # [ruby_flags]
  #
  #  default "T"; only meaningful when sudo_wrap=true and
  #  use_shebang=false.  A string containing one-character flags to be
  #  passed to the ruby interpreter called when sudo_wrap=True.
  #
  # [inherit_flags]
  #
  #  default false; only meaningful when sudo_wrap=true and
  #  use_shebang=false.  If set to true, it will pass some of the
  #  flags originally passed to the Ruby interpreter.
  #
  # [pass_env]
  #
  #  default []; list of names of environment variables which is
  #  passed to the wrapped command.  Effective only with
  #  sudo_wrap=True.  Its value is encoded to special environmental
  #  variable; it cheats the fact that sudo passes all variables
  #  starts with "LC_".
  #
  #  *Caution*: passing some system-defined variables such as IFS,
  #  LD_PRELOAD, LD_LIBRARY_PATH will lead to creation of a security
  #  hole.  This option can bypass security measures provided by sudo,
  #  if the script really tells this module to do so.  Use this
  #  feature only when it is really needed.
  #
  # [showcmd_opts]
  #
  # default nil: if a string is given, this function will compare it
  # with first command-line argument.  If it matches, it shows the
  # command line for the re-invocation and exit.  If "True" is passed,
  # it is treated as if it were "--show-sudo-command-line".

  def suid_emulate(realroot_ok:false, nonsudo_ok:false,
                   sudo_wrap:false, use_shebang:false,
                   ruby_flags:"T", inherit_flags:false,
                   pass_env:[], pass_env_to_root:false,
                   sudo_allow_cached_cred:false,
                   showcmd_opts:nil)
    if SUID_STATUS_::_status
      return SUID_STATUS_::_status.is_suid
    end

    if showcmd_opts
      show_sudo_command_line(
        use_shebang:use_shebang, ruby_flags:ruby_flags,
        inherit_flags:inherit_flags, sudo_allow_cached_cred:sudo_allow_cached_cred,
        pass_env:pass_env, check:showcmd_opts)
    end

    uid = Process::Sys::getuid
    euid = Process::Sys::geteuid
    wrapped_invocation_info = _detect_wrapped_reinvoked()
    is_sudoed = called_via_sudo()

    if (! is_sudoed && wrapped_invocation_info)
      raise SUIDSetupError::new("bad wrapper key found")
    end

    if (uid != euid)
      SUID_STATUS_::_make_status_now(true, false)
      return true
    end

    if euid != 0
      if sudo_wrap
        if wrapped_invocation_info
          raise SUIDSetupError::new("detected wrapping loop")
        end
        _wrap_invoke_sudo(use_shebang:use_shebang,
                          ruby_flags:ruby_flags, inherit_flags:inherit_flags,
                          sudo_allow_cached_cred:sudo_allow_cached_cred,
                          pass_env:pass_env)
      end
      SUID_STATUS_::_make_status_now(false, false)
      return false
    end

    if ! is_sudoed
      # really run by root?
      if (! realroot_ok || ! nonsudo_ok)
        raise SUIDSetupError::new("This script must be invoked via sudo")
      end
      SUID_STATUS_::_make_status_now(false, false)
      return false
    end

    # sudoed.
    sudo_uid = _pick_environment("SUDO_UID")
    sudo_gid = _pick_environment("SUDO_GID")

    if wrapped_invocation_info
      wrapped_invocation_info = _decode_wrapped_info(wrapped_invocation_info, sudo_uid, sudo_gid, pass_env)
    end

    if (! realroot_ok && sudo_uid == 0)
      raise SUIDSetupError::new("This script must be run by non-root")
    end

    sudo_username = ENV.delete("SUDO_USER") {
      raise SUIDSetupError::new("sudo did not set username information")
    }
    sudo_username = _untaint(sudo_username)
    ENV.delete("SUDO_COMMAND")
    ENV.delete("MAIL") # not worth to simulate

    begin
      pwdent = Etc::getpwnam(sudo_username)
    rescue ArgumentError
      raise SUIDSetupError::new("bad username information from sudo: no corresponding user")
    end
    if (pwdent.uid != sudo_uid)
      raise SUIDSetupError::new("inconsistent user information from sudo: why?")
    end
    Process::initgroups(sudo_username, sudo_gid)

    passed_env = if wrapped_invocation_info
                 then wrapped_invocation_info[:passed_env]
                 else {} end

    if pass_env_to_root
      _apply_envs(passed_env)
      passed_env = {}
    end
    SUID_STATUS_::_make_status_now(
      true, true, uids:[sudo_uid, 0], gids:[sudo_gid, 0],
      user_pwent:pwdent, passed_env:passed_env)
    Process::Sys::setregid(sudo_gid, 0)
    Process::Sys::setreuid(sudo_uid, 0)

    if (Process.uid != sudo_uid)
      raise SUIDSetupError::new("setresuid failed")
    end
    if (Process.gid != sudo_gid)
      raise SUIDSetupError::new("setresgid failed")
    end
    return true
  end

  ### Switch between privileges

  private

  def self._raise_setting_error(to_be_root, msg)
    begin
      if to_be_root
        raise SUIDPrivilegesSettingError::new(msg)
      else
        raise SUIDPrivilegesSettingFatalError::new(msg)
      end
    ensure
      $@.delete_if {|x| ERROR_FILTER_REGEXP =~ x };
    end
  end

  def self._set_uids(to_be_root, completely, setenv:false, &procobj)
    s = SUID_STATUS_::_status

    restorer = {
      to_root: (not to_be_root),
      u: [Process::Sys::getuid, Process::Sys::geteuid],
      g: [Process::Sys::getgid, Process::Sys::getegid],
      groups: Process::groups,
      env: {}
    }
    groups = s.groups
    if to_be_root
      to_g, from_g = s.egid, s.gid
      to_u, from_u = s.euid, s.uid
      pwent = s.root_pwent
      env_to_set = s.root_envs
    else
      to_g, from_g = s.gid, s.egid
      to_u, from_u = s.uid, s.euid
      pwent = s.user_pwent
      env_to_set = s.user_envs
    end

    if completely
      from_g = to_g
      from_u = to_u
      groups = [s.egid] if to_be_root
    end

    if setenv
      restorer[:env] = _save_envs(env_to_set.keys())
    end

    begin
      Process::Sys::seteuid(s.euid) # be root to update gid
      Process::groups = s.groups
      Process::Sys::setregid(from_g, to_g)
      Process::Sys::setreuid(from_u, to_u)
    rescue SystemCallError => e
      _raise_setting_error(to_be_root, e.inspect)
    end
    if Process::Sys::geteuid() != to_u
      _raise_setting_error(to_be_root, "setresuid to #{to_u.to_s} failed")
    end
    if setenv
      _apply_envs(env_to_set)
    end
    if procobj
      begin
        return procobj.call()
      ensure
        $@.delete_if {|x| ERROR_FILTER_REGEXP =~ x } if $@
        begin
          Process::Sys::seteuid(s.euid) # be root to update gid
          Process::Sys::setregid(*restorer[:g])
          Process.groups = restorer[:groups]
          Process::Sys::setreuid(*restorer[:u])
          _apply_envs(restorer[:env])
        rescue => e
          _raise_setting_error(restorer[:to_root], e.inspect)
        end
      end
    end
  end

  public
  # Set effective user/group ID to the privileged user.
  #
  # An optional parameter "setenv:False" will skip setting
  # user-related environmental variables accordingly.
  #
  # It can be used either as an ordinary function, or with a block
  # parameter.  If a block is given, it will revert the UID/GID
  # setting after evaluating the block.
  def temporarily_as_root(setenv:true, &procobj)
    return _set_uids(true, false, setenv:setenv, &procobj)
  end

  # Set effective user/group ID to the ordinary user (the one invoking
  # the script).
  #
  # An optional parameter "setenv:False" will skip setting
  # user-related environmental variables accordingly.
  #
  # It can be used either as an ordinary function, or with a block
  # parameter.  If a block is given, it will revert the UID/GID
  # setting after evaluating the block.
  def temporarily_as_user(setenv:true, &procobj)
    return _set_uids(false, false, setenv:setenv, &procobj)
  end

  # Set both real and effective user/group ID to the privileged user.
  # It is useful when invoking setuid-aware program (e.g. mount(8)) as
  # root.
  #
  # An optional parameter "setenv:False" will skip setting
  # user-related environmental variables accordingly.
  #
  # It can be used either as an ordinary function, or with a block
  # parameter.  If a block is given, it will revert the UID/GID
  # setting after evaluating the block.
  def temporarily_as_real_root(setenv:true, &procobj)
    return _set_uids(true, true, setenv:setenv, &procobj)
  end

  # Set both real and effective user/group ID to an ordinary user,
  # dropping any privilege for all of the future.  After calling this,
  # the process can no longer call temporarily_as_root() or other
  # similar functions.
  #
  # By default, it will set user-related environmental variables
  # (including $HOME) accordingly. An optional parameter
  # "setenv:False" will skip it.
  #
  # It can be used to execute a command for which the calling user can
  # do whatever (e.g. shell, editor or language interpreter), or to
  # perform possibly-dangerous operation (e.g. eval or import) in Ruby
  # code.
  #
  # Passing a block to this function is meaningless, because it cannot
  # revert privileged status anymore.  If really needed, consider
  # using fork() or run_in_subprocess() to separate the unprivileged
  # operations to a child process.
  #
  # See SUIDPrivilegesSettingFatalError for special error handling
  # regarding this function.
  def drop_privileges_forever(setenv:true, &procobj)
    return _set_uids(false, true, setenv:setenv, &procobj)
  end

  ### Running (untrusted) code within subprocess

  OK_EXCEPTIONS_ = [ #:nodoc:
    ArgumentError, EncodingError, FiberError,
    IOError, EOFError, IndexError, KeyError, StopIteration,
    ClosedQueueError, LocalJumpError, Math::DomainError,
    NameError, NoMethodError, RangeError, FloatDomainError,
    RegexpError, RuntimeError, SystemCallError,
    ThreadError, TypeError, ZeroDivisionError]
  begin
    OK_EXCEPTIONS_ << FrozenError
  rescue NameError
    true
  end
  OK_EXCEPTION_NAMES_ = OK_EXCEPTIONS_.map {|k| k.name}  #:nodoc:

  private
  def self._wrap_exception(e)
    klass = e.class
    if e.is_a?(SystemCallError)
      return ['SystemCallError', e.message, e.errno]
    elsif e.is_a?(Math::DomainError)
      return ['DomainError', e.message]
    elsif e.class == StandardError
      return ['StandardError', e.message]
    elsif OK_EXCEPTIONS_.include?(klass)
      return [klass.name, e.message]
    else
      return [nil, e.message, klass.name]
    end
  end

  def self._unwrap_exception(d)
    klassname, message, *additional = d
    if klassname == 'SystemCallError'
      return SystemCallError.new(message, additional[0])
    elsif klassname == 'DomainError'
      return Math::DomainError.new(message)
    elsif klassname == nil
      return WrappedSubprocessError.new("#{message} - #{additional[0]}")
    elsif OK_EXCEPTION_NAMES_.include?(klassname)
      return Object.class.const_get(klassname).new(message)
    else
      return WrappedSubprocessError.new("#{message} - #{klass}")
    end
  end

  public
  # Evaluate the given block within a forked subprocess.
  #
  # Return value of the block is returned to the caller, using the
  # YAML encoding. It means that values of only some simple
  # builtin-types the value can be transferred back to the caller.
  #
  # Exceptions happened in the child is also propargated to the caller.
  # However, non-builtin Exceptions are stringified and wrapped with
  # WrappedSubprocessError.
  #
  # The block MUST return some value or raise an exception within Ruby.
  # If you intend to exec() an external process, consider using
  # spawn_in_privilege() in this module.
  def run_in_subprocess

    require 'yaml'
    raise ValueError.new("no block provided") unless block_given?

    pid, ret, rete, mark = nil
    IO.pipe(binmode: true) do |r, w|
      pid = fork do
        r.close
        ret = nil
        begin
          ret = [yield, nil, true]
        rescue => e
          ret = [nil, _wrap_exception(e), true]
        ensure
          # protect from break inside the block parameter
          YAML.dump(ret, w) if ret
          w.close
          exit!(0)
        end
      end
      # parent
      w.close
      begin
        retr = YAML.safe_load(r.read(nil))
        ret, rete, mark = retr
      rescue Exception => e
        ret, rete, mark = nil, SUIDSubprocessExecutionError::new("run_in_subprocess: decoding failed #{e.inspect}")
      end
    end
    pid_, stat = Process::waitpid2(pid)
    raise SUIDSubprocessExecutionError::new("run_in_subprocess: subprocess exited with error #{stat}") unless stat.success?
    raise SUIDSubprocessExecutionError::new("run_in_subprocess: subprocess did not return value") unless mark
    if rete
      if SUIDSubprocessError === rete
        raise rete
      else
        raise _unwrap_exception(rete)
      end
    else
      return ret
    end
  end

  #### Sub-process invocation

  public
  # Invoke a sub-command, with privileges modified.
  #
  # Parameters:
  #
  # [mode] The first argument is either a symbol `:system` or `:spawn`.
  # *  If `:system` is given, the function will wait for the process
  #    termination and returns the exit status of the called program.
  # *  If `:spawn` is given, the function will return immediately when
  #    invoking the child program is succeeded, and its process ID is
  #    returned.
  #
  # In either case, if it cannot "exec" the child program, it will
  # raise an appropriate OSError instance synchronously.
  # (This behavior is different from the built-in "system" method.)
  #
  # [privilege] The second argument is either
  #
  # * a symbol corresponding to the names of the four
  #   privilege-changing functions provided in this module,
  #   representing the privilege which will be passed to the called
  #   program;
  #
  # * A Method or Proc object, which is called before invoking the
  #   child program (similar to preexec_fn in Python).
  #
  # [args] The rest of arguments will be passed to the "exec" built-in.
  #
  def spawn_in_privilege(mode, privilege, *args, **kwargs)
    raise ArgumentError::new("bad mode #{mode}") unless [:system, :spawn].include?(mode)
    case privilege
    when Method, Proc
      true
    else
      raise ArgumentError::new("bad privilege #{privilege}") unless [
        :temporarily_as_root, :temporarily_as_user, :temporarily_as_real_root,
        :drop_privileges_forever].include?(privilege)
      privilege = self.method(privilege)
    end
    require 'yaml'

    exception_mode = false
    if mode == :system && kwargs.include?(:exception)
      kwargs = kwargs.dup
      exception_mode = kwargs.delete(:exception)
    end
    pid, ret, rete, mark = nil

    
    orig_int = true
    orig_quit = true # value not returned from Signal.trap

    begin
      orig_int = Signal.trap("INT", "SIG_IGN")
      orig_quit = Signal.trap("QUIT", "SIG_IGN")
      
      IO.pipe(binmode: true) do |r, w|
        pid = fork do
          r.close
          Signal.trap("QUIT", orig_quit)
          Signal.trap("INT", orig_int)

          privilege.call()
          begin
            exec(*args, **kwargs)
          rescue SystemCallError => e
            YAML.dump([e.message, e.errno], w)
          rescue => e
            YAML.dump([e.message, nil], w)
          end
          w.close
          exit!(255)
        end
        # parent
        w.close
        retr = YAML.safe_load(r.read(nil))
        if retr
          # error
          pid_, stat = Process::waitpid2(pid)
          m, e = retr[0], retr[1]
          if e
            raise SystemCallError.new(m, e)
          else
            raise SUIDHandlingError.new(m)
          end
        else
          # non-error
          case mode
          when :system
            pid_, stat = Process::waitpid2(pid) # $? set here -> returned to caller
            succeeded = stat.success?
            if exception_mode && ! succeeded
              stat_s = stat.to_s.gsub(/^pid \d+ /, "")
              raise SUIDSubprocessError.new("Command failed with #{stat_s}: #{args.to_s}")
            end
            return succeeded
          when :spawn
            return pid
          end
        end
      end
    ensure
      Signal.trap("QUIT", orig_quit) if orig_quit != true
      Signal.trap("INT", orig_int) if orig_int != true
    end
  end

  # Exposed APIs

  #    adjust visibility
  private_class_method *(SUID_SUDO.methods - Object.methods)
  private_constant *(self.constants.select {|x| x.to_s[-1] == '_'})
  module_function :run_in_subprocess, :suid_emulate,
                  :temporarily_as_root, :temporarily_as_user,
                  :temporarily_as_real_root, :drop_privileges_forever,
                  :spawn_in_privilege, :show_sudo_command_line,
                  :compute_sudo_commane_line_patterns
  require 'forwardable'

  # Module to be imported in main namespace, if you want
  module INCLUDE
    extend Forwardable
    [:run_in_subprocess, :suid_emulate,
     :temporarily_as_root, :temporarily_as_user,
     :temporarily_as_real_root, :drop_privileges_forever,
     :spawn_in_privilege
    ].each {|sym|
      def_delegator(:SUID_SUDO, sym)
      module_function(sym)
    }
    [:SUIDHandlingError, :SUIDSetupError, :SUIDPrivilegesSettingError,
     :SUIDPrivilegesSettingFatalError, :SUIDSubprocessError,
     :SUIDSubprocessExecutionError,
     :WrappedSubprocessError].each {|sym|
      const_set(sym, SUID_SUDO.const_get(sym))
    }
  end
end

if __FILE__ == $0
  p "run suid_sudo_test.rb for testing."
end
