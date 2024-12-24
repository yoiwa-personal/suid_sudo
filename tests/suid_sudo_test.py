#!/usr/bin/python3 -I
if __name__ != '__main__': raise RuntimeError("Should not be imported.")

import sys
import os.path
sys.path.insert(0, os.path.dirname(sys.argv[0]) + "/..")
import suid_sudo
from suid_sudo import *
_SuidStatus = suid_sudo._SuidStatus

import os
def print_ids():
    print (os.getresuid(), os.getresgid(), os.getgroups())

suid_emulate(sudo_wrap=True, inherit_flags=True, realroot_ok=True, nonsudo_ok=True,
             pass_env = [], showcmd_opts=True)

cmd = sys.argv[1] if len(sys.argv) >= 2 else "0"

if cmd == "0":
    print (sys.version)
    print_ids()
    print (sys.argv)
    print (_SuidStatus._status)
    for k in os.environ:
        print ("%s=%s" % (k, os.environ[k]))

elif cmd == "1":
    drop_privileges_forever()
    print (sys.version)
    print_ids()
    print (sys.argv)
    print (_SuidStatus._status)
    for k in os.environ:
        print ("%s=%s" % (k, os.environ[k]))

elif cmd == "setuid":
    print ("be USER ")
    temporarily_as_user()
    print_ids()

    print ("be ROOT")
    temporarily_as_root()
    print_ids()

    print ("be REAL_ROOT")
    temporarily_as_real_root()
    print_ids()

    print ("be USER")
    temporarily_as_user()
    print_ids()

    print ("drop to USER")
    drop_privileges_forever()
    print_ids()

    try:
        print ("be ROOT")
        temporarily_as_root()
        print_ids()
        print ("SHOULD FAILED!")
        raise
    except (SUIDPrivilegesSettingError, OSError) as e:
        print("...good to be failed: %r" % e)

elif cmd == "temp":
    print("temporary_in_user")
    with temporarily_as_user():
        print_ids()

    print ("returned")
    print_ids()

elif cmd == "subcall":
    print ("subprocess as real user")
    import subprocess
    subprocess.call(args=["/usr/bin/id"],
                    preexec_fn=drop_privileges_forever)

    print ("returned")
    print_ids()

elif cmd == "subproc":
    print ("call_in_subprocess")
    def _():
        drop_privileges_forever()
        return (os.getresuid(), os.getresgid(), os.getgroups())
    print(call_in_subprocess(_))

    print ("parent")
    print_ids()

    print ("call_in_subprocess_2")
    @call_in_subprocess
    def rval():
        drop_privileges_forever()
        return (os.getresuid(), os.getresgid(), os.getgroups())
    print(rval)

    print ("parent")
    print_ids()

elif cmd == "subproc_fd":
    print ("call_in_subprocess")
    def _():
        os.execlp("ls", "ls", "-lL", "/proc/self/fd")
        # you should not see a pipe in this directory entry
    try:
        print(call_in_subprocess(_))
    except SUIDSubprocessError as e:
        print("OK: exception %r" % (e,))

elif cmd == "subproc_error1":
    print ("call_in_subprocess")
    def _():
        drop_privileges_forever()
        ([1,2])[2]
        return ("BAD", os.getresuid(), os.getresgid(), os.getgroups())
    try:
        print(call_in_subprocess(_))
    except IndexError as e:
        print("OK: exception %r" % (e,))

elif cmd == "subproc_error2":
    print ("call_in_subprocess")
    def _():
        os._exit(255)
    try:
        print(call_in_subprocess(_))
    except SUIDSubprocessExecutionError as e:
        print("OK: exception %r" % (e,))

elif cmd == "subproc_error2_1":
    print ("call_in_subprocess")
    def _():
        exit(100)
    try:
        print(call_in_subprocess(_))
    except WrappedSubprocessError as e:
        # SystemExit is wrapped (otherwise, the parent terminates!)
        print("OK: exception %r" % (e,))

elif cmd == "subproc_error3":
    print ("call_in_subprocess")
    def _():
        os.execl("/usr/bin/id", "/usr/bin/id")
    try:
        print(call_in_subprocess(_))
    except SUIDSubprocessExecutionError as e:
        print("OK: exception %r" % (e,))

elif cmd == "subproc_error4":
    print ("call_in_subprocess")
    def _():
        os.execl("/dev/null", "/dev/null")
    try:
        print(call_in_subprocess(_))
    except OSError as e:
        print("OK: exception %r" % (e,))

else:
    print("unknown test command")
