#!/usr/bin/python3 -I

import sys
import os
import os.path
import json
import subprocess

# check system behavior for suid-sudo

original_sys_path = sys.path[0:]
sys.path.insert(0, os.path.dirname(__file__))
import common_lib
from common_lib import *
sys.path[0:] = original_sys_path

def sudo_test():
    subtest_start("location")

    found = False
    sudo = None
    for sudo in ("/bin/sudo", "/usr/bin/sudo"):
        if os.path.exists(sudo):
            found = True
            break

    if not found:
        test_grave("can't find system sudo")
        return

    test_ok ("sudo is found in %s" % (sudo,))

    subtest_start("permission")

    perm = os.stat(sudo).st_mode
    if ((perm | 0o644) != 0o104755): # lacking read / root-write priv. is OK
        test_ng("%s has bad mode %o" % (sudo, perm))
    else:
        test_ok ("sudo has mode %o (expected 104755), OK" % (perm,))

    subtest_start("path_safety")

    ap = check_affected_by(sudo)

    if len(ap) != 0:
        test_ng ("sudo is affected by the following users: bad.")
        print (repr(ap))
        exit(1)
        # SUDO is critical.
    else:
        test_ok ("sudo seems to be only affected by root. OK.")

def python_test():
    execname = sys.executable
    test_debug ("python is available in %s" % (execname,))

    subtest_start("path_safety")

    ap = check_affected_by(execname)

    if len(ap) != 0:
        test_warn ("python is affected by the some users: check it. " + repr(ap.keys()))
    else:
        test_ok ("python seems to be only affected by root. OK.")

    subtest_start("test_setting_cmdline")
    if (sys.flags.no_user_site or sys.flags.no_site) and sys.flags.ignore_environment:
        test_ok()
    else:
        test_warn("warning: python is not invoked by -sE option. It is not expectation of the suid_sudo library. results might be imprecise.")

    subtest_start("libpath_safety")

    sys_path = original_sys_path
    print(repr(sys_path))
    warn = False
    self_path = os.path.dirname(os.path.abspath(sys.argv[0]))
    while sys_path[0] == '' or (os.path.exists(sys_path[0]) and os.path.samefile(sys_path[0], self_path)):
        test_debug("info: removing %r from library path check (for python2). ensure it is OK." % (sys_path[0],))
        del sys_path[0]
    for e in sys_path:
        ap = check_affected_by(e, noexistok=True)
        if len(ap):
            test_debug ("python library path %s is affected by some users" % (e,))
            warn = True
    if warn:
        test_warn ("python library is affected by the some users: check it.")
    else:
        test_ok()

if __name__ == '__main__':
    do_test(sudo_test)
    do_test(python_test)
    test_summary()
