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
             pass_env = ["TESTVAR"], showcmd_opts=True)

cmd = sys.argv[1] if len(sys.argv) >= 2 else "0"

if cmd == "p":
    print ("\nbe USER ")
    temporarily_as_user()
    print_ids()
    for k in os.environ:
        print ("%s=%s" % (k, os.environ[k]))

    print ("\nbe ROOT")
    temporarily_as_root()
    print_ids()
    for k in os.environ:
        print ("%s=%s" % (k, os.environ[k]))

    print ("\nbe REAL_ROOT")
    temporarily_as_real_root()
    print_ids()
    for k in os.environ:
        print ("%s=%s" % (k, os.environ[k]))

    print ("\nbe USER")
    temporarily_as_user()
    print_ids()
    for k in os.environ:
        print ("%s=%s" % (k, os.environ[k]))

    print ("\ndrop to USER")
    drop_privileges_forever()
    print_ids()
    for k in os.environ:
        print ("%s=%s" % (k, os.environ[k]))

    try:
        print ("\nbe ROOT")
        temporarily_as_root()
        print_ids()
        print ("SHOULD FAILED!")
        raise
    except (SUIDPrivilegesSettingError, OSError) as e:
        print("...good to be failed: %r" % e)

elif cmd == "s":
    print (_SuidStatus._status)

elif cmd == "pw":
    print ("\nbe USER ")
    with temporarily_as_user():
        print_ids()
        for k in os.environ:
            print ("%s=%s" % (k, os.environ[k]))

    print ("\nreturned ")
    print_ids()
    for k in os.environ:
        print ("%s=%s" % (k, os.environ[k]))

    print ("\nbe ROOT")
    with temporarily_as_root():
        print_ids()
        for k in os.environ:
            print ("%s=%s" % (k, os.environ[k]))

    print ("\nbe REAL_ROOT")
    with temporarily_as_real_root():
        print_ids()
        for k in os.environ:
            print ("%s=%s" % (k, os.environ[k]))

    print ("\nbe USER")
    with temporarily_as_user():
        print_ids()
        for k in os.environ:
            print ("%s=%s" % (k, os.environ[k]))

    print ("\ndrop to USER")
    try:
        with drop_privileges_forever():
            print_ids()
            for k in os.environ:
                print ("%s=%s" % (k, os.environ[k]))
        print ("SHOULD FAILED!")
        raise
    except (SUIDPrivilegesSettingError, OSError) as e:
        print("...good to be failed: %r" % e)

else:
    print("unknown test command")
