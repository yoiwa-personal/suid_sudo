#!/usr/bin/python3 -I

import sys, os, re

original_sys_path = sys.path[0:]
sys.path.insert(0, os.path.dirname(__file__))
import common_lib
from common_lib import *
import proc_check
import python_check
import otherlang_check
sys.path[0:] = original_sys_path

import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Check behavior of underlying system to be used with suid_sudo')
    parser.add_argument('--trust-group', '-G', metavar='GROUP', action='append', help='trust a given system group (name or gid)')
    parser.add_argument('--trust-user', '-U', metavar='USER', action='append', help='trust a given system user (name or uid)')
    o = parser.parse_args()

    print(repr(o))
    if o.trust_group:
        for gg in o.trust_group:
            for g in re.split(r'[ \t,]+', gg):
                common_lib.add_trusted_group(g)

    if o.trust_user:
        for uu in o.trust_user:
            for u in re.split(r'[ \t,]+', uu):
                common_lib.add_trusted_user(u)

    do_test(proc_check.proc_test)
    do_test(proc_check.proc_behavior_test)
    do_test(python_check.sudo_test)
    do_test(python_check.python_test)
    do_test(otherlang_check.ruby_test)
    do_test(otherlang_check.perl_test)
    test_summary()
