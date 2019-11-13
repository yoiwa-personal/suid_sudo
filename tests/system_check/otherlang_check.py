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

def extlang_test(lang, cmd):

    subtest_start("path_examine")

    l = subprocess.check_output(cmd)
    if not isinstance(l, str):
        l = l.decode('utf-8')
    l = json.loads(l)
    test_debug(repr(l))

    test_ok()

    libpath, exepath = l

    subtest_start("exe_safety")
    ap = check_affected_by(exepath, noexistok=True)
    if len(ap):
        test_ng ("%s path %s is affected by some users" % (lang, e,))
    else:
        test_ok ("%s seems to be only affected by root. OK." % (exepath,))

    subtest_start("libpath_safety")
    warn = False
    for e in libpath:
        ap = check_affected_by(e, noexistok=True)
        if len(ap):
            test_debug ("%s library path %s is affected by some users" % (lang, e,))
            warn = True
    if warn:
        test_warn ("%s library is affected by the some users: check it." % (lang,))
    else:
        test_ok ("%s library path seems to be only affected by root. OK." % (lang,))

def ruby_test():
    for e in [x for x in os.environ.keys() if x.startswith("RUBY")]:
        del os.environ[e]
    extlang_test("ruby", ['ruby', '-e', 'require "json"; print JSON.dump([$:, File.readlink("/proc/self/exe")])'])

def perl_test():
    for e in [x for x in os.environ.keys() if x.startswith("PERL")]:
        del os.environ[e]
    extlang_test("perl", ['perl', '-MJSON::PP', '-MConfig', '-e', 'print encode_json([\@INC, $Config{perlpath}])'])

if __name__ == '__main__':
    do_test(ruby_test)
    do_test(perl_test)
    test_summary()
