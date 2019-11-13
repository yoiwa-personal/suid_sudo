#!/usr/bin/python3 -I
from __future__ import print_function # python2

import sys
import os
import os.path
import pwd
import grp
import tempfile
import shutil

# check system behavior for suid-sudo

if sys.version_info[0] == 2:
    _ispython2 = True
    if sys.version_info < (2, 7, 13):
        raise RuntimeError("too old python2 version")
    else:
        pass
else:
    _ispython2 = False
    if sys.version_info < (3, 5, 3):
        raise RuntimeError("too old python3 version")
    else:
        pass

if _ispython2:
    import fcntl

global_affected_paths = {}
group_cache = {}
user_cache = {}
trusted_groups = set()
trusted_users = set()

def add_trusted_user(u):
    uid = None
    try:
        uid = int(u)
    except ValueError:
        try:
            uid = pwd.getpwnam(g).pw_uid
        except KeyError:
            raise KeyError("bad user %s for a trusted group" % (u,))
    trusted_users.add(uid)

def add_trusted_group(g):
    gid = None
    try:
        gid = int(g)
    except ValueError:
        try:
            gid = grp.getgrnam(g).gr_gid
        except KeyError:
            raise KeyError("bad group %s for a trusted group" % (g,))
    trusted_groups.add(gid)

def add_affected_by(ap, tag, path, isuser, elem, replace=False):
    if isuser:
        if elem in trusted_users:
            return None
        if elem in user_cache:
            name = user_cache[elem]
        else:
            try:
                rname = "user " + pwd.getpwuid(elem).pw_name
            except KeyError:
                rname = "user " + str(elem)
            user_cache[elem] = rname
            name = rname
    else:
        if elem in trusted_groups:
            return None
        if elem in group_cache:
            name = group_cache[elem]
        else:
            try:
                rname = "group " + grp.getgrgid(elem).gr_name
            except KeyError:
                rname = "group " + str(elem)
            group_cache[elem] = rname
            name = rname

    p = str(path)
    for a in (ap, global_affected_paths):
        l = a.get(name, None)
        if l is None: l = set()
        if replace:
            l = set(p)
        else:
            l.add(p)
        a[name] = l

def check_affected_by(path, norecur=None, noexistok=False):
    ap = (norecur or {})
#    p = Path(path)
    p = path
    while p:
        if os.path.exists(p): #p.exists():
            s = os.stat(p) #p.stat()
            perm = s.st_mode
            if perm & 2 != 0:
                add_affected_by(ap, path, p, true, "ANYONE", True)
            else:
                if perm & 0o20 != 0 and s.st_gid != 0:
                    add_affected_by(ap, path, p, False, s.st_gid)
                elif s.st_uid != 0:
                    add_affected_by(ap, path, p, True, s.st_uid)
        else:
            if noexistok:
                pass
            else:
                raise RuntimeError("%s not exists" % (str(p)))

        pp = p
        p = os.path.dirname(p) #p.parent
        if p == pp: break

    abspath = os.path.abspath(path)
    if abspath != path:
        if norecur:
            raise "affected_by: norecur with non-absolute path"
        else:
            check_affected_by(abspath, ap, noexistok=noexistok)
    return ap

class S: pass

g = S()
g.test_cnt = 0
g.ok_cnt = 0
g.warn_cnt = 0
g.ng_cnt = 0
g.running_test = ""
g.running_subtest = ""
g.previous_subtest = ""
g.errored_tests = set()
g.warned_tests = set()

def do_test(f, s = ""):
    if s == "":
        s = (f.__name__ or "?")
        if s.startswith("test_"):
            s = s[5:]
        elif s.endswith("_test"):
            s = s[0:-5]
    saved = (g.ok_cnt, g.warn_cnt, g.ng_cnt, g.test_cnt)
    try:
        g.running_test = s
        print ("---- Performing test group %s..." % (s,), file=sys.stderr)
        f()
    except RuntimeError as e:
        test_grave("runtime error caused: %r" % repr(e))
    finally:
        g.running_test = ""
    print ("---- ... Done test %s (ok %d, warning %d, ng %d)." % (
        s, g.ok_cnt - saved[0], g.warn_cnt - saved[1], g.ng_cnt - saved[2]),
           file=sys.stderr)

def subtest_start(s):
    if (g.running_test == ""): raise ValueError("subtest_start")
    if (g.running_subtest != ""): raise ValueError("subtest_start")
    print ("------ subtest %s_%s..." % (g.running_test, s), file=sys.stderr)
    g.running_subtest = g.previous_subtest = s

def test_ok(msg = None):
    g.test_cnt += 1
    g.ok_cnt += 1
    if msg:
        msg = " (" + msg + ")"
    else:
        msg = ""
    print ("   ok  Test %s_%s%s" % (g.running_test, g.running_subtest, msg), file=sys.stderr)
    g.running_subtest = ""

def test_warn(msg = None):
    g.test_cnt += 1
    g.warn_cnt += 1
    if msg:
        msg = ": " + msg
    else:
        msg = " have warnings"
    print ("[WARN] Test %s_%s%s" % (g.running_test, g.running_subtest, msg), file=sys.stderr)
    g.warned_tests.add("%s_%s" % (g.running_test, g.running_subtest))
    g.running_subtest = ""

def test_ng(msg = None):
    g.test_cnt += 1
    g.ng_cnt += 1
    if msg:
        msg = ": " + msg
    else:
        msg = " have error"
    print ("[ NG ] Test %s_%s%s" % (g.running_test, g.running_subtest, msg), file=sys.stderr)
    g.errored_tests.add("%s_%s" % (g.running_test, g.running_subtest))
    g.running_subtest = ""

def test_grave(msg = None):
    g.ng_cnt += 1
    st = ""
    if g.running_subtest == "":
        st = g.previous_subtest
    else:
        g.test_cnt += 1
        st = g.running_subtest
    if msg:
        msg = ": " + msg
    else:
        msg = " have fatal error"
    print ("[FATAL] Test %s_%s%s" % (g.running_test, st, msg), file=sys.stderr)
    g.errored_tests.add("%s_%s" % (g.running_test, st))
    g.running_subtest = ""
    test_summary()
    exit(1)

def test_debug(msg):
    print ("    >> %s" % (msg,), file=sys.stderr)

def test_summary():
    print ("""
=========================================
  Test summary
=========================================

    performed %3d tests:

         ok   %3d tests
    warning   %3d tests
         NG   %3d tests

""" % (g.test_cnt, g.ok_cnt, g.warn_cnt, g.ng_cnt))

    if len(g.errored_tests):
        print("""Tests with errors:\n""")
        for test in sorted(g.errored_tests):
                print ("    %s" % (test, ))
        print ("")

    if len(g.warned_tests):
        print("""Tests with warnings:\n""")
        for test in sorted(g.warned_tests):
                print ("    %s" % (test, ))
        print ("")

    if len(global_affected_paths):
        print ("""The following paths are possibly danger: please check it.
(if shown user is trusted, it is OK.)

""")
        for user in sorted(global_affected_paths.keys()):
            print ("for %s:" % (user, ))
            for path in sorted(global_affected_paths[user]):
                print ("    %s" % (path, ))
    print ("""
=========================================""")

__all__ = ["check_affected_by", "global_affected_paths", "_ispython2",
           "do_test", "subtest_start", "test_ok", "test_warn", "test_ng", "test_grave", "test_summary", "test_debug"]

