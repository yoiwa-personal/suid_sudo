#!/usr/bin/python3 -I

from __future__ import print_function
import sys
import os
import os.path
#from pathlib import Path, PurePath
import tempfile
import shutil
import time # for sleep
import signal

# Python 2/3 bi-compatibility

_ispython2 = False
if sys.version_info[0] == 2:
    _ispython2 = True
    if sys.version_info < (2, 7, 13):
        raise RuntimeError("too old python2 version")
    else:
        pass
else:
    if sys.version_info < (3, 5, 3):
        raise RuntimeError("too old python3 version")
    else:
        pass

if _ispython2:
    import fcntl

# check system behavior for suid-sudo

sys.path.insert(0, os.path.dirname(__file__))
from common_lib import *

_procexe_linkname = None

def proc_test():
    subtest_start("exist")

    if not os.path.exists("/proc"):
        test_grave("no /proc available?")
    else:
        test_ok()

    subtest_start("mode")

    stat_proc = os.stat("/proc")
    if not (stat_proc.st_uid == 0 and stat_proc.st_gid == 0 and
            stat_proc.st_dev & 0xff00 == 0 and # non-device-backed file system
            stat_proc.st_mode == 0o40555):
        test_grave("/proc system is something bad")
    else:
        test_ok ("/proc is sane, having mode %o" % (stat_proc.st_mode))

    subtest_start("proc_link")

    self_pid = os.getpid()

    global _procexe_linkname
    for l in ("exe", "file"):
        f = "/proc/%d/%s" % (self_pid, l)
        if os.path.exists(f):
            try:
                os.readlink(f)
                # exe link must be available and is a readable link
            except OSError as e:
                test_grave("/proc system is something bad: cannot read link of %s: %r" % (f, e))

        _procexe_linkname = l
        break

    if _procexe_linkname == None:
        test_grave("cannot find way to check the executable name from proc")

    test_ok("Executable name is available on /proc/*/%s" % (_procexe_linkname,))

def procexe_linkname(p):
    return ("/proc/%d/%s" % (p, _procexe_linkname))

def spawn_2level(f):
    (rp1_childpid, wp1_childpid) = os.pipe() # for parent to send child PID
    (rp2_downstream, wp2_downstream) = os.pipe() # to send from grandparent to child
    (rp3_upstream, wp3_upstream) = os.pipe() # to receive from child to grandparent
    pid1 = os.fork()
    if pid1 != 0:
        # grandparent:
        os.close(wp1_childpid)
        os.close(rp2_downstream)
        os.close(wp3_upstream)
        rp1_childpid = os.fdopen(rp1_childpid, "r")
        wp2_downstream = os.fdopen(wp2_downstream, "w")
        rp3_upstream = os.fdopen(rp3_upstream, "r")
        #print ("waiting for parent to send child PID")
        line = rp1_childpid.readline()
        #print ("waiting for parent to send child PID: done")
        pid2 = int(line)
        rp1_childpid.close()
        return wp2_downstream, rp3_upstream, pid1, pid2
    else:
        tempfiles = set()
        (rp4_execsignal, wp4_execsignal) = os.pipe() # to signal child has executed the process
        if _ispython2:
            # O_CLOEXEC flag is set in Python 3 only.
            for p in (rp4_execsignal, wp4_execsignal):
                fcntl.fcntl(p, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        # child:
        os.close(wp2_downstream)
        os.close(rp1_childpid)
        pid2 = os.fork()
        if pid2 != 0:
            try:
                # parent
                os.close(rp2_downstream)
                os.close(rp3_upstream)
                os.close(wp4_execsignal)
                wp1_childpid = os.fdopen(wp1_childpid, "w")
                rp4_execsignal = os.fdopen(rp4_execsignal, "r")
                #print ("waiting for child executing " + f)
                lines = rp4_execsignal.readlines()
                #print ("child executed " + f)
                wp1_childpid.write(str(pid2))
                wp1_childpid.flush()
                #print ("process ID sent to parent")
                wp1_childpid.close()
                #print ("waiting for child")
                try:
                    os.waitpid(pid2, 0)
                except Exception as e:
                    print ("waitpid failed: %r" % (e,), file=sys.stderr)
                    raise e
                #print ("waiting for child done")
                os._exit(0)
            finally:
                os._exit(1)
        else:
            # child
            try:
                os.close(rp4_execsignal)
                os.close(wp1_childpid)
                os.dup2(rp2_downstream, 0) # stdin
                os.dup2(wp3_upstream, 1) # stdout
                os.close(rp2_downstream)
                os.close(wp3_upstream)
                if isinstance(f, str):
                    #print ("executing " + f)
                    # this will close wp4_execsignal
                    os.execvp(f, [f])
                else:
                    #print ("executing " + repr(f), file=sys.stderr)
                    os.close(wp4_execsignal)
                    try:
                        f()
                        os._exit(0)
                    except BaseException as e:
                        print ("waitpid failed: %r" % (e,), file=sys.stderr)
                        raise e
            finally:
                os._exit(1)

def proc_behavior_test():
    tempdir = tempfile.mkdtemp()
    test_debug("--- temporary dir is " + tempdir)
    tempfiles = set()
    try:
        fC = tempdir + "/cat1"
        shutil.copy("/bin/cat", fC)
        tempfiles.add(fC)
        fH = tempdir + "/cat-H"
        os.link(fC, fH)
        tempfiles.add(fH)
        fS = tempdir + "/cat-S"
        os.symlink(fC, fS)
        tempfiles.add(fS)

        subtest_start("test1: usual invocation")

        (wp, rp, pid1, pid2) = spawn_2level(fC)

        #print ((wp, rp, pid1, pid2))
        #os.system("ls -l /proc/%d /proc/%d /proc/%d" % (os.getpid(), pid1, pid2))
        #os.system("ps u %d %d %d" % (os.getpid(), pid1, pid2))
        l = os.readlink(procexe_linkname(pid2))
        if l != fC:
            test_grave("cannot read proc link correctly (%s != %s)" % (l, fC))
        else:
            test_ok("reading child exe: %s, expected %s, OK" % (l, fC))
        wp.close()
        rp.close()
        if (os.waitpid(pid1, 0)[1] != 0):
            test_grave("non-zero exit status")

        # try 2: via symlink

        subtest_start("test2: via symlink")
        (wp, rp, pid1, pid2) = spawn_2level(fS)

        #print ((wp, rp, pid1, pid2))
        #os.system("ls -l /proc/%d /proc/%d /proc/%d" % (os.getpid(), pid1, pid2))
        #os.system("ps u %d %d %d" % (os.getpid(), pid1, pid2))
        l = os.readlink(procexe_linkname(pid2))
        if l == fC:
            test_ok ("reading child exe: %s, expected %s (resolved symlink), OK" % (l, fC))
        elif l == fS:
            test_warn ("warning: symlink readback by proc: %s, expected %s" % (l, fC))
        else:
            test_ng ("cannot read proc link correctly (%s != %s)" % (l, fC))
        wp.close()
        rp.close()
        if (os.waitpid(pid1, 0)[1] != 0):
            test_grave("non-zero exit status")

        # try 3: via removed path

        subtest_start ("test3a: via removed hardlink (linkname)")
        (wp, rp, pid1, pid2) = spawn_2level(fH)

        #print ((wp, rp, pid1, pid2))
        #os.system("ls -l /proc/%d/exe /proc/%d/exe /proc/%d/exe" % (os.getpid(), pid1, pid2))
        #os.system("ps u %d %d %d" % (os.getpid(), pid1, pid2))
        os.unlink(fH)
        tempfiles.discard(fH)
        #os.system("ls -l /proc/%d/exe /proc/%d/exe /proc/%d/exe" % (os.getpid(), pid1, pid2))

        l = os.readlink(procexe_linkname(pid2))
        if l == fH or l == (fH + " (deleted)"):
            test_ok ("reading child exe: %s, expected %s, OK" % (l, fH))
        else:
            test_warn ("warning: unknown child exe readback for removed files: %s, expected %s" % (l, fH))

        subtest_start ("test3b: via removed hardlink (stat)")

        s1 = os.stat(procexe_linkname(pid2))
        s2 = os.stat(fC)
        if os.path.samestat(s1, s2):
            test_ok ("checking stat for removed child exe: (%d, %d) == (%d, %d), OK" % (s1.st_ino, s1.st_dev, s2.st_ino, s2.st_dev))
        else:
            test_ng ("cannot stat proc link correctly (%s != %s)" % (s1, s2))
        wp.close()
        rp.close()
        if (os.waitpid(pid1, 0)[1] != 0):
            test_grave("non-zero exit status")

        # try 4: parent exited earlier

        def _():
            #print("waiting from grandparent", file=sys.stderr)
            sys.stdin.readlines()
            ppid = None
            xtimes = 0
            for xtimes in range(1,10):
                ppid = os.getppid()
                test_debug(">>> %d (%d)" % (ppid, xtimes))
                if ppid == 1:
                    test_debug (">>> ppid change check in trial #%d; OK" % (xtimes,))
                    break
                time.sleep(0.1)
            print(ppid)
            sys.stdout.flush()

        subtest_start ("test4a: parent exit earlier (pid)")
        (wp, rp, pid1, pid2) = spawn_2level(_)

        #print ((wp, rp, pid1, pid2))
    #    os.system("ls -l /proc/%d/exe /proc/%d/exe /proc/%d/exe" % (os.getpid(), pid1, pid2))
        ok = False
        try:
            os.readlink("/proc/%d/exe" % pid1)
        except OSError:
            test_grave ("cannot read symlink before killing; why?")
        os.kill(pid1, signal.SIGTERM)
        xtimes = 0
        for xtimes in range(1,10):
            try:
                test_debug (">>> %s (%d)" % (os.readlink("/proc/%d/exe" % pid1), xtimes))
            except OSError:
                test_debug (">>> non-exists check in trial #%d; OK killed!" % (xtimes,))
                ok = True
                break
            time.sleep(0.1)

    #    os.system("ls -l /proc/%d/exe /proc/%d/exe /proc/%d/exe" % (os.getpid(), pid1, pid2))

        if not ok:
            test_grave("failed to kill parent?")

        wp.close()
        lines = rp.readlines()
        if len(lines) == 1:
            s = lines[0]
            if s == "1\n":
                test_ok("zombie parent process ID readback as 1; expected; OK")
            elif s == ("%d\n" % pid1):
                test_warn ("warning: zombie parent process ID readback as original; unexpected (expected = 1)")
            else:
                test_ng ("unknown readback from grand child: %r (expected \"1\\n\")" % (s,))
        else:
            test_ng ("unknown readback from grand child: %r  (expected [\"1\\n\"])" % (lines,))
        rp.close()
        if os.path.exists("/proc/%d" % pid1):
            test_debug("zombie is still existing before waitpid; OK")
            pass
        else:
            test_grave("zombie is not alive; why?")
        r = os.waitpid(pid1, 0)[1]
        #print ("parent killed: ", r)
        if r != signal.SIGTERM: test_grave("process result failed: %d")

    finally:
        for f in tempfiles:
            test_debug ("--- removing " + f)
            os.unlink(f)
        test_debug ("--- removing " + tempdir)
        os.rmdir(tempdir)

if __name__ == '__main__':
    do_test(proc_test)
    do_test(proc_behavior_test)
    test_summary()
