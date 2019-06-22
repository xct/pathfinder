#!/usr/bin/env python

import angr
import time
import sys


def main():
    file = False
    cmd = sys.argv[1]
    if "@@" in cmd:
        print "[+] File provided"
        file = True
        cmd = cmd.replace("@@", "symfile")
        p = angr.Project(
            cmd.split(" ")[0], load_options={
                'auto_load_libs': False})
    else:
        p = angr.Project(cmd, load_options={'auto_load_libs': False})

    if file:
        files = dict()
        files["symfile"] = angr.storage.file.SimFile("symfile", "r", size=100)
        args = cmd.split(" ")
        st = p.factory.full_init_state(args=args, fs=files)
    else:
        st = p.factory.full_init_state()
    sm = p.factory.simgr(st)
    print sm
    start = time.time()
    while len(sm.active) != 0:
        sm.step()
        print sm.active
    end = time.time()
    print sm
    print "[+] Execution took " + str(round(end - start, 2)) + " seconds"
    for s in sm.deadended:
        print "\tStdin: " + str(repr(s.posix.dumps(0)))
        print "\tStdout: " + str(s.posix.dumps(1))
        print "\tStderr: " + str(s.posix.dumps(2))


if __name__ == '__main__':
    print main()
