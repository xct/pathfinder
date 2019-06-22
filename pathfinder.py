import angr
import fuzzer
import pathfinder
import random
import sys
import timeout
import utils


class Pathfinder():

    def __init__(self, Fuzzer, verbose=False):
        # back link to fuzzer to access config items and update bitmap etc.
        self.fuzzer = Fuzzer
        self.sc = "shellcode"
        self.depth_limit = int(self.fuzzer.depth_limit)
        if verbose:
            self.msg = utils.msg
        else:
            self.msg = utils.dummy

    def show_stateinfo(self, s):
        self.msg("\tStdin: " + str(repr(s.posix.dumps(0))))
        self.msg("\tStdout: " + str(s.posix.dumps(1)))
        self.msg("\tStderr: " + str(s.posix.dumps(2)))
        #print s.fs._files
        for filename in s.fs._files.keys():
            try:
                self.msg(
                    "\t" +
                    str(filename) +
                    ": " +
                    repr(
                        s.posix.dump_file_by_path(filename)))
            except BaseException:
                pass

    def apply_choice(self, sm, choice, unknown, ignore=[], safe_delayed=True):
        if choice is None or choice in ignore:
            self.msg("[-] Invalid choice made.")
            return
        self.msg("[?] From " + str(hex(sm.active[0].history.bbl_addrs[-1])
                                   ).rstrip("L") + " to " + str(sm.active) + " --> Choosing " + str(choice))
        for s in sm.active:
            if s != choice and s not in ignore:
                if s in unknown:
                    s.globals['level'] = 0
                    self.fuzzer.new.push(s)
                    sm.delayed_new.append(s)
                else:
                    if 'level' not in s.globals.keys():
                        s.globals['level'] = 1
                    s.globals['level'] += 1
                    #print s.globals['level']
                    if safe_delayed:
                        if s.globals['level'] < self.depth_limit:
                            sm.delayed.append(s)
        del sm.active[:]
        sm.active.append(choice)

    def create_sm(self, state, extra_stashes):
        sm = self.p.factory.simgr(state, save_unconstrained=True)
        for stash in extra_stashes:
            sm.stashes[stash] = []
        return sm

    def is_register_symbolic(self, state, register):
        for i in range(state.arch.bits):
            if not state.se.symbolic(register[i]):
                return False
        return True

    def exploit(self, state):
        ''' really simple implementation, just to showcase possibility
        this just generates a poc that sets eip to '\x41', if we want to go further we need to find jmp esp and so on
        '''
        if self.is_register_symbolic(state, state.ip):
            self.msg("[+] Instruction Pointer completely symbolic")
            state.add_constraints(state.ip == state.se.BVV('\x41' * 8, 64))
            buff = state.posix.dumps(0)
            buff = buff.rstrip(chr(0))
            offset = len(buff) - 8
            if offset > 0:
                self.msg("[+] Offset is " + str(offset))
                # need a jmp esp to exploit this, we could integrate pwntools
                # to find it
                exploit = ('\x41' * 8).rjust(offset, '\x90')
                exploit += self.sc
                self.msg("[+] Done, writing POC")
                self.fuzzer.write_outputs([exploit,], prefix="exploit", path=self.fuzzer.exploit_dir)
            else:
                self.msg("[-] Not exploitable")


class Tracer(pathfinder.Pathfinder):

    def __init__(self, fuzzer, verbose=False):
        Pathfinder.__init__(self, fuzzer, verbose)

    def trace_concrete(self, args, traces, etraces, inputs):
        ''' takes the dynamorio trace and follows it as closely as possible within angr with preconstrained input
        '''
        pf_traces = dict()
        del self.fuzzer.simfiles[:]
        for ei, etrace in enumerate(etraces):  # run for every provided input
            cur_input = list(inputs.items())[ei]

            if self.fuzzer.stdin:
                stdin_simfile = angr.storage.file.SimFile(
                    'stdin', content=cur_input[1])
                state = self.fuzzer.p.factory.full_init_state(
                    args=args[:-1], stdin=stdin_simfile)
            else:
                files = dict()
                files[self.fuzzer.sym_file_name] = angr.storage.file.SimFile(
                    self.fuzzer.sym_file_name, content=cur_input[1])
                stdin_simfile = angr.storage.file.SimFile('stdin', size=0)
                state = self.fuzzer.p.factory.full_init_state(
                    args=args, stdin=stdin_simfile)
                state.fs.insert(self.fuzzer.sym_file_name,
                                files[self.fuzzer.sym_file_name])
            state.options.add("UNICORN")
            trace = []

            sm = self.fuzzer.create_sm(state, ["delayed", "delayed_new"])
            ptr = 0
            while len(sm.active) > 0:
                self.msg(sm.active)
                if len(sm.active) > 1:
                    states = sm.active
                    edges = dict()  # {encoded_edge, state}
                    for s in states:
                        last = self.fuzzer.to_map(s.history.bbl_addrs[-1])
                        cur = self.fuzzer.to_map(s.addr)
                        e = last ^ cur
                        edges[e] = s
                    index = -1
                    found = None
                    choice = None
                    for i in range(ptr, len(etrace), 1):
                        for e in edges.keys():
                            if e == etrace[i]:
                                found = e
                                index = i
                                break
                        if found is not None:
                            break
                    if found:
                        self.msg("[+] Found edge at " + str(index))
                        choice = edges[found]
                        if found in self.fuzzer.bitmap.keys():
                            self.fuzzer.bitmap[found] += 1
                        else:
                            # these are added because we take them in the
                            # concrete trace
                            self.fuzzer.bitmap[found] = 1
                        ptr = index + 1
                        self.msg(str(s.posix.dumps(0)))
                        # if we get "forks" with full constrained input, they
                        # have to be blacklisted as they are artifacts of some
                        # sort
                        ignore = []
                        for e in edges.keys():
                            if e != found:
                                s = edges[e]
                                ignore.append(s)
                                # self.fuzzer.blacklist.append(e)
                        # we choose to not safe new states here, as we want to
                        # do that in the symbolic trace pass
                        self.apply_choice(sm, choice, [], ignore=ignore)
                    else:
                        # catchup mode ?
                        # this is just a temporary solution to make it work on
                        # more targets
                        self.msg(
                            "[-] Problem in trace, resorting to random path selection")
                        choice = random.choice(sm.active)
                        # we choose to not safe new states here, as we want to
                        # do that in the symbolic trace pass
                        self.apply_choice(sm, choice, [])
                trace.append(sm.active[0].addr)
                try:
                    with timeout.timeout(self.fuzzer.timeout):
                        sm.step()
                except BaseException:
                    self.msg("[-] Error in concrete trace..")
                    del sm.active[:]
                    break
            self.msg("Concrete trace walked for " + str(cur_input[0]))
            self.msg(sm)
            pf_traces[cur_input[0]] = trace
            if len(sm.deadended) == 1:
                self.show_stateinfo(sm.deadended[-1])
            else:
                self.msg("[+] Error in initial trace - Skipping")
                # self.show_stateinfo(sm.errored[-1].state)
                #print sm.errored[-1]
                # sys.exit(0)
                # utils.yes("")
                # dump pruned or errored states ? pruned could be interesting..
        return pf_traces

    def trace_symbolic(self, args, traces, inputs):
        ''' takes the concrete angr trace and runs it symbolically, saving all new discovered states
        '''
        del self.fuzzer.simfiles[:]
        # longest input file is taken as reference length
        symlen = len(max(inputs.values(), key=len))
        for ei, trace in enumerate(traces):
            cur_input = list(inputs.items())[ei]
            if self.fuzzer.stdin:
                stdin_simfile = angr.storage.file.SimFile('stdin', size=symlen)
                state = self.fuzzer.p.factory.full_init_state(
                    args=args[:-1], stdin=stdin_simfile)
            else:
                stdin_simfile = angr.storage.file.SimFile('stdin', size=0)
                simfile = angr.storage.file.SimFile(
                    self.fuzzer.sym_file_name, size=symlen)
                state = self.fuzzer.p.factory.full_init_state(
                    args=args, stdin=stdin_simfile)
                state.fs.insert(self.fuzzer.sym_file_name, simfile)
            state.options.add("UNICORN")
            trace = []
            cur_input = list(inputs.items())[ei]
            trace = traces[cur_input[0]]
            sm = self.fuzzer.create_sm(
                state, ["delayed", "delayed_new", "crashed", "timeouted"])
            ptr = 0
            length = 0
            while True:
                self.msg(sm.active)
                if len(
                        sm.active) == 0:  # there should be at least one finished path after inital tracing
                    if len(sm.deadended) > 0:
                        s = sm.deadended[-1]
                        self.msg(
                            "[+] Symbolic trace walked  (" + str(sm) + ")")
                        self.show_stateinfo(s)
                        length = s.history.block_count
                        break
                    elif len(sm.unconstrained) > 0:
                        s = sm.unconstrained[-1]
                        self.msg(
                            "[-] Symbolic trace errored  (" + str(sm) + ")")
                        self.show_stateinfo(s)
                        self.msg("[+] Trying to generate exploit...")
                        self.exploit(s)
                        length = s.history.block_count
                        break
                    else:
                        self.msg(
                            "[-] Symbolic trace errored  (" + str(sm) + ")")
                        if len(sm.errored) > 0:
                            s = sm.errored.pop()
                            print(s)
                        break
                elif len(sm.active) == 1:
                    pass
                else:  # more than one state
                    choice = None
                    for s in sm.active:
                        if ptr < len(trace):
                            # this could fail if divergence between trace and
                            # actual execution
                            if s.addr == trace[ptr]:
                                choice = s
                    if choice is None:
                        self.msg(
                            "Problem in trace, resorting to random path selection")
                        choice = random.choice(sm.active)
                    unknown = []
                    ignore = []
                    for s in sm.active:
                        if s != choice:
                            # this is a candidate for a new state, however it
                            # could also be known from the bitmap (which
                            # inreturn is context insensitive, so there is no
                            # right or wrong here)
                            last = self.fuzzer.to_map(s.history.bbl_addrs[-1])
                            cur = self.fuzzer.to_map(s.addr)
                            e = last ^ cur
                            if e not in self.fuzzer.blacklist:
                                if e not in self.fuzzer.bitmap:
                                    self.fuzzer.notify("new")
                                    self.fuzzer.bitmap[e] = 1
                                    unknown.append(s)
                            else:
                                ignore.append(s)
                    self.apply_choice(sm, choice, unknown, ignore=ignore)
                try:
                    with timeout.timeout(self.fuzzer.timeout):
                        sm.step()
                except BaseException:
                    self.msg("[-] Error in symbolic trace..")
                    del sm.active[:]
                    break
                ptr += 1
        return length


class Explorer(pathfinder.Pathfinder):

    def __init__(self, fuzzer, verbose):
        Pathfinder.__init__(self, fuzzer, verbose)

    def run(self, state, safe_delayed=True, limit=10000):
        ''' run with fully symbolic input and force the decisions from the pf_trace, afterwards explore symbolic leafs
        '''
        sm = self.fuzzer.create_sm(
            state, ["delayed", "delayed_new", "crashed", "timeouted"])
        length = sm.active[0].history.block_count  # limit length
        while True:
            length += 1
            self.msg(str(sm.active) + " (" + str(length) + "/" + str(limit) + ")")
            if len(sm.active) == 0:  # no more states left, do something about it
                if len(sm.unconstrained) > 0:
                    # handle unconstrained states
                    s = sm.unconstrained.pop()
                    self.msg(
                        "[+] Found Bounds Checking Error (" + str(sm) + ")")
                    self.show_stateinfo(s)
                    self.msg("[+] Trying to generate exploit...")
                    self.fuzzer.dump_maybe(s)
                    self.exploit(s)
                if len(sm.deadended) > 0:
                    # handle normal deadended states
                    # delete deadended states, they only consume memory without
                    # giving any benefit
                    s = sm.deadended.pop()
                    self.msg("[+] Path completed (" + str(sm) + ")")
                    self.show_stateinfo(s)
                    self.fuzzer.dump_maybe(s)
                if safe_delayed and len(sm.delayed) > 0:
                    for s in sm.delayed:
                        self.fuzzer.delayed.push(s)
                    break
                    # sm.active.append(sm.delayed.pop())
                    # self.msg("[+] Continuing with delayed old path
                    # "+str(sm.active[0])
                else:
                    break  # we are done!
            elif len(sm.active) == 1:  # exactly one state active, this is the normal case
                if limit != 0 and length > limit:
                    self.msg("[*] Path too long, killing..")
                    sm.active.pop()
                pass
            else:  # more than one state, make some decision magic
                choice = None
                states = sm.active
                edges = dict()
                for s in states:
                    last = self.fuzzer.to_map(s.history.bbl_addrs[-1])
                    cur = self.fuzzer.to_map(s.addr)
                    e = last ^ cur
                    edges[e] = s
                known = dict()
                unknown = []
                for e in edges.keys():
                    if e in self.fuzzer.bitmap:
                        known[e] = self.fuzzer.bitmap[e]  # value of bitmap
                    else:
                        self.fuzzer.bitmap[e] = 1
                        unknown.append(edges[e])  # states
                if len(unknown) >= 1:
                    # if its exactly one, follow it, if its more than one,
                    # follow first since we delay the others and follow them
                    # later
                    choice = unknown.pop()
                else:
                    # 2 or more known states
                    choice = random.choice(sm.active)  # rng
                self.apply_choice(sm, choice, unknown, safe_delayed=True)
            try:
                with timeout.timeout(self.fuzzer.timeout):
                    sm.step()
            except timeout.TimeoutError:
                self.msg("[-] Timeout, dumping..")
                for s in sm.active:
                    self.fuzzer.dump_maybe(s)
                del sm.active[:]
            except BaseException:
                self.msg("[-] Unknown error, dumping..")
                for s in sm.active:
                    self.fuzzer.dump_maybe(s)
                del sm.active[:]
        return len(sm.delayed_new)


if __name__ == "__main__":
    self.msg("[?] Do not run pathfinder.py directly - run fuzzer.py instead")
