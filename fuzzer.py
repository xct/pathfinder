
''' This is the control part of pathfinder, managing resources and managing afl
'''
import afl
import angr
from angr.procedures.glibc import *
import argparse
import pickle
import configparser
import json
import multiprocessing
import os
import pathfinder
import random
import subprocess
import string
import time
import utils
import re


class Dummy(angr.SimProcedure):
    def run(self):
        print("[*] Dummy")
        return 0


class Fuzzer():

    def __init__(self):
        self.cores = multiprocessing.cpu_count()
        self.warmup = 20
        self.parse_arguments()
        self.parse_config()
        self.p = angr.Project(
            self.args[0],
            exclude_sim_procedures_list=self.exclude_sim_procedures_list,
            load_options={'auto_load_libs': self.simlibs})
        self.drun = self.drun.replace("@", str(self.p.arch.bits))
        self.dtrace = self.dtrace.replace("@", str(self.p.arch.bits))
        self.sym_file_name = "symbolic_file"
        self.map = dict()  # mapping addr to random values to encode edges
        self.bitmap = dict()  # map of all encoded edges (of multiple inputs)
        # same as bitmap but for edges that are never explored (artifacts from
        # concrete trace)
        self.blacklist = []
        self.setup_directories()
        self.new = utils.Cache("new", self.temp_dir)
        self.delayed = utils.Cache("delayed", self.temp_dir)
        txt = "Fuzzing " + self.cmd + "\n"
        txt += "Hybrid: " + str(self.hybrid)
        utils.write_file(self.temp_dir + "stats", txt, "w")
        print("[+] Setup complete\n[+] Identified " + \
            str(self.cores) + " usable cores")
        print("[!] Please use echo core > /proc/sys/kernel/core_pattern before using this program")
        self.simfiles = []
        if self.verbose:
            self.msg = utils.msg
        else:
            self.msg = utils.dummy

    def setup_directories(self):
        self.afl_dir = self.temp_dir + "afl/"
        self.queue_dir = self.temp_dir + "queue/"
        self.crash_dir = self.temp_dir + "crashes/"
        self.trace_dir = self.temp_dir + "traces/"
        self.input_dir = self.temp_dir + "inputs/"
        self.exploit_dir = self.temp_dir + "exploits/"

        utils.mkdir(self.temp_dir, delete=True)
        utils.mkdir(self.crash_dir)
        utils.mkdir(self.input_dir)
        utils.mkdir(self.queue_dir)
        utils.mkdir(self.trace_dir)
        utils.mkdir(self.exploit_dir)
        utils.run(f"cp {self.original_inputs}/* {self.input_dir}")
        utils.run(f"cp {self.original_inputs}/* {self.queue_dir}")
        if self.hybrid:
            utils.mkdir(self.temp_dir + "afl/")
            utils.mkdir(self.temp_dir + "afl/tmp")
            utils.mkdir(self.temp_dir + "afl/in")
            utils.mkdir(self.temp_dir + "afl/sync")

    def parse_arguments(self):
        parser = argparse.ArgumentParser(
            description='Pathfinder - Using Symbolic Execution to find new paths through programs')
        parser.add_argument('-i', help='input directory')  # afl path
        parser.add_argument('cmd')
        # optional parameter to find a path to the target basic block, no
        # tracing etc needed for this
        parser.add_argument('-t', help='address of target basic block')
        parser.add_argument('-v', action='store_true',
                            help='verbose, print a lot of debug output')
        parser.add_argument('-hybrid', action='store_true',
                            help='verbose, print a lot of debug output')
        args = parser.parse_args()
        self.original_inputs = args.i
        self.cmd = args.cmd
        self.stdin = False
        self.args = self.cmd.split(" ")
        if "/" in self.args[0]:
            self.pname = self.args[0].split("/")[-1]
        else:
            self.pname = self.args[0]
        if args.t:
            self.target_mode = True
            self.target = int(args.t, 16)
        else:
            self.target_mode = False
        if args.v:
            self.verbose = True
        else:
            self.verbose = False
        if args.hybrid:
            self.hybrid = True
        else:
            self.hybrid = False

    def parse_config(self):
        config = configparser.ConfigParser()
        config.read('config.ini')        
        self.temp_dir = f"{config['General']['tmp_path']}{self.pname}/"
        print(self.temp_dir)
        self.afl = afl.Afl(
            config['General']['afl_path'],
            self.temp_dir + "afl/",
            self.cmd)
        self.drun = config['General']['dynamorio_path'] + "build@/bin@/drrun"
        self.dtrace = "./tracer/build@/bin/libtrace_bb.so"
        self.depth = config['Strategy']['depth']
        self.depth_limit = config['Strategy']['depth_limit']
        self.coverage = config['Strategy']['coverage']
        self.exclude_sim_procedures_list = json.loads(
            config['Fix']['skipfunctions'])  # using json to be able to use array in config
        if config['Fix']['simlibs'] == "True":
            self.simlibs = True
        else:
            self.simlibs = False        
        self.path_limit = int(config['Strategy']['limit'])
        self.timeout = int(config['Strategy']['timeout'])
        self.afl_timeout = int(config['Strategy']['afl_timeout'])

    def pre_afl(self):
        ''' clear traces from pathfinder and copy over afl queue and pf results as new inputs to afl via using cmin to avoid doublettes
        '''
        utils.run(f"rm {self.trace_dir}/*")  # clean traces
        cmd = "cp -au " + self.queue_dir + "/* " + self.afl_dir + "tmp/"  # inputs from pf to afl
        utils.run(cmd)
        cmd = "cp -au " + self.afl_dir + "/sync/master/queue/id* " + self.afl_dir + "tmp/"  # old queue from afl to inputs for restart
        utils.run(cmd)
        cmd = "rm " + self.afl_dir + "in/*"  # for cmin the folder needs to be empty
        utils.run(cmd)
        self.afl.cmin(self.afl_dir + "tmp/", self.afl_dir + "in/", verbose=self.verbose)
        cmd = "rm " + self.afl_dir + "tmp/*"  # clear out temp aswell
        utils.run(cmd)

    def post_afl(self):
        ''' copy over afl queue + crashes to pathfinder, also inputs to queue
        '''
        utils.run(
            "rm " + self.queue_dir + "/*")  # clean old queue to avoid doubling up inputs (afl renames them)
        # clean old queue to avoid doubling up inputs (afl renames them)
        utils.run("rm " + self.input_dir + "/*")
        utils.run("cp " + self.afl_dir + "sync/master/queue/id* " + self.input_dir)  # copy inputs from afl to pf
        utils.run("cp -au " + self.afl_dir + "sync/master/crashes/* " + self.crash_dir)  # save crashes
        utils.run("cp -au " + self.input_dir + "/* " + self.queue_dir)

    def check_crash(self, path):
        ''' checks weather files in queue dir are causing crashes on the target application
        '''
        if self.stdin:
            cmd = self.cmd + " < " + path
        else:
            cmd = self.cmd.replace("@@", path)
        ret = utils.run(cmd)
        if ret == 139:  # sigsegv http://www.bu.edu/tech/files/text/batchcode.txt
            print("[+] Segmentation Fault detected - copying input " + str(path) + " to crashes")
            self.notify("Segmentation Fault")
            name = path.rsplit('/', 1)[-1]
            utils.run("cp " + path + " " + self.crash_dir + "/" + name + ":11")
        if ret == 134:  # sigsegv http://www.bu.edu/tech/files/text/batchcode.txt
            print("[+] Abort detected - copying input " + str(path) + " to crashes")
            self.notify("Abort")
            name = path.rsplit('/', 1)[-1]
            utils.run("cp " + path + " " + self.crash_dir + "/" + name + ":6")

    def generate_traces(self, inputs):
        ''' Utilize DynamoRIO to create a trace of binary running with concrete seed/input.
        '''
        # clean tmp dir
        trace_dir = self.temp_dir + "traces/"
        with open(os.devnull, 'w') as fp:
            proc = subprocess.Popen(
                "rm " + trace_dir + "*",
                shell=True,
                stdout=fp,
                stderr=fp)
            proc.wait()

        # generate traces
        base_cmd = f"{self.drun} -t drcov -dump_text -logdir {trace_dir}"
        for fname in inputs.keys():
            cmd = base_cmd + " -- " + self.cmd + " "
            if "@@" in cmd:
                # input from file
                # there could be an extension in place
                parts = cmd.split(" ")
                replace = None
                for p in parts:
                    if p.startswith("@@"):
                        replace = p
                cmd = cmd.replace(replace, self.input_dir + "/" + fname)
            else:
                # input from stdin
                cmd += "< " + self.input_dir + "/" + fname
            with open(os.devnull, 'w') as fp:
                print(cmd)
                proc = subprocess.Popen(cmd, shell=True, stdout=fp, stderr=fp)
                proc.wait()
        print("[+] Created " + str(len(inputs)) + " trace(s)")  

        # read traces
        traces = dict()
        avg = 0
        for fname in os.listdir(self.temp_dir + "traces/"):
            if not fname.startswith(".") and not os.path.isdir(trace_dir + fname):
                print(fname)
                with open(trace_dir + "/" + fname, "r") as file:
                    traces[fname] = []
                    lines = file.readlines()
                    for i, line in enumerate(lines):
                          # skip first 4 lines
                        if i < 4:
                            continue                      
                        # parse basic blocks
                        m = re.match(r'\s*module\[\s*([0-9]+)\]:\s*([x0-9a-f]+),\s*([x0-9a-f]+)', line)
                        if m != None and len(m.groups()) == 3:
                            addr = m.group(2)
                            traces[fname].append(int(addr, 16))
                            avg += len(traces[fname])
        # print("[+] Read " + str(len(traces)) + " traces"#, average trace
        # length is "+str(avg/len(traces))
        return traces

    def encode_traces(self, traces):
        ''' Encode trace into a trace of edges.
        '''
        etraces = []
        for trace in traces.values():  # multiple traces
            etrace = []
            for i in range(1, len(trace), 1):
                last = self.to_map(trace[i - 1])
                cur = self.to_map(trace[i])
                e = last ^ cur
                etrace.append(e)
            etraces.append(etrace)
        return etraces

    def to_map(self, addr):
        ''' Get abstract value from real address.
        '''
        if addr not in self.map:
            self.map[addr] = random.randint(0, 0xFFFFFFF)
        #print("to_map: "+str(hex(addr))+" | "+str(hex(self.map[addr]))
        return self.map[addr]

    def from_map(self, num):
        ''' Gets real address from abstract value.
        '''
        for k, v in self.map.iteritems():
            if v == num:
                return self.map[k]
        assert(num in self.map.values())

    def clear_temp(self):
        ''' Clear old temp data from tmp directory.
        '''
        subprocess.Popen("rm " + self.temp_dir + ".bitmap", shell=True, stdout=fp, stderr=fp)
        subprocess.Popen("rm " + self.temp_dir + ".inputs", shell=True, stdout=fp, stderr=fp)
        subprocess.Popen("rm " + self.temp_dir + ".cache*", shell=True, stdout=fp, stderr=fp)

    def save_temp(self, inputs, bitmap):
        ''' Saves inputs and bitmaps to temporary files.
        '''
        temp = self.temp_dir + ".inputs"
        with open(temp, 'wb') as outfile:
            outfile.write(pickle.dumps(inputs))
        temp = self.temp_dir + ".bitmap"
        with open(temp, 'wb') as outfile:
            outfile.write(pickle.dumps(bitmap))

    def load_temp(self):
        ''' Loads saved inputs and bitmaps from temporary files if they exist.
        '''
        temp = self.temp_dir + ".inputs"
        try:
            with open(temp, 'rb') as infile:
                inputs = pickle.load(infile)
        except IOError:
            inputs = []
        temp = self.temp_dir + ".bitmap"
        try:
            with open(temp, 'rb') as infile:
                bitmap = pickle.load(infile)
        except IOError:
            bitmap = dict()
        return (inputs, bitmap)

    def fix_args(self, args, inputs=[]):
        ''' Fixes arguments to accomodate for Stdin- / Fileinput.
        '''
        orgs = args[:]
        self.stdin = True
        for inp in inputs:
            args = orgs[:]
            for i, a in enumerate(args):
                if a.startswith("@@"):
                    self.stdin = False
            if self.stdin:
                args.append(" < " + self.input_dir + "/" + inp)
        if not self.stdin:
            print("[?] Symbolic reads from stdin disabled.")
            args = orgs[:]
            for i, a in enumerate(args):
                arg = a.split(".")
                if arg[0] == "@@":
                    if len(arg) > 1:
                        self.sym_file_name += "." + arg[1]
                        args[i] = self.sym_file_name
                    else:
                        args[i] = self.sym_file_name
                    #print args[i]
        return args

    def create_sm(self, state, extra_stashes):
        '''
        '''
        sm = self.p.factory.simgr(state, save_unconstrained=True)
        for stash in extra_stashes:
            sm.stashes[stash] = []
        return sm

    def filter_compare(self, inputs, data):
        ''' Compare outputs to inputs to avoid storing doubles.
        '''
        res = list(set(data) - set(inputs.values()))
        return res

    def write_outputs(self, data, prefix="pathfinder", path=None):
        ''' Write output data as a file to the specified directory.
        '''
        if path is None:
            path = self.queue_dir
        for i, d in enumerate(data):
            ident = prefix + ":" + str(i) + ":" + ''.join(random.choice(
                string.ascii_lowercase + string.digits) for _ in range(8))
            # if we had symbolic input with an extension, we use that for out
            # files aswell
            ext = self.sym_file_name.split(".")
            if len(ext) > 1:
                ident += "." + ext[1]
            fpath = path + "/" + ident
            with open(fpath, 'wb') as outfile:
                outfile.write(d)
            self.check_crash(fpath)

    def dump_maybe(self, s, prefix="pathfinder"):
        ''' Concretize inputs and write to file, given a state. This only dumps the outputs when they are a) different from an existing
        output/input and b) the path depended on the input (there have to be constraints on it).
        '''
        data = []
        if not self.stdin:
            try:
                cur_data = s.posix.dump_file_by_path(self.sym_file_name)
            except BaseException:
                print("Could not dump file")
                return False
        else:
            cur_data = s.posix.dumps(0)
        if len(cur_data) > 0:
            data.append(cur_data)
        if len(data) > 0:
            queue = utils.read_files(self.queue_dir)
            # compare to inputs to avoid doublettes
            data = self.filter_compare(queue, data)
            if len(data) > 0:
                #print("[+] Found "+ str(len(data)) + " unique! (Writing to disk..)"
                self.write_outputs(data, prefix)
                return True
        return False

    def notify(self, txt):
        #subprocess.Popen("spd-say --voice-type female3 "+txt,shell=True)
        pass

    def update_stats(self):
        txt = ""
        utils.write_file(self.temp_dir + "stats", txt, "a")

    def discover(self, coverage, input_dir, mode='full'):
        tracer = pathfinder.Tracer(self, self.verbose)

        def run(inputs):
            cov = False
            if coverage == "full":
                cov = True
            traces = self.generate_traces(inputs)  # dynamorio traces
            etraces = self.encode_traces(traces)  # edge traces
            args = self.fix_args(self.args, inputs)  # replace placeholders
            self.msg("[+] Tracing with: " + str(args))
            concrete_traces = tracer.trace_concrete(args, traces, etraces, inputs)
            if len(concrete_traces) == 0:
                return
            length = tracer.trace_symbolic(args, concrete_traces, inputs)
            self.msg("[+] Done Tracing, discovered " + str(len(self.new)) + " new edges")
            self.__discover(length, cov)

        all_inputs = utils.read_files(input_dir)  # inputs
        # we do this to create a way to get results quicker, sacrificing a complete coverage map for quick results
        # by not tracing everything and then running discover but tracing
        # single files and discovering on them
        if mode == 'full':
            run(all_inputs)
        else:
            #print all_inputs
            k, v = all_inputs.items()[random.randint(0, len(all_inputs) - 1)]
            one_input = dict()
            one_input[k] = v
            run(one_input)

    def __discover(self, length, full):
        ''' Call setup first or this will fail gloriously
        '''
        explorer = pathfinder.Explorer(self, self.verbose)
        while len(self.new) > 0 or len(self.delayed) > 0:
            while len(self.new) > 0:
                s = self.new.pop()
                self.msg("[+] Exploring " + str(s) + " (New Remaining: " + str(len(self.new)) + ")")
                amount = len(self.new)
                if full:
                    new = explorer.run(s, safe_delayed=True, limit=length * self.path_limit)
                else:
                    new = explorer.run(s, safe_delayed=False, limit=length * self.path_limit)
                if len(self.new) == amount:
                    # at this point we could delete the input if it has not
                    # lead to new states for hybrid mode
                    pass
                self.msg("[+] Done for " + str(s) +
                         "! Found " + str(new) + " new states")
            if not full:
                break
            # 2nd pass, now we (eventually) explore delayed states that were
            # not new
            # this runs until the substates until no more new states can be found
            while len(self.delayed) > 0:
                if len(self.new) > 0:  # new states need to be prioritized
                    self.notify("new edge")
                    break
                if self.depth == 'shallow':
                    s = self.delayed.popleft()  # take from beginning
                else:
                    s = self.delayed.random()  # this needs to be random, to not get stuck in local areas
                self.msg("[+] Exploring " + str(s) + " (Known Remaining: " + str(len(self.delayed)) + ")")
                new = explorer.run(s, limit=length * self.path_limit)
                self.msg("[+] Done for " + str(s) + "! Found " + str(new) + " new states")

    def main(self):
        ''' Read inputs, generate traces, compile edgetraces and run pathfinder.
        '''
        if self.target_mode:
            ''' finding path to a specific, predefined basic block
            '''
            print("[+] Running in target-mode, target=" + str(hex(self.target)))
            start = time.time()
            self.run_target()
            end = time.time()
        elif self.hybrid:
            ''' supporting afl in finding new paths
            '''
            init = True
            while True:
                if not init:
                    self.pre_afl()
                else:
                    utils.run("cp " + self.input_dir + "/* " + self.afl_dir + "in/")
                    init = False
                print("[+] AFL running, waiting for warmup (" + str(self.warmup) + ") until symbolic exploration is started")
                # runs afl on the provided inputs, forever without a timeout in
                # background
                self.afl.run(self.afl_timeout)
                # give afl some time before exploring its queue
                time.sleep(self.warmup)
                self.update_stats()
                self.post_afl()
                print("[+] Exploring symbolically...")
                # quick mode just explores on one random input (tracing takes a
                # long time so we could be stuck tracing here for ages)
                self.discover(coverage="fast", input_dir=self.input_dir, mode='quick')
                self.update_stats()
                print("[+] Done exploring - restarting AFL")
                self.afl.kill()
        else:
            ''' following traces, recording new edgess, automatically discovery new paths
            '''
            print("[+] Running in discovery-mode")
            start = time.time()
            self.discover(coverage=self.coverage, input_dir=self.input_dir)
            end = time.time()
            print("[+] Execution took " + \
                str(round(end - start, 2)) + " seconds")


if __name__ == "__main__":
    fuzzer = Fuzzer()
    fuzzer.main()
