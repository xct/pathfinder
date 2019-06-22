import signal
import atexit
import os
import subprocess
import time
import utils
import psutil


class Afl():

    def exit_handler(self):
        try:
            os.killpg(os.getpgid(self.pid), signal.SIGTERM)
        except BaseException:
            pass

    def __init__(self, afl_path, temp_path, command):
        self.afl_path = afl_path  # afl installation directory
        self.temp_path = temp_path  # afl working directory
        self.command = command
        self.pid = -1

    def get_stats(self, entry):
        result = ""
        while result == "":
            result = utils.run_out("cat " + self.temp_path + "sync/master/fuzzer_stats | grep " + entry + " | cut -d ':' -f 2")
            time.sleep(1)
        return int(result.replace(" ", ""))

    def kill(self):
        process = psutil.Process(self.pid)
        try:
            for proc in process.children(recursive=True):
                proc.kill()
            process.kill()
        except BaseException:
            # bug ?
            pass

    def cmin(self, inp, out, verbose=False):
        cmd = self.afl_path + "afl-cmin -Q -i " + \
            inp + " -o " + out + " -- " + self.command
        if verbose:
            proc = subprocess.Popen(cmd, shell=True)
            proc.wait()
        else:
            with open(os.devnull, 'w') as fp:
                proc = subprocess.Popen(
                    cmd, shell=True, stdout=fp)
                proc.wait()

    def run(self, timeout=30, verbose=False):
        atexit.register(self.exit_handler)

        # run afl
        cmd = "AFL_SKIP_BIN_CHECK=1 AFL_SKIP_CRASHES=1 " + self.afl_path + "afl-fuzz -i " + self.temp_path + \
            "in/" + " -o " + self.temp_path + "sync/ -M master -Q -m none "
        cmd += self.command

        if verbose:
            afl = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid)
        else:
            with open(os.devnull, 'w') as fp:
                afl = subprocess.Popen(
                    cmd, shell=True, stdout=fp, stderr=fp)

        self.pid = afl.pid
        if timeout == -1:  # if we have a timeout only run for that time
            return
        count = 0
        refresh = 1
        start = time.time()
        while True:
            time.sleep(refresh)
            count += refresh
            if count > timeout:
                print("[*] Configured timeout (" + str(timeout) + ") reached")
                self.kill()
                break
            last = self.get_stats("last_path")
            if last > 0:  # or some set timeout is hit, could never find a new path
                diff = last - start
                if diff > 120:  # no new path for x sec or no path at all for y sec
                    print("[-] No new path for (" + str(120) + ") seconds")
                    self.kill()
                    break
