import os
import subprocess
import random
from diskcache import Deque
import collections
import sys
import threading
''' general utilities and helper functions
'''


class Cache():
    ''' Holds configurable amount of items in ram while swapping out the rest to disk
    '''

    def __init__(self, name, path):
        self.cache_max = 3000  # how many items are kept in RAM at most
        self.cache_min = 200  # how many items are kept in RAM at least
        self.cache = []
        mkdir(path + 'cache/')
        # diskcache to avoid crashes caused by full RAM
        self.disk = Deque(directory=path + 'cache/' + str(name))

    def __len__(self):
        return len(self.cache) + len(self.disk)

    def to_disk(self, items):
        self.disk.extend(items)

    def push(self, item):
        if len(self.cache) > self.cache_max:
            out = self.cache[:-self.cache_min]  # everything to be cached out
            self.cache = self.cache[-self.cache_min:]  # everything kept
            self.to_disk(out)
            # self.store_thread = threading.Thread(target=self.to_disk, args=(out,))  # we have to to this in a thread, its incredibly slow
            # self.store_thread.start()
        self.cache.append(item)

    def pushl(self, items):
        if len(self.cache) > self.cache_max:
            a = self.cache[:-self.cache_min]  # everything to be cached out
            self.cache = self.cache[-self.cache_min:]  # everything kept
        self.cache.extend(item)

    def random(self):
        ''' not truely random as it takes items from cache before taking them from disk (only random on a subset)
        '''
        if len(self.cache) > 1:
            item = random.choice(self.cache)
            self.cache.remove(item)
        else:
            length = len(self.disk)
            if length >= self.cache_min:
                length = self.cache_min
            for i in range(length):
                self.cache.append(self.disk.pop())
            item = random.choice(self.cache)
            self.cache.remove(item)
        return item

    def pop(self):
        if len(self.cache) > 1:
            return self.cache.pop()
        else:
            length = len(self.disk)
            if length >= self.cache_min:
                length = self.cache_min
            for i in range(length):
                self.cache.append(self.disk.pop())
            return self.cache.pop()

    def popleft(self):
        if len(self.cache) > 1:
            return self.cache.pop(0)
        else:
            length = len(self.disk)
            if length >= self.cache_min:
                length = self.cache_min
            for i in range(length):
                self.cache.append(self.disk.pop())
            return self.cache.pop(0)


def dummy(*arg):
    pass


def msg(txt):
    print(txt)


def read_files(path):
    ''' Read inputs from filesystem.
    '''
    files = collections.OrderedDict()
    for fname in os.listdir(path):
        p = f"{path}/{fname}"
        if os.path.isfile(p):
            with open(p, "rb") as file:
                files[fname] = file.read()
    print(f"[+] Read {str(len(files))} files from {str(path)}")
    return files


def yes(question):
    ''' Helper method to pause execution and wait for user input.
    '''
    while "[-] Answer is invalid":
        reply = str(raw_input(question + ' (y/n): ')).lower().strip()
        if reply[:1] == 'y':
            return True
        if reply[:1] == 'n':
            return False


def debug_print(msg):
    '''
    '''
    print(msg)


def mkdir(path, delete=False):
    '''
    '''
    if not os.path.exists(path):
        os.makedirs(path)
    else:
        if delete:
            run("rm -r " + path)
            mkdir(path)


def write_file(path, msg, mode):
    '''
    '''
    with open(path, mode) as file:
        file.write(msg)


def run(cmd, verbose=False):
    ''' https://docs.python.org/2/library/subprocess.html#module-subprocess says to not use pipes to hide the output
    '''
    if verbose:
        proc = subprocess.Popen(cmd, shell=True, close_fds=True)
    else:
        with open(os.devnull, 'w') as fp:
            proc = subprocess.Popen(cmd, shell=True, stdout=fp, stderr=fp)
    out, err = proc.communicate()  # this implicates wait()
    return proc.returncode


def run_out(cmd):
    '''
    '''
    return subprocess.Popen(cmd, shell=True, close_fds=True).communicate()[0]
