import argparse
import ctypes
import os
import re

libc = ctypes.CDLL('libc.so.6')

enum_t = ctypes.c_int
pid_t = ctypes.c_int32
ptr_t = ctypes.c_void_p
null = ptr_t()


class IOVec(ctypes.Structure):
    _fields_ = [("iov_base", ptr_t),
                ("iov_len", ctypes.c_size_t)]


PTRACE_ATTACH = 16
PTRACE_DETACH = 17


class PTrace:
    libc_ptrace = libc.ptrace

    def __init__(self, pid):
        self.pid = pid_t(pid)

    def __enter__(self):
        self.attach()
        return self

    def __exit__(self, *_):
        self.detach()

    def attach(self):
        self.trace(PTRACE_ATTACH)

        info = os.waitpid(self.pid.value, 0)
        if not os.WIFSTOPPED(info[1]) or os.WSTOPSIG(info[1]) != 19:
            print('[!] Attach failure')
            exit(-1)

    def detach(self):
        self.trace(PTRACE_DETACH)

    def trace(self, request, address=null, data=null):
        self.libc_ptrace(enum_t(request), self.pid, address, data)


class MemScram:
    libc_process_vm_readv = libc.process_vm_readv
    libc_process_vm_writev = libc.process_vm_writev

    map_re = re.compile(r'(\w+)-(\w+)\x20rw..\x20')

    def __init__(self, pid):
        self.pid = pid
        self.maps = self._map_memory()

    def _map_memory(self):
        def convert(start, end):
            return int(start, 16), int(end, 16) - int(start, 16)

        with open(f'/proc/{self.pid}/maps', 'r') as fp:
            return [convert(x, y) for x, y in self.map_re.findall(fp.read())]

    def scramble(self, pattern):
        for offset, length in self.maps:
            for match in re.finditer(pattern.encode(), self._read(offset, length)):
                start, end = match.span()
                self._write(offset + start, end - start)

    def _read(self, address, length):
        buffer = ctypes.create_string_buffer(length)

        local, remote = self._io_vector(buffer, address, length)

        self.libc_process_vm_readv(self.pid, local, 1, remote, 1, 0)

        return buffer.raw

    def _write(self, address, length):
        buffer = ctypes.create_string_buffer(length)
        buffer.value = b'.' * length

        local, remote = self._io_vector(buffer, address, length)

        self.libc_process_vm_writev(self.pid, local, 1, remote, 1, 0)

    @staticmethod
    def _io_vector(buffer, address, length):
        local = IOVec(ctypes.cast(ctypes.byref(buffer), ptr_t), length)
        remote = IOVec(ptr_t(address), length)

        return ctypes.byref(local), ctypes.byref(remote)


def main(pid, evt_types):
    pattern = '({})'.format('|'.join(evt_types))

    with PTrace(pid):
        MemScram(pid).scramble(pattern)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Scramble strings in process memory')
    parser.add_argument('pid', type=int, help='pid of target process')
    parser.add_argument('strings', type=str, nargs='+', help='list of strings')

    args = parser.parse_args()

    main(args.pid, args.strings)
