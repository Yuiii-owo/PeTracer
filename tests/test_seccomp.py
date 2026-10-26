import os
import struct
import unittest

from petracer import seccomp


def decode(blob):
    out = []
    for i in range(0, len(blob), 8):
        code, jt, jf, k = struct.unpack_from("<HBBI", blob, i)
        out.append((code, jt, jf, k))
    return out


class SeccompTests(unittest.TestCase):
    def test_filter_shape(self):
        prog = decode(seccomp.build_filter())
        self.assertEqual(prog[0][0], seccomp.BPF_LD_W_ABS)
        self.assertEqual(prog[0][3], 4)  # offsetof(seccomp_data, arch)
        # last instruction always allows
        self.assertEqual(prog[-1][0], seccomp.BPF_RET_K)
        self.assertEqual(prog[-1][3], seccomp.SECCOMP_RET_ALLOW)

    def test_ptrace_is_denied(self):
        prog = decode(seccomp.build_filter())
        found = False
        for i, (code, jt, jf, k) in enumerate(prog):
            if code == seccomp.BPF_JMP_JEQ_K and k == 101:  # __NR_ptrace
                self.assertEqual(prog[i + 1][0], seccomp.BPF_RET_K)
                self.assertEqual(prog[i + 1][3] & 0xFFFF0000, seccomp.SECCOMP_RET_ERRNO)
                found = True
        self.assertTrue(found)

    def test_fd_export(self):
        fd = seccomp.open_filter_fd()
        try:
            data = os.read(fd, 10 * 1024)
            self.assertGreater(len(data), 8)
            self.assertEqual(len(data) % 8, 0)
        finally:
            os.close(fd)


if __name__ == "__main__":
    unittest.main()
