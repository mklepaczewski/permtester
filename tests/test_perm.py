import unittest
import tempfile
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/..")
from permtester import Perm


class TestPerm(unittest.TestCase):

    def test_overlay_onto(self):
        handle, path = tempfile.mkstemp("permtester")

        cases = [
            # file_permissions, target_permission, expected_changes
            (0o000, "r--------", 0o0400),
            (0o000, "-w-------", 0o0200),
            (0o000, "--x------", 0o0100),
            (0o000, "---r-----", 0o0040),
            (0o000, "----w----", 0o0020),
            (0o000, "-----x---", 0o0010),
            (0o000, "------r--", 0o0004),
            (0o000, "-------w-", 0o0002),
            (0o000, "--------x", 0o0001),

            (0o000, "r--r-----", 0o0440),
            (0o000, "-w--w----", 0o0220),
            (0o000, "--x--x---", 0o0110),
            (0o000, "---r--r--", 0o0044),
            (0o000, "----w--w-", 0o0022),
            (0o000, "-----x--x", 0o0011),
            (0o000, "r-----r--", 0o0404),
            (0o000, "-w-----w-", 0o0202),
            (0o000, "--x-----x", 0o0101),

            (0o000, "rwxrwxrwx", 0o0777),

            # With wildcards, where the wildcard perm is not set
            (0o000, "?--------", 0o0000),
            (0o000, "-?-------", 0o0000),
            (0o000, "--?------", 0o0000),
            (0o000, "---?-----", 0o0000),
            (0o000, "----?----", 0o0000),
            (0o000, "-----?---", 0o0000),
            (0o000, "------?--", 0o0000),
            (0o000, "-------?-", 0o0000),
            (0o000, "--------?", 0o0000),

            # With wildcards, where the wildcard perm is set
            (0o400, "?--------", 0o400),
            (0o200, "-?-------", 0o200),
            (0o100, "--?------", 0o100),
            (0o040, "---?-----", 0o040),
            (0o020, "----?----", 0o020),
            (0o010, "-----?---", 0o010),
            (0o004, "------?--", 0o004),
            (0o002, "-------?-", 0o002),
            (0o001, "--------?", 0o001),

            # With X wildcard, where x is not present
            (0o000, "--X------", 0o000),
            (0o000, "-----X---", 0o000),
            (0o000, "--------X", 0o000),

            # With X wildcard, where x is present
            (0o100, "--X------", 0o100),
            (0o010, "-----X---", 0o010),
            (0o001, "--------X", 0o001),
        ]

        for file_permissions, target_permissions, expected_changes in cases:
            os.chmod(path, file_permissions)
            perm = Perm.from_string(target_permissions)
            result = perm.overlay_onto(path)
            self.assertEqual(expected_changes, result, f"Expected changes from {oct(file_permissions)} -> {target_permissions}: {oct(expected_changes)}, got {oct(result)}")

    def test_overlay_onto_dir(self):
        path = tempfile.mkdtemp("permtester")

        cases = [
            # With X wildcard, where x is not present
            (0o000, "--X------", 0o100),
            (0o000, "-----X---", 0o010),
            (0o000, "--------X", 0o001),

            # With X wildcard, where x is present
            (0o100, "--X------", 0o100),
            (0o010, "-----X---", 0o010),
            (0o001, "--------X", 0o001),

            (0o100, "--X--X---", 0o110),
            (0o010, "-----X--X", 0o011),
            (0o001, "--X-----X", 0o101),

            (0o300, "r-X--X---", 0o510),
            (0o300, "--X--X---", 0o110),
        ]

        for file_permissions, target_permissions, expected_changes in cases:
            os.chmod(path, file_permissions)
            perm = Perm.from_string(target_permissions)
            result = perm.overlay_onto(path)
            self.assertEqual(expected_changes, result, f"Expected changes: {oct(expected_changes)}, got {oct(result)}")


if __name__ == '__main__':
    unittest.main()
