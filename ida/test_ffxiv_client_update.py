import unittest
from types import SimpleNamespace

from ffxiv_client_update import Analyzer


class ClientUpdateTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = Analyzer(SimpleNamespace(), SimpleNamespace(), float("inf"))

    def decode(self, code):
        return list(self.analyzer.decoder.disasm(bytes.fromhex(code), 0x1000))

    def test_tracks_interior_pointer_without_following_loaded_pointer(self):
        instructions = self.decode("48 8D 59 20 8B 43 04 48 8B 49 30 8B 41 08")
        accesses = self.analyzer.accesses(instructions)
        self.assertEqual([item[0] for item in accesses.values()], [0x20, 0x24, 0x30])

    def test_partial_register_write_invalidates_pointer(self):
        for code in ("31 C9 8B 41 20", "B1 01 8B 41 20", "66 B9 01 00 8B 41 20"):
            with self.subTest(code=code):
                self.assertEqual(self.analyzer.accesses(self.decode(code)), {})

    def test_call_invalidates_volatile_pointer_but_preserves_saved_this(self):
        accesses = self.analyzer.accesses(self.decode("48 89 CB E8 00 00 00 00 8B 41 20 8B 43 24"))
        self.assertEqual([item[0] for item in accesses.values()], [0x24])

    def test_branch_join_does_not_reuse_linear_pointer_state(self):
        accesses = self.analyzer.accesses(self.decode("48 89 CB 74 03 48 89 C3 8B 43 24"))
        self.assertEqual(accesses, {})

    def test_shape_accepts_displacement_encoding_change(self):
        source = self.decode("48 8B 41 70 C3")
        target = self.decode("48 8B 81 90 00 00 00 C3")
        self.assertEqual(self.analyzer.shape(source), self.analyzer.shape(target))
        self.assertNotEqual(self.analyzer.accesses(source), self.analyzer.accesses(target))

    def test_ambiguous_shape_does_not_match(self):
        self.analyzer.groups = [{"shape": [0x1000]}, {"shape": [0x2000, 0x3000]}]
        self.analyzer.match()
        self.assertEqual(self.analyzer.pairs, {})

    def test_agreeing_branches_preserve_saved_pointer(self):
        accesses = self.analyzer.accesses(self.decode("48 89 CB 74 02 90 90 8B 43 24"))
        self.assertEqual([item[0] for item in accesses.values()], [0x24])

    def test_loop_pointer_drift_is_not_reported_as_fixed_field(self):
        accesses = self.analyzer.accesses(self.decode("48 89 CB 8B 43 24 48 8D 5B 08 75 F7"))
        self.assertNotIn((1, 1), accesses)


if __name__ == "__main__":
    unittest.main()
