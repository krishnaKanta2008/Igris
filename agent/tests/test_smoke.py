"""Phase 0 smoke tests for the igris-agent package (stdlib only)."""

import unittest

import igris_agent
from igris_agent import __main__


class TestPackage(unittest.TestCase):
    def test_version_present(self) -> None:
        self.assertIsInstance(igris_agent.__version__, str)
        self.assertTrue(igris_agent.__version__)

    def test_main_returns_zero(self) -> None:
        self.assertEqual(__main__.main(), 0)


if __name__ == "__main__":
    unittest.main()
