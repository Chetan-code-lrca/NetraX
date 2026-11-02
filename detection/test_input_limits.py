import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pandas as pd

from detection.input_limits import InputLimitError, read_bounded_flow_csv


class BoundedCsvInputTests(unittest.TestCase):
    def write_csv(self, content):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "flows.csv"
        path.write_text(content, encoding="utf-8")
        return path

    def test_accepts_exactly_the_configured_limit(self):
        path = self.write_csv("src,dst\na,b\nc,d\n")
        frame = read_bounded_flow_csv(path, max_rows=2)
        self.assertEqual(len(frame), 2)

    def test_rejects_first_row_over_limit(self):
        path = self.write_csv("src,dst\na,b\nc,d\ne,f\n")
        with self.assertRaisesRegex(InputLimitError, "more than 2 flow rows"):
            read_bounded_flow_csv(path, max_rows=2)

    def test_reads_only_one_row_beyond_limit(self):
        path = self.write_csv("src,dst\n" + "a,b\n" * 20)
        with mock.patch("detection.input_limits.pd.read_csv", wraps=pd.read_csv) as reader:
            with self.assertRaises(InputLimitError):
                read_bounded_flow_csv(path, max_rows=3)
        reader.assert_called_once_with(path, nrows=4)

    def test_rejects_invalid_limits(self):
        path = self.write_csv("src\na\n")
        for value in (0, -1, True, 1.5, "3"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    read_bounded_flow_csv(path, max_rows=value)

    def test_accepts_empty_data_section(self):
        path = self.write_csv("src,dst\n")
        frame = read_bounded_flow_csv(path, max_rows=1)
        self.assertEqual(len(frame), 0)
        self.assertEqual(list(frame.columns), ["src", "dst"])


if __name__ == "__main__":
    unittest.main()
