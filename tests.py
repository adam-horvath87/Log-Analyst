"""
tests.py - Unit tests for the Apache2 Log Analyzer.

IEEE 829 compliant test suite.

How to run:
    python3 tests.py
"""

import unittest
import os
import tempfile
from datetime import datetime

from log_parser import LogParser
from security_engine import DetectionEngine


class TestTC01LogParsing(unittest.TestCase):
    """
    TCS-01: Standard Log Parsing.
    Objective: Verify that a valid log line is correctly parsed into fields.
    """

    def setUp(self):
        """Runs before every test. Creates a fresh LogParser."""
        self.parser = LogParser()

    def test_valid_line_parses_without_error(self):
        """TC-01a: A valid Combined Log Format line should parse correctly."""
        line = '127.0.0.1 - - [12/May/2026:06:00:00 +0200] "GET /test.php HTTP/1.1" 200 512 "-" "-"'
        result = self.parser.parse_line(line, line_number=1)
        self.assertIsNotNone(result)

    def test_ip_address_is_extracted(self):
        """TC-01b: The IP address field should be extracted correctly."""
        line = '83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "-"'
        result = self.parser.parse_line(line, line_number=1)
        self.assertEqual(result["ip"], "83.149.9.216")

    def test_status_code_is_integer(self):
        """TC-01c: The status code must be an integer, not a string."""
        line = '127.0.0.1 - - [12/May/2026:06:00:00 +0200] "GET /test.php HTTP/1.1" 200 512 "-" "-"'
        result = self.parser.parse_line(line, line_number=1)
        self.assertIsInstance(result["status_code"], int)
        self.assertEqual(result["status_code"], 200)

    def test_timestamp_is_datetime(self):
        """TC-01d: The timestamp must be a datetime object."""
        line = '127.0.0.1 - - [12/May/2026:06:00:00 +0200] "GET /test.php HTTP/1.1" 200 512 "-" "-"'
        result = self.parser.parse_line(line, line_number=1)
        self.assertIsInstance(result["timestamp"], datetime)

    def test_uri_and_query_string_are_split(self):
        """TC-01e: URI and query string should be split at the '?' character."""
        line = '127.0.0.1 - - [12/May/2026:06:00:00 +0200] "GET /search?q=hello&page=2 HTTP/1.1" 200 512 "-" "-"'
        result = self.parser.parse_line(line, line_number=1)
        self.assertEqual(result["uri"], "/search")
        self.assertEqual(result["query_string"], "q=hello&page=2")

    def test_dash_bytes_becomes_zero(self):
        """TC-01f: A '-' in the bytes field should be converted to 0."""
        line = '127.0.0.1 - - [12/May/2026:06:00:00 +0200] "GET /test HTTP/1.1" 304 - "-" "-"'
        result = self.parser.parse_line(line, line_number=1)
        self.assertEqual(result["bytes"], 0)


class TestTC02ThreatDetection(unittest.TestCase):
    """
    TCS-02: Plaintext Threat Detection.
    Objective: Verify that attack patterns are detected in log entries.
    """

    def setUp(self):
        """Creates a temporary patterns file and a DetectionEngine for testing."""
        self.tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".db", delete=False, encoding="utf-8")
        self.tmp.write("UNION SELECT\n")
        self.tmp.write("/etc/passwd\n")
        self.tmp.write("<script>\n")
        self.tmp.write("eval(\n")
        self.tmp.close()

        self.engine = DetectionEngine(self.tmp.name, burst_threshold=5)

    def tearDown(self):
        """Deletes the temporary file after the test."""
        os.unlink(self.tmp.name)

    def make_entry(self, uri, query_string="", ip="192.168.1.1"):
        """Helper: creates a fake log entry dictionary for testing."""
        return {
            "ip": ip,
            "timestamp": None,
            "method": "GET",
            "uri": uri,
            "query_string": query_string,
            "status_code": 200,
            "bytes": 512
        }

    def test_sql_injection_detected(self):
        """TC-02a: UNION SELECT in the query string should be flagged."""
        entry = self.make_entry("/admin", "cmd=UNION+SELECT+null,user--")
        matches = self.engine.check_request(entry)
        self.assertGreater(len(matches), 0, "SQL injection was not detected!")

    def test_path_traversal_detected(self):
        """TC-02b: /etc/passwd path traversal should be detected."""
        entry = self.make_entry("/view", "path=../../etc/passwd")
        matches = self.engine.check_request(entry)
        self.assertTrue(any("/etc/passwd" in m for m in matches), "Path traversal not detected!")

    def test_clean_request_not_flagged(self):
        """TC-02c: A normal clean request should return no matches."""
        entry = self.make_entry("/index.html", "")
        matches = self.engine.check_request(entry)
        self.assertEqual(len(matches), 0, "A clean request was incorrectly flagged!")


class TestTC03MultiplePatterns(unittest.TestCase):
    """
    TCS-03: Multiple Pattern Matching.
    Objective: A single log line can match more than one attack pattern.
    """

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".db", delete=False, encoding="utf-8")
        self.tmp.write("/etc/passwd\n")
        self.tmp.write("<script>\n")
        self.tmp.close()
        self.engine = DetectionEngine(self.tmp.name)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_two_patterns_in_one_line(self):
        """TC-03: Both /etc/passwd and <script> should be found in the same line."""
        entry = {
            "ip": "1.2.3.4", "timestamp": None, "method": "GET",
            "uri": "/etc/passwd", "query_string": "id=<script>alert(1)</script>",
            "status_code": 200, "bytes": 0
        }
        matches = self.engine.check_request(entry)
        self.assertGreaterEqual(len(matches), 2, "Expected at least 2 matches!")


class TestTC04Normalization(unittest.TestCase):
    """
    TCS-04: Case Sensitivity and Normalization.
    Objective: Pattern matching must work regardless of letter case.
    """

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".db", delete=False, encoding="utf-8")
        self.tmp.write("admin/login.php\n")
        self.tmp.write("union select\n")
        self.tmp.close()
        self.engine = DetectionEngine(self.tmp.name)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_uppercase_uri_matches_lowercase_pattern(self):
        """TC-04a: 'ADMIN/LOGIN.PHP' should match pattern 'admin/login.php'."""
        entry = {
            "ip": "1.2.3.4", "timestamp": None, "method": "POST",
            "uri": "/ADMIN/LOGIN.PHP", "query_string": "",
            "status_code": 200, "bytes": 0
        }
        matches = self.engine.check_request(entry)
        self.assertGreater(len(matches), 0, "Uppercase URI did not match!")

    def test_mixed_case_sql_injection(self):
        """TC-04b: 'UnIoN SeLeCt' should still be detected."""
        entry = {
            "ip": "1.2.3.4", "timestamp": None, "method": "GET",
            "uri": "/page", "query_string": "q=UnIoN+SeLeCt+1,2,3",
            "status_code": 200, "bytes": 0
        }
        matches = self.engine.check_request(entry)
        self.assertGreater(len(matches), 0, "Mixed case SQL injection not detected!")


class TestTC05CorruptedInput(unittest.TestCase):
    """
    TCS-05: Empty or Corrupted Line Handling.
    Objective: The program must not crash on bad input.
    """

    def setUp(self):
        self.parser = LogParser()

    def test_empty_line_returns_none(self):
        """TC-05a: An empty line should return None without crashing."""
        result = self.parser.parse_line("", line_number=1)
        self.assertIsNone(result)

    def test_whitespace_line_returns_none(self):
        """TC-05b: A whitespace-only line should return None."""
        result = self.parser.parse_line("   \n", line_number=2)
        self.assertIsNone(result)

    def test_garbage_text_returns_none(self):
        """TC-05c: Random text that is not a log line should return None."""
        result = self.parser.parse_line("this is not a log line!!!", line_number=3)
        self.assertIsNone(result)

    def test_parser_continues_after_bad_line(self):
        """TC-05d: After a bad line the parser should still handle the next good line."""
        self.parser.parse_line("garbage", line_number=1)
        good_line = '127.0.0.1 - - [12/May/2026:06:00:00 +0200] "GET /ok HTTP/1.1" 200 100 "-" "-"'
        result = self.parser.parse_line(good_line, line_number=2)
        self.assertIsNotNone(result)


class TestTC06StreamingArchitecture(unittest.TestCase):
    """
    TCS-06: Resource Consumption / Streaming Architecture.
    Objective: parse_file() must use a generator, not load everything at once.
    """

    def test_parse_file_returns_a_generator(self):
        """TC-06: parse_file() should return a generator object."""
        import types

        tmp_log = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8")
        tmp_log.write('127.0.0.1 - - [12/May/2026:06:00:00 +0200] "GET /a HTTP/1.1" 200 100 "-" "-"\n')
        tmp_log.write('127.0.0.1 - - [12/May/2026:06:00:01 +0200] "GET /b HTTP/1.1" 404 50 "-" "-"\n')
        tmp_log.close()

        parser = LogParser()
        result = parser.parse_file(tmp_log.name)

        self.assertIsInstance(result, types.GeneratorType,
            "parse_file() should return a generator, not a list!")

        os.unlink(tmp_log.name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
