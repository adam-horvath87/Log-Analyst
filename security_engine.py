"""
security_engine.py - Signature-based threat detection engine.

This module loads attack patterns from the patterns.db file
and checks each log entry against them.
"""

import sys
from urllib.parse import unquote_plus


class DetectionEngine:
    """
    Compares log entries against known attack signatures.

    Patterns are loaded from a plain text file (one pattern per line).
    The engine checks the URI and query string of each log entry.
    """

    def __init__(self, database_path, burst_threshold=10):
        """
        Creates the engine and loads the patterns.

        Args:
            database_path (str): Path to the patterns.db file.
            burst_threshold (int): Max requests per second per IP before flagging as DoS.
        """
        self.burst_threshold = burst_threshold
        self.patterns = self.load_patterns(database_path)

        # This dictionary counts requests per IP per second
        # Example: { "192.168.1.1": { "20150517100503": 5 } }
        self.request_counter = {}

    def load_patterns(self, database_path):
        """
        Reads the attack patterns from the text file.
        Lines starting with '#' are comments and are skipped.
        All patterns are stored in lowercase for case-insensitive matching.

        Args:
            database_path (str): Path to the patterns file.

        Returns:
            list: A list of lowercase attack pattern strings.
        """
        patterns = []

        try:
            with open(database_path, "r", encoding="utf-8") as db_file:
                for line in db_file:
                    line = line.strip()

                    # Skip empty lines and comment lines
                    if not line or line.startswith("#"):
                        continue

                    # Store in lowercase so the search is case-insensitive
                    patterns.append(line.lower())

        except FileNotFoundError:
            print(f"FATAL ERROR: Pattern database not found: {database_path}", file=sys.stderr)
            sys.exit(2)

        print(f"INFO: Loaded {len(patterns)} attack signatures.", file=sys.stderr)
        return patterns

    def check_request(self, log_entry):
        """
        Checks if a log entry contains any known attack patterns.

        Returns a list of matched patterns.
        If the list is empty, there is no threat.

        Args:
            log_entry (dict): A parsed log entry from LogParser.

        Returns:
            list: The matched pattern strings.
        """
        # Combine URI and query string, then URL-decode and lowercase
        # URL-decoding is needed because attackers often encode their payloads
        # Example: "UNION+SELECT" is actually "UNION SELECT"
        raw_request = log_entry["uri"] + "?" + log_entry["query_string"]
        request = unquote_plus(raw_request).lower()

        matches = []

        for pattern in self.patterns:
            if pattern in request:
                matches.append(pattern)

        return matches

    def check_burst(self, log_entry):
        """
        Checks if an IP is sending too many requests per second (possible DoS).

        Args:
            log_entry (dict): A parsed log entry from LogParser.

        Returns:
            bool: True if the IP exceeds the burst threshold.
        """
        if log_entry["timestamp"] is None:
            return False

        ip = log_entry["ip"]
        timestamp = log_entry["timestamp"]

        # Create a key like "20150517100503" to identify the second
        second_key = timestamp.strftime("%Y%m%d%H%M%S")

        # Add the IP to the counter if it is not there yet
        if ip not in self.request_counter:
            self.request_counter[ip] = {}

        # Add this second to the counter if it is not there yet
        if second_key not in self.request_counter[ip]:
            self.request_counter[ip][second_key] = 0

        # Increase the counter
        self.request_counter[ip][second_key] += 1

        # Check if the threshold was exceeded
        if self.request_counter[ip][second_key] > self.burst_threshold:
            return True

        return False
