"""
log_parser.py - Apache2 log file parser module.

This module reads the log file line by line and turns
each raw text line into a Python dictionary.
"""

import re
import sys
from datetime import datetime


class LogParser:
    """
    Parses Apache2 Combined Log Format lines.

    A typical log line looks like this:
    83.149.9.216 - - [17/May/2015:10:05:03 +0000] "GET /index.html HTTP/1.1" 200 512
    """

    # This regex pattern finds the data fields in a log line.
    # Each part in parentheses (...) captures one piece of data.
    LOG_PATTERN = re.compile(
        r'^(\S+)'           # group 1: IP address
        r' \S+ \S+'         # we skip these two fields
        r' \[([^\]]+)\]'    # group 2: timestamp (between [ and ])
        r' "(\S+)'          # group 3: HTTP method (GET, POST, etc.)
        r' (\S+)'           # group 4: URI (e.g. /page.html?q=hello)
        r' \S+"'            # HTTP version, we skip it
        r' (\d+)'           # group 5: status code (200, 404, etc.)
        r' (\S+)'           # group 6: bytes transferred
    )

    # Apache writes timestamps like: 17/May/2015:10:05:03 +0000
    TIMESTAMP_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

    def parse_line(self, line, line_number=0):
        """
        Parses one log line and returns a dictionary.
        Returns None if the line is malformed.

        Args:
            line (str): One raw line from the log file.
            line_number (int): The line number, used in error messages.

        Returns:
            dict: The extracted fields, or None if parsing failed.
        """

        # Remove spaces and newline character from the start and end
        line = line.strip()

        # Skip empty lines
        if not line:
            return None

        # Try to match the line against our pattern
        match = self.LOG_PATTERN.match(line)

        # If it does not match, the line is malformed
        if match is None:
            print(f"WARNING: Line {line_number} is malformed, skipping: {line[:60]}", file=sys.stderr)
            return None

        # Extract the data from the match groups
        ip = match.group(1)
        timestamp_str = match.group(2)
        method = match.group(3)
        full_uri = match.group(4)
        status_code = int(match.group(5))
        bytes_str = match.group(6)

        # Convert the timestamp string to a real datetime object
        try:
            timestamp = datetime.strptime(timestamp_str, self.TIMESTAMP_FORMAT)
        except ValueError:
            timestamp = None

        # Split the URI and the query string at the "?" character
        # Example: /search?q=hello -> uri=/search, query=q=hello
        if "?" in full_uri:
            uri, query_string = full_uri.split("?", 1)
        else:
            uri = full_uri
            query_string = ""

        # The bytes field can be "-" when no data was transferred
        if bytes_str == "-":
            bytes_count = 0
        else:
            try:
                bytes_count = int(bytes_str)
            except ValueError:
                bytes_count = 0

        return {
            "ip": ip,
            "timestamp": timestamp,
            "method": method,
            "uri": uri,
            "query_string": query_string,
            "status_code": status_code,
            "bytes": bytes_count
        }

    def parse_file(self, file_path):
        """
        Reads the log file line by line using a generator.

        This way only one line is in memory at a time,
        so even a 10 GB file won't run out of RAM.

        Args:
            file_path (str): Path to the Apache log file.

        Yields:
            dict: One parsed log entry at a time.
        """
        with open(file_path, "r", encoding="utf-8", errors="replace") as log_file:
            for line_number, line in enumerate(log_file, start=1):
                result = self.parse_line(line, line_number)
                if result is not None:
                    yield result
