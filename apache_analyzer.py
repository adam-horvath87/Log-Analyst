"""
apache_analyzer.py - Apache2 Log Analyzer main program.

Usage:
    python3 apache_analyzer.py --file access.log
    python3 apache_analyzer.py --file access.log --scan --database patterns.db
    python3 apache_analyzer.py --file access.log --scan --database patterns.db --threshold 5
"""

import sys

from log_parser import LogParser
from security_engine import DetectionEngine


def read_arguments():
    """
    Reads command line arguments from sys.argv manually.

    sys.argv is a list of the words typed in the terminal.
    Example: ['apache_analyzer.py', '--file', 'access.log', '--scan']

    Returns:
        tuple: (log_file, database, scan_mode, burst_threshold)
    """
    args = sys.argv

    log_file = None
    database = None
    scan_mode = False
    burst_threshold = 10

    # Go through the arguments and find the values
    i = 0
    while i < len(args):
        if args[i] == "--file":
            log_file = args[i + 1]
            i += 2
        elif args[i] == "--database":
            database = args[i + 1]
            i += 2
        elif args[i] == "--scan":
            scan_mode = True
            i += 1
        elif args[i] == "--threshold":
            burst_threshold = int(args[i + 1])
            i += 2
        else:
            i += 1

    # If no log file was given, stop the program
    if log_file is None:
        print("ERROR: You must provide the --file argument!", file=sys.stderr)
        print("Example: python3 apache_analyzer.py --file access.log", file=sys.stderr)
        sys.exit(2)

    # If scan mode is on but no database was given, stop the program
    if scan_mode and database is None:
        print("ERROR: --scan also requires --database!", file=sys.stderr)
        sys.exit(2)

    return log_file, database, scan_mode, burst_threshold


def print_statistics(stats):
    """
    Prints the final summary report to stderr.
    Diagnostic messages go to stderr as required by the specification.

    Args:
        stats (dict): The collected statistics.
    """
    print("\n" + "=" * 55, file=sys.stderr)
    print("  ANALYSIS COMPLETE - SUMMARY REPORT", file=sys.stderr)
    print("=" * 55, file=sys.stderr)

    print(f"\n  Total lines processed : {stats['total_lines']}", file=sys.stderr)
    print(f"  Total threats found   : {stats['total_threats']}", file=sys.stderr)

    # HTTP status code summary
    print("\n  HTTP Status Codes:", file=sys.stderr)
    print(f"    2xx (Success)      : {stats['count_2xx']}", file=sys.stderr)
    print(f"    3xx (Redirect)     : {stats['count_3xx']}", file=sys.stderr)
    print(f"    4xx (Client Error) : {stats['count_4xx']}", file=sys.stderr)
    print(f"    5xx (Server Error) : {stats['count_5xx']}", file=sys.stderr)

    # Top 10 most requested URIs
    print("\n  Top 10 Most Requested URIs:", file=sys.stderr)
    sorted_uris = sorted(stats["uri_counter"].items(), key=lambda x: x[1], reverse=True)
    for i, (uri, count) in enumerate(sorted_uris[:10], start=1):
        print(f"    {i:2}. [{count:>6} hits] {uri}", file=sys.stderr)

    # Top 3 attacker IPs (only when threats were found)
    if stats["total_threats"] > 0:
        print("\n  Top 3 Attacker IPs:", file=sys.stderr)
        sorted_attackers = sorted(stats["attacker_ips"].items(), key=lambda x: x[1], reverse=True)
        for i, (ip, count) in enumerate(sorted_attackers[:3], start=1):
            print(f"    {i}. {ip} ({count} threat(s))", file=sys.stderr)

    # Top 10 most active IPs
    print("\n  Top 10 Most Active IPs:", file=sys.stderr)
    sorted_ips = sorted(stats["ip_counter"].items(), key=lambda x: x[1], reverse=True)
    for i, (ip, count) in enumerate(sorted_ips[:10], start=1):
        print(f"    {i:2}. [{count:>6} reqs] {ip}", file=sys.stderr)

    print("\n" + "=" * 55, file=sys.stderr)


def main():
    """
    Main function - the program starts here.
    """

    # Step 1: Read the command line arguments
    log_file, database, scan_mode, burst_threshold = read_arguments()

    # Step 2: Create the parser and the detection engine
    parser = LogParser()

    engine = None
    if scan_mode:
        engine = DetectionEngine(database, burst_threshold)

    # Step 3: Set up the statistics dictionaries
    stats = {
        "total_lines": 0,
        "total_threats": 0,
        "count_2xx": 0,
        "count_3xx": 0,
        "count_4xx": 0,
        "count_5xx": 0,
        "ip_counter": {},
        "uri_counter": {},
        "attacker_ips": {}
    }

    print(f"INFO: Starting analysis of: {log_file}", file=sys.stderr)

    # Step 4: Open the log file - stop if it does not exist
    try:
        entries = parser.parse_file(log_file)
    except FileNotFoundError:
        print(f"FATAL ERROR: Log file not found: {log_file}", file=sys.stderr)
        sys.exit(2)
    except PermissionError:
        print(f"FATAL ERROR: Cannot read file: {log_file}", file=sys.stderr)
        sys.exit(2)

    threat_found = False

    # Step 5: Go through every log entry one by one
    for entry in entries:
        stats["total_lines"] += 1

        # Print a progress message every 1000 lines (goes to stderr)
        if stats["total_lines"] % 1000 == 0:
            print(f"INFO: Processing... {stats['total_lines']} lines done.", file=sys.stderr)

        # Count requests per IP
        ip = entry["ip"]
        if ip not in stats["ip_counter"]:
            stats["ip_counter"][ip] = 0
        stats["ip_counter"][ip] += 1

        # Count requests per URI (lowercase for grouping)
        uri = entry["uri"].lower()
        if uri not in stats["uri_counter"]:
            stats["uri_counter"][uri] = 0
        stats["uri_counter"][uri] += 1

        # Count HTTP status codes by group
        status = entry["status_code"]
        if 200 <= status < 300:
            stats["count_2xx"] += 1
        elif 300 <= status < 400:
            stats["count_3xx"] += 1
        elif 400 <= status < 500:
            stats["count_4xx"] += 1
        elif 500 <= status < 600:
            stats["count_5xx"] += 1

        # Security check (only when --scan was given)
        if engine is not None:

            # Check for attack patterns
            matches = engine.check_request(entry)
            if matches:
                threat_found = True
                stats["total_threats"] += 1

                # Count threats per attacker IP
                if ip not in stats["attacker_ips"]:
                    stats["attacker_ips"][ip] = 0
                stats["attacker_ips"][ip] += 1

                pattern_list = ", ".join(matches)

                # Threats go to STDOUT as required by the specification
                print(
                    f"THREAT | IP: {entry['ip']} | "
                    f"URI: {entry['uri']}?{entry['query_string']} | "
                    f"Matched: [{pattern_list}]"
                )

            # Check for burst / DoS behavior
            is_burst = engine.check_burst(entry)
            if is_burst:
                threat_found = True
                print(f"BURST  | IP: {entry['ip']} is sending too many requests per second!")

    # Step 6: Print the final statistics report to stderr
    print_statistics(stats)

    # Step 7: Exit with the correct exit code
    # 0 = success, no threats found
    # 1 = success, but at least one threat was found
    if threat_found:
        sys.exit(1)
    else:
        sys.exit(0)


# Only run main() when the script is run directly,
# not when it is imported by another file (like the tests)
if __name__ == "__main__":
    main()
