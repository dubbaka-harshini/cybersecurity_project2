"""
cli.py
------------------------------------------------------------
Command-Line Interface for the Network Security Port Scanner.

Usage:
    python cli.py

You will be prompted for:
    1. Target hostname or IP address
    2. Start port
    3. End port

Example session:
    Enter target hostname or IP: scanme.nmap.org
    Enter start port [1]: 20
    Enter end port [1024]: 100

------------------------------------------------------------
LEGAL NOTICE: Only scan hosts you own or are authorized to test.
------------------------------------------------------------
"""

import sys
from scanner import (
    scan_ports,
    ScannerValidationError,
    ScannerHostError,
    MAX_PORTS_PER_SCAN,
)

BANNER = r"""
==========================================================
   NETWORK SECURITY PORT SCANNER (Educational Tool)
==========================================================
 For authorized use only. Scanning systems without explicit
 permission may be illegal in your jurisdiction.
==========================================================
"""


def prompt_target() -> str:
    return input("Enter target hostname or IP address: ").strip()


def prompt_port(label: str, default: int) -> str:
    raw = input(f"Enter {label} port [{default}]: ").strip()
    return raw if raw else str(default)


def print_progress(done: int, total: int) -> None:
    bar_len = 30
    filled = int(bar_len * done / total)
    bar = "#" * filled + "-" * (bar_len - filled)
    sys.stdout.write(f"\rScanning [{bar}] {done}/{total}")
    sys.stdout.flush()
    if done == total:
        print()  # newline after progress bar finishes


def main():
    print(BANNER)

    target = prompt_target()
    start_port = prompt_port("start", 1)
    end_port = prompt_port("end", 1024)

    print(
        f"\nStarting scan of '{target}' "
        f"(ports {start_port}-{end_port}, max {MAX_PORTS_PER_SCAN} per scan)...\n"
    )

    try:
        summary = scan_ports(
            target=target,
            start_port=start_port,
            end_port=end_port,
            progress_callback=print_progress,
        )
    except (ScannerValidationError, ScannerHostError) as err:
        print(f"\n[ERROR] {err}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nScan cancelled by user.")
        sys.exit(1)

    # ---- Display results ----
    print("\n" + "=" * 58)
    print(f" TARGET      : {summary.target_input} ({summary.resolved_ip})")
    print(f" PORT RANGE  : {summary.start_port}-{summary.end_port}")
    print(f" PORTS SCANNED: {summary.total_scanned}")
    print(f" TIME TAKEN  : {summary.duration_seconds}s")
    print("=" * 58)

    if summary.open_ports:
        print(f"\n OPEN PORTS ({len(summary.open_ports)} found):\n")
        print(f" {'PORT':<8}{'STATUS':<10}{'SERVICE'}")
        print(" " + "-" * 34)
        for result in summary.open_ports:
            print(f" {result.port:<8}{result.status.upper():<10}{result.service}")
    else:
        print("\n No open ports found in the given range.")

    print(f"\n CLOSED/FILTERED PORTS: {summary.closed_count}")
    print("\nScan complete.\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as unexpected:
        # Catch-all so beginners never see a raw traceback in the terminal.
        print(f"\n[UNEXPECTED ERROR] {unexpected}")
        sys.exit(1)
