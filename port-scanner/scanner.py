"""
scanner.py
------------------------------------------------------------
Core TCP Port Scanning Engine
------------------------------------------------------------
This module contains all the logic needed to:
  1. Validate a target (hostname or IP address)
  2. Validate a port range
  3. Perform a TCP "connect scan" against each port
  4. Return clean, structured results

It has NO dependency on Flask or any UI framework, so it can be
reused by the command-line tool (cli.py), the web app (app.py),
or imported into your own scripts.

LEGAL / ETHICAL NOTICE
------------------------------------------------------------
Only scan systems you own, or systems you have explicit written
permission to test. Scanning networks without authorization may
violate laws such as the Computer Fraud and Abuse Act (US),
the Computer Misuse Act (UK), or equivalent laws in your country.
------------------------------------------------------------
"""

import socket
import ipaddress
import time
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional


# --------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------

MIN_PORT = 1
MAX_PORT = 65535

# Safety cap so a single scan can't be abused to hammer a host or hang
# the web server forever. Raise this in cli.py usage if you need to scan
# a wider range on your own infrastructure.
MAX_PORTS_PER_SCAN = 1024

DEFAULT_TIMEOUT = 0.7  # seconds, per-port connection timeout
DEFAULT_THREADS = 100  # concurrent worker threads


# --------------------------------------------------------------------------
# Custom exceptions -> these let the UI/CLI show friendly error messages
# instead of raw Python tracebacks.
# --------------------------------------------------------------------------

class ScannerValidationError(Exception):
    """Raised when user-supplied input (target or ports) is invalid."""
    pass


class ScannerHostError(Exception):
    """Raised when the target host cannot be resolved or reached at all."""
    pass


# --------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------

@dataclass
class PortResult:
    port: int
    status: str          # "open" or "closed"
    service: str = ""    # best-guess service name, e.g. "http"
    banner: str = ""      # optional banner text grabbed from the service


@dataclass
class ScanSummary:
    target_input: str          # what the user typed
    resolved_ip: str           # the IP we actually scanned
    start_port: int
    end_port: int
    open_ports: List[PortResult] = field(default_factory=list)
    closed_count: int = 0
    duration_seconds: float = 0.0

    @property
    def total_scanned(self) -> int:
        return (self.end_port - self.start_port + 1)


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------

def resolve_target(target: str) -> str:
    """
    Validate and resolve a hostname or IP address to an IPv4/IPv6 address.

    Raises:
        ScannerValidationError: if the input is empty/malformed.
        ScannerHostError: if the hostname cannot be resolved (DNS failure).
    """
    target = (target or "").strip()
    if not target:
        raise ScannerValidationError("Target cannot be empty.")

    # Basic sanity check: reject obvious junk / spaces / URLs with schemes
    if "://" in target:
        raise ScannerValidationError(
            "Enter a bare hostname or IP (no http:// or https://)."
        )
    if " " in target:
        raise ScannerValidationError("Target cannot contain spaces.")

    # If it's already a valid IP literal, accept it directly.
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass  # not an IP literal -> try DNS resolution below

    # Otherwise, try to resolve it as a hostname.
    try:
        resolved_ip = socket.gethostbyname(target)
        return resolved_ip
    except socket.gaierror:
        raise ScannerHostError(
            f"Could not resolve host '{target}'. Check the spelling or "
            f"your network/DNS connection."
        )


def validate_port_range(start_port, end_port) -> (int, int):
    """
    Validate that start_port/end_port form a sane, safely-sized range.

    Accepts ints or numeric strings. Raises ScannerValidationError with a
    human-readable message on any problem.
    """
    try:
        start_port = int(start_port)
        end_port = int(end_port)
    except (TypeError, ValueError):
        raise ScannerValidationError("Ports must be whole numbers.")

    if start_port < MIN_PORT or end_port > MAX_PORT:
        raise ScannerValidationError(
            f"Ports must be between {MIN_PORT} and {MAX_PORT}."
        )

    if start_port > end_port:
        raise ScannerValidationError(
            "Start port cannot be greater than end port."
        )

    port_count = end_port - start_port + 1
    if port_count > MAX_PORTS_PER_SCAN:
        raise ScannerValidationError(
            f"Range too large ({port_count} ports). "
            f"Please scan {MAX_PORTS_PER_SCAN} ports or fewer at a time "
            f"to keep scans fast and considerate to the target host."
        )

    return start_port, end_port


# --------------------------------------------------------------------------
# Core scanning logic
# --------------------------------------------------------------------------

def _scan_single_port(ip: str, port: int, timeout: float) -> Optional[PortResult]:
    """
    Attempt a TCP connection to a single port ("TCP connect scan").

    A successful connection (return code 0) means the port is OPEN.
    Any connection error (refused, timed out, etc.) means CLOSED/filtered.

    Returns None for closed ports (so callers can just collect the open
    ones), or a PortResult for open ports.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result_code = sock.connect_ex((ip, port))
        if result_code == 0:
            service = _guess_service_name(port)
            return PortResult(port=port, status="open", service=service)
        return None
    except socket.error:
        return None
    finally:
        sock.close()


def _guess_service_name(port: int) -> str:
    """Best-effort lookup of the common service name for a port."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def scan_ports(
    target: str,
    start_port: int,
    end_port: int,
    timeout: float = DEFAULT_TIMEOUT,
    max_workers: int = DEFAULT_THREADS,
    progress_callback=None,
) -> ScanSummary:
    """
    Main entry point: validates input, then scans every port in the given
    range on the target using a thread pool for speed.

    Args:
        target: hostname or IP string, as typed by the user.
        start_port / end_port: inclusive port range.
        timeout: per-connection timeout in seconds.
        max_workers: number of concurrent scanning threads.
        progress_callback: optional callable(done_count, total_count)
            invoked as ports complete, useful for a CLI progress bar.

    Returns:
        ScanSummary with the list of open ports and scan metadata.

    Raises:
        ScannerValidationError / ScannerHostError on bad input.
    """
    resolved_ip = resolve_target(target)
    start_port, end_port = validate_port_range(start_port, end_port)

    ports_to_scan = list(range(start_port, end_port + 1))
    total = len(ports_to_scan)
    open_results: List[PortResult] = []
    completed = 0

    start_time = time.time()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(_scan_single_port, resolved_ip, port, timeout): port
            for port in ports_to_scan
        }
        for future in as_completed(future_to_port):
            completed += 1
            result = future.result()
            if result is not None:
                open_results.append(result)
            if progress_callback:
                progress_callback(completed, total)

    duration = time.time() - start_time
    open_results.sort(key=lambda r: r.port)

    return ScanSummary(
        target_input=target,
        resolved_ip=resolved_ip,
        start_port=start_port,
        end_port=end_port,
        open_ports=open_results,
        closed_count=total - len(open_results),
        duration_seconds=round(duration, 2),
    )
