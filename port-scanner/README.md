# NetScan — Network Security Port Scanner

A beginner-friendly, fully-working **TCP port scanner** with both a
command-line interface and a clean, cybersecurity-themed web UI built with
Python and Flask. Built as a learning project to demonstrate core
networking and security-tooling concepts: sockets, TCP connect scanning,
input validation, threading, and safe error handling.

> ## ⚠️ Authorized Use Only
> This tool must **only** be used against systems you own, or systems for
> which you have received **explicit, written authorization** to test.
> Scanning networks or hosts without permission may violate laws such as
> the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse Act, or
> equivalent legislation in your country — even a simple "is this port
> open" check can be considered unauthorized access. Use responsibly, and
> only on infrastructure you control (e.g. your own machine, a local VM,
> or a host like `scanme.nmap.org` that explicitly permits scanning).

---

## 1. Project Objective

Port scanning is one of the first techniques taught in network security —
it's how you discover which services are exposed on a host before you can
assess them further. This project implements a **TCP connect scan** from
scratch using Python's built-in `socket` library (no external scanning
libraries), wraps it in solid input validation and error handling, and
presents results through two interfaces:

1. A **CLI tool** (`cli.py`) — for quick terminal-based scans.
2. A **Flask web app** (`app.py`) — a clean, dark, terminal-styled UI for
   running scans from a browser.

The goal is to demonstrate, in an approachable and well-documented way,
how a basic security scanning tool is designed and built end to end —
making it a good portfolio piece and a good topic to walk through in a
cybersecurity interview.

---

## 2. Features

- **TCP Connect Scanning** — attempts a real TCP handshake against each
  port to determine open/closed status (the same fundamental technique
  used by tools like Nmap's `-sT` scan).
- **Hostname or IP target support** — accepts either (`example.com` or
  `192.168.1.1`), with DNS resolution and IP literal validation.
- **Custom port ranges** — scan any range from 1–65535 (capped at 1024
  ports per scan by default, to keep scans fast and considerate — see
  §6).
- **Concurrent scanning** — uses a `ThreadPoolExecutor` so a 1000-port
  scan finishes in a couple of seconds rather than minutes.
- **Service name identification** — open ports are matched against
  well-known service names (e.g. port 22 → `ssh`, port 80 → `http`).
- **Robust input validation & error handling**:
  - Empty / malformed target input
  - Unresolvable hostnames (DNS failure)
  - Invalid or out-of-range ports
  - Start port greater than end port
  - Oversized port ranges
  - Connection timeouts / refused connections / unreachable hosts
  - Server-side and client-side validation in the web app
- **Clean results display** — a readable table (CLI) or styled results
  panel (web) showing target, resolved IP, port, status, and service.
- **Cybersecurity-themed UI** — dark terminal aesthetic, monospace font,
  scanline effect, and a prominent authorized-use banner.

---

## 3. Technologies Used

| Layer            | Technology                                |
|-------------------|--------------------------------------------|
| Core scan engine   | Python 3 standard library (`socket`, `ipaddress`, `concurrent.futures`) |
| CLI interface      | Python (`cli.py`)                         |
| Web backend        | Flask 3                                   |
| Web frontend       | HTML5, vanilla CSS, vanilla JavaScript (no frameworks) |
| Communication      | JSON over `fetch()` (AJAX) between browser and Flask |

No third-party scanning libraries are used — the scanning logic itself is
implemented directly with raw sockets so the mechanics are fully visible
and explainable.

---

## 4. Project Structure

```
port-scanner/
├── app.py                # Flask web app (routes, request handling)
├── cli.py                # Command-line interface
├── scanner.py            # Core scanning engine (shared by CLI & web)
├── requirements.txt      # Python dependencies
├── README.md
├── templates/
│   └── index.html        # Web UI page
└── static/
    ├── style.css          # Cybersecurity-themed dark styling
    └── script.js          # Form handling + AJAX + results rendering
```

The scanning logic is deliberately isolated in **`scanner.py`**, with no
Flask or CLI-specific code inside it. This separation of concerns means
the same tested scanning engine powers both interfaces, and it could be
imported into any other Python project.

---

## 5. Setup & Execution Instructions

### Prerequisites
- Python 3.8+
- pip

### Installation

```bash
# 1. Clone or download this repository
git clone <your-repo-url>
cd port-scanner

# 2. (Recommended) create a virtual environment
python -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Running the Web App

```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser, enter a target and
port range, and click **Start Scan**.

### Running the CLI Version

```bash
python cli.py
```

You'll be prompted for a target and a port range interactively, and
results will print directly to the terminal.

### Example (safe to try — this host permits scanning)

```
Enter target hostname or IP address: scanme.nmap.org
Enter start port [1]: 20
Enter end port [1024]: 100
```

---

## 6. How the Scanner Works

1. **Input validation** — `scanner.py` validates the target string
   (rejects empty input, URLs with `http://`, spaces, etc.) and resolves
   it: if it's already a valid IP address it's used directly; otherwise
   `socket.gethostbyname()` performs DNS resolution and raises a clear
   error if resolution fails.

2. **Port range validation** — start/end ports must be integers between
   1 and 65535, start ≤ end, and the range must be no larger than
   **1024 ports** by default. This cap exists so a single scan can't
   accidentally (or deliberately) flood a target with thousands of
   simultaneous connections, and so the web request doesn't hang
   indefinitely — good practice for any tool that touches a network you
   don't fully control.

3. **TCP connect scan** — for each port, the scanner opens a
   `socket.socket(AF_INET, SOCK_STREAM)` and calls `connect_ex()` with a
   short timeout (0.7s by default):
   - Return code `0` → the TCP three-way handshake succeeded → **port is
     open**.
   - Any other result (connection refused, timeout, unreachable) →
     **port is treated as closed/filtered**.

   This is a "connect scan," the simplest and most portable scan type
   (it doesn't require raw sockets or elevated OS privileges, unlike a
   SYN/stealth scan).

4. **Concurrency** — ports are scanned in parallel using a
   `ThreadPoolExecutor` (100 worker threads by default), since each
   socket connection spends most of its time waiting on the network, not
   on CPU — an ideal case for threading over multiprocessing.

5. **Results aggregation** — open ports are collected, sorted, and
   annotated with a best-guess service name via
   `socket.getservbyport()`. A summary (target, resolved IP, duration,
   counts) is returned alongside the list.

6. **Presentation** — the CLI prints a formatted table; the web app
   returns JSON, and `script.js` renders it into a styled results panel.

---

## 7. Security Considerations

- **Authorization is the user's responsibility.** This tool performs no
  identity or ownership verification of the target — the person running
  it must ensure they have permission. The UI and README both carry
  explicit warnings, but the tool cannot enforce authorization
  technically.
- **Rate limiting / scan size cap.** The `MAX_PORTS_PER_SCAN` limit
  (1024 by default) reduces the risk of accidentally overwhelming a
  target host or triggering intrusion-detection alarms during learning
  and testing.
- **No raw sockets / no privilege escalation.** This scanner intentionally
  uses a full TCP connect scan (not a SYN/stealth scan), so it never
  needs root/administrator privileges or raw socket access — which also
  makes its network behavior more transparent and less evasive.
- **Local-only web server by default.** `app.py` binds to
  `127.0.0.1` (localhost) and runs with Flask's development server.
  **Do not** expose this app to the public internet or run it with
  `debug=True` in any environment other than local learning/testing —
  the Flask debugger allows arbitrary code execution if reachable by an
  attacker.
- **No data persistence.** Scan results are not logged or stored
  anywhere; each scan is stateless and results only live in the
  browser/terminal session.
- **Error messages are sanitized.** Validation and connection errors are
  caught and converted into short, user-facing messages rather than
  leaking raw stack traces.

---

## 8. Future Improvements

- Add **UDP scanning** support (requires different logic, since UDP has
  no handshake to confirm state).
- Add **banner grabbing** for open ports (reading the first bytes a
  service sends, e.g. an HTTP server header or SSH version string) to
  aid service fingerprinting.
- Add **scan history** (optional local storage/database) so past scans
  can be reviewed.
- Add **export options** (CSV/JSON download of results) from the web UI.
- Add **rate-limiting/backoff configuration** in the UI so users can
  trade off scan speed vs. how "noisy" the scan is.
- Add **IPv6 support** throughout the scanning engine.
- Add a **Dockerfile** for one-command containerized setup.
- Add **unit tests** for `scanner.py` (e.g. mocking sockets to test
  validation logic and open/closed classification without needing a
  real network).

---

## 9. Explaining This Project in an Interview

A good way to walk through this project:

1. **Problem** — "I wanted to understand how port scanners like Nmap
   work at a fundamental level, so I built a simplified TCP connect
   scanner from scratch using raw Python sockets."
2. **Design decision** — "I separated the scanning engine (`scanner.py`)
   from the interface layer (CLI and Flask), so the same tested logic
   powers both — this is a basic example of separation of concerns."
3. **Networking concept** — "A connect scan works by attempting a full
   TCP handshake — `connect_ex()` returning 0 means the handshake
   succeeded, so the port is open. This doesn't require raw sockets or
   root access, unlike a SYN scan."
4. **Performance concern & solution** — "Scanning sequentially is slow
   because each connection attempt can take up to the timeout value, so
   I used a `ThreadPoolExecutor` to run many connection attempts
   concurrently, since they're I/O-bound, not CPU-bound."
5. **Security/ethics awareness** — "I added a hard cap on ports-per-scan
   and made the authorized-use requirement explicit in the UI, because a
   tool like this can be misused if there's no built-in restraint."
6. **What I'd add next** — point to the Future Improvements section
   (UDP scanning, banner grabbing, etc.) to show awareness of the tool's
   current limitations.

---

## License

This project is provided for educational purposes. Use it responsibly
and only against systems you are authorized to test.
