"""
app.py
------------------------------------------------------------
Flask Web Application for the Network Security Port Scanner.

Run with:
    python app.py

Then open:
    http://127.0.0.1:5000

This file is intentionally kept thin: all scanning logic lives in
scanner.py. app.py is only responsible for:
    - Rendering the HTML page
    - Reading/validating form input
    - Calling the scanner engine
    - Returning results (as JSON for the AJAX scan request)

------------------------------------------------------------
LEGAL NOTICE: Only scan hosts you own or are authorized to test.
------------------------------------------------------------
"""

from flask import Flask, render_template, request, jsonify

from scanner import (
    scan_ports,
    ScannerValidationError,
    ScannerHostError,
    MAX_PORTS_PER_SCAN,
    MIN_PORT,
    MAX_PORT,
)

app = Flask(__name__)


@app.route("/")
def index():
    """Render the main scanner page."""
    return render_template(
        "index.html",
        min_port=MIN_PORT,
        max_port=MAX_PORT,
        max_ports_per_scan=MAX_PORTS_PER_SCAN,
    )


@app.route("/scan", methods=["POST"])
def scan():
    """
    AJAX endpoint used by the front-end JavaScript.

    Expects JSON body:
        {
            "target": "example.com",
            "start_port": 1,
            "end_port": 100
        }

    Returns JSON:
        On success -> scan summary + list of open ports.
        On failure -> {"error": "human readable message"} with HTTP 400.
    """
    data = request.get_json(silent=True) or {}

    target = data.get("target", "")
    start_port = data.get("start_port")
    end_port = data.get("end_port")

    try:
        summary = scan_ports(
            target=target,
            start_port=start_port,
            end_port=end_port,
        )
    except (ScannerValidationError, ScannerHostError) as err:
        # Expected, user-facing errors -> return a clean 400 response.
        return jsonify({"error": str(err)}), 400
    except Exception as unexpected:
        # Anything unforeseen (e.g. network stack issue) -> generic 500.
        return jsonify({"error": f"Unexpected server error: {unexpected}"}), 500

    return jsonify({
        "target_input": summary.target_input,
        "resolved_ip": summary.resolved_ip,
        "start_port": summary.start_port,
        "end_port": summary.end_port,
        "total_scanned": summary.total_scanned,
        "duration_seconds": summary.duration_seconds,
        "closed_count": summary.closed_count,
        "open_ports": [
            {"port": r.port, "status": r.status, "service": r.service}
            for r in summary.open_ports
        ],
    })


@app.errorhandler(404)
def not_found(_e):
    return jsonify({"error": "Not found"}), 404


if __name__ == "__main__":
    # debug=True is fine for local learning/dev use only.
    # Never run a Flask debug server exposed to the internet.
    app.run(debug=True, host="127.0.0.1", port=5000)
