// script.js
// ------------------------------------------------------------
// Handles the scan form: client-side validation, the AJAX call
// to /scan, and rendering the results table.
// ------------------------------------------------------------

const form = document.getElementById("scan-form");
const scanBtn = document.getElementById("scan-btn");
const errorBox = document.getElementById("error-box");
const statusLine = document.getElementById("status-line");
const progressWrap = document.getElementById("progress-wrap");
const summaryGrid = document.getElementById("summary-grid");
const resultsTable = document.getElementById("results-table");
const resultsBody = document.getElementById("results-body");
const noResults = document.getElementById("no-results");

function resetResultsUI() {
  errorBox.classList.add("hidden");
  errorBox.textContent = "";
  summaryGrid.classList.add("hidden");
  resultsTable.classList.add("hidden");
  noResults.classList.add("hidden");
  resultsBody.innerHTML = "";
}

function showError(message) {
  errorBox.textContent = "⚠ " + message;
  errorBox.classList.remove("hidden");
  statusLine.textContent = "Scan failed.";
}

function validateClientSide(target, startPort, endPort) {
  if (!target) {
    return "Please enter a target hostname or IP address.";
  }
  if (Number.isNaN(startPort) || Number.isNaN(endPort)) {
    return "Start and end ports must be numbers.";
  }
  if (startPort < 1 || endPort > 65535) {
    return "Ports must be between 1 and 65535.";
  }
  if (startPort > endPort) {
    return "Start port cannot be greater than end port.";
  }
  return null;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  resetResultsUI();

  const target = document.getElementById("target").value.trim();
  const startPort = parseInt(document.getElementById("start_port").value, 10);
  const endPort = parseInt(document.getElementById("end_port").value, 10);

  const clientError = validateClientSide(target, startPort, endPort);
  if (clientError) {
    showError(clientError);
    return;
  }

  scanBtn.disabled = true;
  scanBtn.textContent = "⏳ Scanning...";
  statusLine.textContent = `Scanning ${target} (ports ${startPort}-${endPort})...`;
  progressWrap.classList.remove("hidden");

  try {
    const response = await fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: target,
        start_port: startPort,
        end_port: endPort,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      showError(data.error || "An unknown error occurred.");
      return;
    }

    renderResults(data);
  } catch (networkErr) {
    showError(
      "Could not reach the scanner backend. Is the Flask server running?"
    );
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "▶ Start Scan";
    progressWrap.classList.add("hidden");
  }
});

function renderResults(data) {
  statusLine.textContent = `Scan complete for ${data.target_input}.`;

  document.getElementById("sum-target").textContent = data.target_input;
  document.getElementById("sum-ip").textContent = data.resolved_ip;
  document.getElementById("sum-range").textContent =
    `${data.start_port}-${data.end_port}`;
  document.getElementById("sum-scanned").textContent = data.total_scanned;
  document.getElementById("sum-open").textContent = data.open_ports.length;
  document.getElementById("sum-duration").textContent =
    `${data.duration_seconds}s`;
  summaryGrid.classList.remove("hidden");

  if (data.open_ports.length === 0) {
    noResults.classList.remove("hidden");
    return;
  }

  data.open_ports.forEach((portResult) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${portResult.port}</td>
      <td class="status-open">OPEN</td>
      <td>${portResult.service}</td>
    `;
    resultsBody.appendChild(row);
  });

  resultsTable.classList.remove("hidden");
}
