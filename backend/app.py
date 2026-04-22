"""
MFAT Backend - app.py
Flask API server: receives memory dumps, runs Volatility, returns parsed results
"""

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import uuid
import threading
import json
import sys
from pathlib import Path
from werkzeug.utils import secure_filename

# Add preprocessing to path
sys.path.insert(0, str(Path(__file__).parent.parent / "preprocessing"))
import runner
import parser as mfat_parser

app = Flask(__name__, static_folder="../frontend")
CORS(app)

UPLOAD_FOLDER = Path("./dump")
RESULTS_FOLDER = Path("./results")
UPLOAD_FOLDER.mkdir(exist_ok=True)
RESULTS_FOLDER.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {".raw", ".vmem", ".mem", ".dmp", ".img", ".bin"}

# In-memory scan status tracker
# { scan_id: { "status": "pending|running|done|error", "progress": 0-100, "message": "..." } }
scan_status = {}


def allowed_file(filename):
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


def run_scan_background(scan_id, image_name):
    """Background thread: runs full scan and saves results."""
    scan_status[scan_id] = {"status": "running", "progress": 5, "message": "Starting scan..."}
    
    try:
        # Set dump dir for runner
        runner.DUMP_DIR = UPLOAD_FOLDER.resolve()
        
        def progress_cb(plugin, output, current, total):
            pct = int(10 + (current / total) * 80)
            scan_status[scan_id] = {
                "status": "running",
                "progress": pct,
                "message": f"Running {plugin} ({current}/{total})"
            }
        
        scan_status[scan_id] = {"status": "running", "progress": 8, "message": "Detecting volatility version..."}
        raw_findings = runner.run_all_plugins(image_name, progress_callback=progress_cb)
        
        scan_status[scan_id] = {"status": "running", "progress": 92, "message": "Parsing results..."}
        report = mfat_parser.parse_all(raw_findings)
        
        # Save results
        result_path = RESULTS_FOLDER / f"{scan_id}.json"
        with open(result_path, "w") as f:
            json.dump(report, f, indent=2)
        
        scan_status[scan_id] = {
            "status": "done",
            "progress": 100,
            "message": f"Scan complete. {report['summary']['total_iocs']} IOC(s) found."
        }
    
    except Exception as e:
        scan_status[scan_id] = {
            "status": "error",
            "progress": 0,
            "message": f"Error: {str(e)}"
        }


# ── Routes ──────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the dashboard."""
    return send_from_directory("../frontend", "dashboard.html")


@app.route("/api/upload", methods=["POST"])
def upload_file():
    """Upload a memory dump and start scanning."""
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400
    
    if not allowed_file(file.filename):
        return jsonify({"error": f"File type not allowed. Supported: {ALLOWED_EXTENSIONS}"}), 400
    
    filename = secure_filename(file.filename)
    save_path = UPLOAD_FOLDER / filename
    file.save(save_path)
    
    scan_id = str(uuid.uuid4())[:8]
    
    # Start background scan
    thread = threading.Thread(target=run_scan_background, args=(scan_id, filename))
    thread.daemon = True
    thread.start()
    
    return jsonify({"scan_id": scan_id, "filename": filename, "message": "Scan started"})


@app.route("/api/status/<scan_id>")
def get_status(scan_id):
    """Poll scan status."""
    status = scan_status.get(scan_id, {"status": "not_found", "progress": 0, "message": "Scan ID not found"})
    return jsonify(status)


@app.route("/api/results/<scan_id>")
def get_results(scan_id):
    """Get full scan results."""
    result_path = RESULTS_FOLDER / f"{scan_id}.json"
    if not result_path.exists():
        return jsonify({"error": "Results not ready yet"}), 404
    
    with open(result_path) as f:
        return jsonify(json.load(f))


@app.route("/api/scans")
def list_scans():
    """List all past scans."""
    scans = []
    for result_file in RESULTS_FOLDER.glob("*.json"):
        sid = result_file.stem
        status = scan_status.get(sid, {})
        scans.append({
            "scan_id": sid,
            "status": status.get("status", "done"),
            "message": status.get("message", "")
        })
    return jsonify(scans)


if __name__ == "__main__":
    print("[*] MFAT Backend starting on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
