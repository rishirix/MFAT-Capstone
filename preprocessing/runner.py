#!/bin/python3
"""
MFAT - runner.py
Runs Volatility 3 plugins via Docker
"""

import subprocess
import json
import os
from pathlib import Path

DUMP_DIR = Path("./dump").resolve()
VOL2_IMAGE = "vol2"
VOL3_IMAGE = "vol3"

VOL3_PLUGINS = [
    "windows.pslist",
    "windows.pstree", 
    "windows.netscan",
    "windows.malfind",
    "windows.cmdline",
    "windows.dlllist",
    "windows.svcscan"
]


def run_docker_vol3(image_name, plugin, extra_args=[]):
    """Run a Volatility 3 plugin via Docker and return stdout."""
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{DUMP_DIR}:/dump",
        VOL3_IMAGE,
        "-f", f"/dump/{image_name}",
        plugin
    ] + extra_args

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=180, encoding='utf-8', errors='replace')
    return result.stdout, result.stderr, result.returncode


def run_all_plugins(image_name, progress_callback=None):
    """Run all vol3 plugins and return dict of results."""
    findings = {}

    for i, plugin in enumerate(VOL3_PLUGINS):
        print(f"[*] Running {plugin} ({i+1}/{len(VOL3_PLUGINS)})...")
        stdout, stderr, code = run_docker_vol3(image_name, plugin)
        findings[plugin] = stdout if code == 0 else f"ERROR: {stderr}"
        
        if progress_callback:
            progress_callback(plugin, stdout, i+1, len(VOL3_PLUGINS))

    findings["_meta"] = {
        "vol_version": "v3",
        "profile": None,
        "image_name": image_name
    }
    return findings


if __name__ == "__main__":
    import sys
    image = sys.argv[1] if len(sys.argv) > 1 else "Challenge.raw"
    results = run_all_plugins(image)
    with open("raw_output.json", "w") as f:
        json.dump(results, f, indent=2)
    print("[+] Done. Output saved to raw_output.json")
