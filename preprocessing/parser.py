"""
MFAT - parser.py
Converts raw Volatility text output into structured Python dicts/lists
"""

import re


# Processes considered suspicious in normal memory forensics
# NEW - only flag processes that are genuinely abnormal/abused
SUSPICIOUS_PROCESS_NAMES = {
    "cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe",
    "wmic.exe", "regsvr32.exe", "at.exe"
}

SUSPICIOUS_PORTS = {4444, 1337, 31337, 8080, 9999, 6666, 5555}
SUSPICIOUS_REMOTE_IPS_PATTERNS = [r"^10\.", r"^192\.168\.", r"^172\.(1[6-9]|2\d|3[01])\."]


def parse_pslist(output):
    """Parse pslist/windows.pslist output into list of process dicts."""
    processes = []
    lines = output.strip().splitlines()
    
    for line in lines:
        # Skip headers and blank lines
        if not line.strip() or line.startswith("Offset") or line.startswith("*") or line.startswith("Volatility"):
            continue
        
        # Vol2 pslist format: Name PID PPID Thds Hnds Sess Wow64 Start Exit
        # Vol3 pslist format: PID PPID ImageFileName ...
        parts = line.split()
        if len(parts) < 4:
            continue
        
        try:
            proc = {
                "name": parts[0] if not parts[0].isdigit() else parts[2],
                "pid": int(parts[1]) if not parts[0].isdigit() else int(parts[0]),
                "ppid": int(parts[2]) if not parts[0].isdigit() else int(parts[1]),
                "raw": line.strip()
            }
            proc["suspicious"] = proc["name"].lower() in SUSPICIOUS_PROCESS_NAMES
            processes.append(proc)
        except (ValueError, IndexError):
            continue
    
    return processes


def parse_netscan(output):
    """Parse netscan output into network connection dicts."""
    connections = []
    lines = output.strip().splitlines()
    
    for line in lines:
        if not line.strip() or "Proto" in line or "Offset" in line or line.startswith("*") or line.startswith("Volatility"):
            continue
        
        parts = line.split()
        if len(parts) < 5:
            continue
        
        try:
            conn = {
                "proto": parts[1] if len(parts) > 6 else parts[0],
                "local": parts[2] if len(parts) > 6 else parts[1],
                "remote": parts[3] if len(parts) > 6 else parts[2],
                "state": parts[4] if len(parts) > 6 else parts[3],
                "raw": line.strip()
            }
            # Flag suspicious ports
            remote = conn["remote"]
            try:
                port = int(remote.split(":")[-1])
                conn["suspicious_port"] = port in SUSPICIOUS_PORTS
            except (ValueError, IndexError):
                conn["suspicious_port"] = False
            
            connections.append(conn)
        except (ValueError, IndexError):
            continue
    
    return connections


def parse_malfind(output):
    """Parse malfind output - extracts suspicious memory regions."""
    hits = []
    current = {}
    lines = output.strip().splitlines()
    
    for line in lines:
        if line.startswith("Process:") or line.startswith("Pid"):
            if current:
                hits.append(current)
            current = {"raw_lines": [line], "has_pe_header": False, "has_exec": False}
            # Extract process name
            m = re.search(r"Process:\s*(\S+)", line)
            if m:
                current["process"] = m.group(1)
        elif current:
            current["raw_lines"].append(line)
            if "MZ" in line or "4d5a" in line.lower():
                current["has_pe_header"] = True
            if "PAGE_EXECUTE" in line or "EXECUTE_READ" in line:
                current["has_exec"] = True
    
    if current:
        hits.append(current)
    
    # Clean up
    result = []
    for h in hits:
        if "process" in h:
            result.append({
                "process": h.get("process", "unknown"),
                "has_pe_header": h["has_pe_header"],
                "has_exec": h["has_exec"],
                "severity": "HIGH" if (h["has_pe_header"] and h["has_exec"]) else "MEDIUM" if h["has_exec"] else "LOW",
                "raw": "\n".join(h.get("raw_lines", []))[:500]
            })
    
    return result


def parse_cmdline(output):
    """Parse cmdline output - look for suspicious commands."""
    commands = []
    SUSPICIOUS_PATTERNS = [
        r"powershell.*-enc",
        r"powershell.*bypass",
        r"certutil.*-decode",
        r"bitsadmin",
        r"mshta.*http",
        r"regsvr32.*scrobj",
        r"wscript.*http",
        r"cmd.*\/c.*del",
        r"net.*user.*\/add",
    ]
    
    for line in output.splitlines():
        if "CommandLine:" in line or "Command line" in line:
            cmd_part = line.split(":", 1)[-1].strip()
            suspicious = False
            matched_pattern = None
            for pattern in SUSPICIOUS_PATTERNS:
                if re.search(pattern, cmd_part, re.IGNORECASE):
                    suspicious = True
                    matched_pattern = pattern
                    break
            commands.append({
                "raw": line.strip(),
                "command": cmd_part,
                "suspicious": suspicious,
                "pattern": matched_pattern
            })
    
    return commands


def build_ioc_summary(processes, connections, malfind_hits, commands):
    """Build a list of Indicators of Compromise (IOCs) from all parsed data."""
    iocs = []

    HIGH_RISK_PROCS = {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe", "rundll32.exe"}
    
    for p in processes:
        if p.get("suspicious"):
            sev = "HIGH" if p["name"].lower() in HIGH_RISK_PROCS else "MEDIUM"
            iocs.append({
                "type": "Suspicious Process",
                "severity": sev,
                "detail": f"{p['name']} (PID {p['pid']})",
                "description": f"Process '{p['name']}' is often abused by malware"
            })
    
    for c in connections:
        if c.get("suspicious_port"):
            iocs.append({
                "type": "Suspicious Network",
                "severity": "HIGH",
                "detail": f"{c['remote']}",
                "description": "Connection to known malware C2 port"
            })
    
    for m in malfind_hits:
        iocs.append({
            "type": "Code Injection",
            "severity": m["severity"],
            "detail": f"In process: {m['process']}",
            "description": "Executable code found in non-image memory region" +
                          (" (PE header detected)" if m["has_pe_header"] else "")
        })
    
    for cmd in commands:
        if cmd.get("suspicious"):
            iocs.append({
                "type": "Suspicious Command",
                "severity": "HIGH",
                "detail": cmd["command"][:100],
                "description": f"Matches pattern: {cmd['pattern']}"
            })
    
    return iocs


def parse_all(raw_findings):
    """Main function: parse all raw plugin output into structured report."""
    # Normalize plugin names (vol2 vs vol3)
    def get(key_v2, key_v3=""):
        return raw_findings.get(key_v2, raw_findings.get(key_v3, ""))
    
    processes  = parse_pslist(get("pslist", "windows.pslist"))
    connections = parse_netscan(get("netscan", "windows.netscan"))
    malfind     = parse_malfind(get("malfind", "windows.malfind"))
    commands    = parse_cmdline(get("cmdline", "windows.cmdline"))
    iocs        = build_ioc_summary(processes, connections, malfind, commands)
    
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    iocs.sort(key=lambda x: severity_order.get(x["severity"], 3))
    
    return {
        "meta": raw_findings.get("_meta", {}),
        "summary": {
            "total_processes": len(processes),
            "suspicious_processes": sum(1 for p in processes if p.get("suspicious")),
            "network_connections": len(connections),
            "suspicious_connections": sum(1 for c in connections if c.get("suspicious_port")),
            "malfind_hits": len(malfind),
            "suspicious_commands": sum(1 for c in commands if c.get("suspicious")),
            "total_iocs": len(iocs),
            "high_iocs": sum(1 for i in iocs if i["severity"] == "HIGH"),
        },
        "iocs": iocs,
        "processes": processes,
        "connections": connections,
        "malfind": malfind,
        "commands": commands,
    }
