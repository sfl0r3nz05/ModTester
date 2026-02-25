#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
MetasploitBridge.py  -  System/Core/MetasploitBridge.py
--------------------------------------------------------
Bridges ModTester to Metasploit SCADA auxiliary modules without relying
on pymetasploit3 or any MSF RPC library (both unmaintained).

Strategy
--------
Build a temporary Metasploit resource script (.rc), execute it through
  msfconsole -q -r <script>
capture stdout, parse [+] / [*] / [-] lines, return a normalised dict
that each Application/modules/modbus/msf/*.py module can consume and
that ModTester writes to its Output/ directory automatically.

Wrapped MSF SCADA auxiliaries
------------------------------
  auxiliary/scanner/scada/modbusdetect           (service detection)
  auxiliary/scanner/scada/modbus_banner_grabbing  (FC43 fingerprinting)
  auxiliary/scanner/scada/modbus_findunitid       (UID enumeration)
  auxiliary/scanner/scada/modbusclient            (read & write, 8 actions)

Requirements
------------
  * Metasploit Framework installed, msfconsole on PATH
  * Python 2.7 / 3.x compatible
  * No external Python dependencies beyond stdlib
"""

from __future__ import print_function

import os
import re
import subprocess
import tempfile
from datetime import datetime

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
try:
    from Colors import bcolors
    def green(s):  return bcolors.OKGREEN + s + bcolors.ENDC
    def red(s):    return bcolors.FAIL    + s + bcolors.ENDC
    def yellow(s): return bcolors.WARNING + s + bcolors.ENDC
    def white(s):  return s
    def blue(s):   return bcolors.OKBLUE  + s + bcolors.ENDC
except ImportError:
    def green(s):  return s
    def red(s):    return s
    def yellow(s): return s
    def white(s):  return s
    def blue(s):   return s

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MSF_CONSOLE     = "msfconsole"
DEFAULT_PORT    = 502
DEFAULT_TIMEOUT = 120

_HERE      = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.abspath(os.path.join(_HERE, '..', '..', 'Output'))

MODBUSCLIENT_ACTIONS = set([
    "READ_COILS", "READ_DISCRETE_INPUTS",
    "READ_HOLDING_REGISTERS", "READ_INPUT_REGISTERS",
    "WRITE_COIL", "WRITE_REGISTER",
    "WRITE_COILS", "WRITE_REGISTERS",
])

# Detection strings from modbusdetect [+] output.
# Actual MSF output: "192.168.159.128:5020 - MODBUS - received correct MODBUS/TCP header (unit-ID: 1)"
_DETECT_POSITIVE = [
    "correct modbus/tcp header",
    "modbus/tcp header",
    "modbus",
    "is running",
    "open",
]

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _write_rc(lines):
    fd, path = tempfile.mkstemp(suffix=".rc", prefix="modtester_msf_")
    with os.fdopen(fd, "w") as f:
        for line in lines:
            f.write(line + "\n")
        f.write("exit -y\n")
    return path


def _run_msf(rc_path, timeout=DEFAULT_TIMEOUT):
    """
    Python 2/3 compatible MSF runner.
    -n disables msfconsole colour/ANSI output so [+]/[*]/[-] are plain text.
    """
    try:
        proc = subprocess.Popen(
            [MSF_CONSOLE, "-q", "-n", "-r", rc_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = proc.communicate()
        return (stdout.decode("utf-8", errors="replace"),
                stderr.decode("utf-8", errors="replace"),
                proc.returncode)
    except OSError:
        return ("", "msfconsole not found - is Metasploit installed and on PATH?", -2)


# ANSI escape code stripper - defence-in-depth if -n flag is ignored
_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mABCDEFGHJKSTfnsulhp]')

def _parse_msf_output(raw):
    result = {"success": [], "info": [], "errors": [], "raw": raw}
    for line in raw.splitlines():
        line = _ANSI_RE.sub('', line).strip()  # strip ANSI codes then whitespace
        if line.startswith("[+]"):
            result["success"].append(line[3:].strip())
        elif line.startswith("[*]"):
            result["info"].append(line[3:].strip())
        elif line.startswith("[-]"):
            result["errors"].append(line[3:].strip())
    return result


def _save_output(module_name, target_ip, content):
    if not os.path.isdir(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    filename = "{}_{}.txt".format(module_name, target_ip)
    filepath = os.path.join(OUTPUT_DIR, filename)
    with open(filepath, "w") as f:
        f.write(content)
    return filepath


def _header(module_name, target, port):
    lines = [
        "=" * 60,
        "ModTester - Metasploit SCADA Bridge",
        "Module  : {}".format(module_name),
        "Target  : {}:{}".format(target, port),
        "Date    : {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "=" * 60,
        "",
    ]
    return "\n".join(lines)


def _is_detected(parsed, target_ip):
    """
    Flexible detection: consider positive if ANY [+] line either
    contains a known positive keyword OR contains the target IP
    (meaning MSF reported something about it rather than an error).
    """
    all_success = " ".join(parsed["success"]).lower()
    # Positive keyword match
    for kw in _DETECT_POSITIVE:
        if kw in all_success:
            return True
    # Fallback: any [+] line mentioning the target IP
    for line in parsed["success"]:
        if target_ip in line:
            return True
    return False


# ===========================================================================
# Public API
# ===========================================================================

def msf_modbusdetect(target_ip, port=DEFAULT_PORT, unit_id=1,
                     timeout=DEFAULT_TIMEOUT):
    """
    auxiliary/scanner/scada/modbusdetect
    Returns: dict(detected, info, errors, raw, output)
    """
    print(blue("[MSF] modbusdetect  {}:{}".format(target_ip, port)))

    rc = [
        "use auxiliary/scanner/scada/modbusdetect",
        "set RHOSTS {}".format(target_ip),
        "set RPORT {}".format(port),
        "set UNIT_ID {}".format(unit_id),
        "run",
    ]
    rc_path = _write_rc(rc)
    try:
        stdout, stderr, _ = _run_msf(rc_path, timeout)
    finally:
        os.unlink(rc_path)

    parsed   = _parse_msf_output(stdout)
    detected = _is_detected(parsed, target_ip)

    # Dump raw output for debugging when nothing is detected
    if not detected and not parsed["success"]:
        print(yellow("[*] No [+] lines in MSF output. Raw tail:"))
        for line in stdout.strip().splitlines()[-10:]:
            print(yellow("    " + line))

    report  = _header("MSF_modbusdetect", target_ip, port)
    report += "\nDETECTED: {}\n\n".format("YES" if detected else "NO")
    report += "RAW OUTPUT:\n" + stdout
    filepath = _save_output("MSF_modbusdetect", target_ip, report)

    if detected:
        print(green("[+] Modbus service DETECTED on {}:{}".format(target_ip, port)))
    else:
        print(red("[-] Modbus NOT detected on {}:{} (check Output file for raw MSF output)".format(
            target_ip, port)))
    print(white("[*] Saved: {}".format(filepath)))

    return dict(detected=detected, info=parsed["info"],
                errors=parsed["errors"], raw=stdout, output=filepath)


# ---------------------------------------------------------------------------

def msf_modbus_banner_grabbing(target_ip, port=DEFAULT_PORT,
                                timeout=DEFAULT_TIMEOUT):
    """
    auxiliary/scanner/scada/modbus_banner_grabbing
    oitc/modbus-server exposes: VendorName=Pymodbus, ProductCode=PM,
    VendorUrl, ProductName, ModelName, MajorMinorRevision=3.12.1
    Returns: dict(banner, info, errors, raw, output)
    """
    print(blue("[MSF] modbus_banner_grabbing  {}:{}".format(target_ip, port)))

    rc = [
        "use auxiliary/scanner/scada/modbus_banner_grabbing",
        "set RHOSTS {}".format(target_ip),
        "set RPORT {}".format(port),
        "run",
    ]
    rc_path = _write_rc(rc)
    try:
        stdout, stderr, _ = _run_msf(rc_path, timeout)
    finally:
        os.unlink(rc_path)

    parsed = _parse_msf_output(stdout)
    banner = {}

    # Primary pattern: "IP:PORT - Key: Value"
    banner_re = re.compile(r"[\d.]+:\d+\s+-\s+([A-Za-z ]+):\s+(.+)")
    # Fallback pattern: "Key: Value" anywhere in [+] lines
    kv_re = re.compile(r"([A-Za-z][A-Za-z ]{2,30}):\s+(.+)")

    for line in parsed["success"] + parsed["info"]:
        m = banner_re.search(line)
        if m:
            banner[m.group(1).strip()] = m.group(2).strip()
            continue
        m = kv_re.search(line)
        if m:
            key = m.group(1).strip()
            # Filter out noise keys
            if key.lower() not in ("scanned", "auxiliary", "target"):
                banner[key] = m.group(2).strip()

    report  = _header("MSF_modbus_banner_grabbing", target_ip, port)
    report += "\nBANNER INFORMATION\n" + "-" * 30 + "\n"
    if banner:
        for k, v in sorted(banner.items()):
            report += "  {:25s}: {}\n".format(k, v)
    else:
        report += "  No banner data returned (FC43 may be unsupported).\n"
    report += "\nRAW OUTPUT:\n" + stdout
    filepath = _save_output("MSF_modbus_banner_grabbing", target_ip, report)

    if banner:
        print(green("[+] Banner retrieved:"))
        for k, v in sorted(banner.items()):
            print(green("    {:25s}: {}".format(k, v)))
    else:
        print(yellow("[*] No banner data returned."))
        print(yellow("[*] Check raw output: {}".format(filepath)))
    print(white("[*] Saved: {}".format(filepath)))

    return dict(banner=banner, info=parsed["info"],
                errors=parsed["errors"], raw=stdout, output=filepath)


# ---------------------------------------------------------------------------

def msf_modbus_findunitid(target_ip, port=DEFAULT_PORT,
                           uid_from=0, uid_to=254,
                           be_nice=0, timeout=300):
    """
    auxiliary/scanner/scada/modbus_findunitid
    Returns: dict(unit_ids, info, errors, raw, output)
    """
    print(blue("[MSF] modbus_findunitid  {}:{}  UIDs {}-{}".format(
        target_ip, port, uid_from, uid_to)))

    rc = [
        "use auxiliary/scanner/scada/modbus_findunitid",
        "set RHOSTS {}".format(target_ip),
        "set RPORT {}".format(port),
        "set UNIT_ID_FROM {}".format(uid_from),
        "set UNIT_ID_TO {}".format(uid_to),
        "set BENICE {}".format(be_nice),
        "run",
    ]
    rc_path = _write_rc(rc)
    try:
        stdout, stderr, _ = _run_msf(rc_path, timeout)
    finally:
        os.unlink(rc_path)

    parsed   = _parse_msf_output(stdout)
    # Actual MSF output: "...correct MODBUS/TCP from stationID  1"
    # Legacy fallback:   "Found Unit ID: 1"
    uid_re   = re.compile(r"stationID\s+(\d+)|[Uu]nit\s+ID[:\s]+(\d+)")
    unit_ids = []
    for line in parsed["success"]:
        m = uid_re.search(line)
        if m:
            uid = int(m.group(1) if m.group(1) else m.group(2))
            if uid not in unit_ids:
                unit_ids.append(uid)

    report  = _header("MSF_modbus_findunitid", target_ip, port)
    report += "\nSCAN RANGE : {} - {}\n".format(uid_from, uid_to)
    report += "FOUND UIDs : {}\n\n".format(unit_ids if unit_ids else "None")
    report += "RAW OUTPUT:\n" + stdout
    filepath = _save_output("MSF_modbus_findunitid", target_ip, report)

    if unit_ids:
        print(green("[+] Valid Unit IDs: {}".format(unit_ids)))
    else:
        print(yellow("[*] No valid UIDs found in range {}-{}.".format(uid_from, uid_to)))
    print(white("[*] Saved: {}".format(filepath)))

    return dict(unit_ids=unit_ids, info=parsed["info"],
                errors=parsed["errors"], raw=stdout, output=filepath)


# ---------------------------------------------------------------------------

def msf_modbusclient(target_ip, port=DEFAULT_PORT, unit_number=1,
                     action="READ_HOLDING_REGISTERS",
                     data_address=0, number=8,
                     data=None, data_coils=None,
                     hexdump=False, timeout=DEFAULT_TIMEOUT):
    """
    auxiliary/scanner/scada/modbusclient - all 8 read/write actions.
    Returns: dict(action, values, write_ok, info, errors, raw, output)
    """
    action = action.upper()
    if action not in MODBUSCLIENT_ACTIONS:
        raise ValueError("Unknown action '{}'. Valid: {}".format(
            action, sorted(MODBUSCLIENT_ACTIONS)))

    print(blue("[MSF] modbusclient {} on {}:{} unit={} addr={}".format(
        action, target_ip, port, unit_number, data_address)))

    rc = [
        "use auxiliary/scanner/scada/modbusclient",
        "set RHOSTS {}".format(target_ip),
        "set RPORT {}".format(port),
        "set UNIT_NUMBER {}".format(unit_number),
        "set ACTION {}".format(action),
        "set DATA_ADDRESS {}".format(data_address),
    ]
    if action.startswith("READ"):
        rc.append("set NUMBER {}".format(number))
    if action in ("WRITE_COIL", "WRITE_REGISTER", "WRITE_REGISTERS") \
            and data is not None:
        rc.append("set DATA {}".format(data))
    if action == "WRITE_COILS" and data_coils is not None:
        rc.append("set DATA_COILS {}".format(data_coils))
    if hexdump:
        rc.append("set HEXDUMP true")
    rc.append("run")

    rc_path = _write_rc(rc)
    try:
        stdout, stderr, _ = _run_msf(rc_path, timeout)
    finally:
        os.unlink(rc_path)

    parsed     = _parse_msf_output(stdout)
    values     = []
    write_ok   = False
    # MSF modbusclient splits output across TWO consecutive [+] lines:
    #   Line 1: "16 register values from address 0 : "   (trailing empty)
    #   Line 2: "[3000, 4500, 100, ...]"                 (Python list format)
    # We detect line 1 as a trigger, then grab the next line as the data.
    header_re  = re.compile(
        r"(?:\d+\s+)?(?:values?|bits?|registers?|coils?)\s+from\s+address\s+\d+",
        re.IGNORECASE)
    list_re    = re.compile(r"\[([\d,\s]+)\]")      # matches "[3000, 4500, ...]"
    written_re = re.compile(
        r"(?:successfully\s+written|value\s+.*\s+written|write\s+ok|wrote)",
        re.IGNORECASE)

    all_lines  = parsed["success"] + parsed["info"]
    grab_next  = False
    for line in all_lines:
        if grab_next:
            # Try Python list format first: "[3000, 4500, ...]"
            m = list_re.search(line)
            if m:
                values = [v.strip() for v in m.group(1).split(",") if v.strip()]
            elif line.strip():
                values = line.strip().split()
            grab_next = False
            continue
        if header_re.search(line):
            # Check if values are on the same line after the colon
            colon_idx = line.rfind(":")
            if colon_idx != -1:
                after = line[colon_idx+1:].strip()
                if after:
                    m = list_re.search(after)
                    values = [v.strip() for v in m.group(1).split(",")] if m else after.split()
                else:
                    grab_next = True  # values are on the next line
            continue
        if written_re.search(line):
            write_ok = True

    report  = _header("MSF_modbusclient_{}".format(action), target_ip, port)
    report += "ACTION       : {}\n".format(action)
    report += "UNIT ID      : {}\n".format(unit_number)
    report += "DATA ADDRESS : {}\n\n".format(data_address)
    if values:
        report += "VALUES: {}\n\n".format(" ".join(str(v) for v in values))
    elif write_ok:
        report += "WRITE: SUCCESS\n\n"
    else:
        report += "No structured data parsed - see raw output.\n\n"
    report += "RAW OUTPUT:\n" + stdout
    filepath = _save_output(
        "MSF_modbusclient_{}".format(action), target_ip, report)

    if values:
        print(green("[+] {} values from addr {}: {}".format(
            len(values), data_address, " ".join(str(v) for v in values))))
    elif write_ok:
        print(green("[+] Write successful."))
    else:
        print(yellow("[*] No values parsed - check: {}".format(filepath)))
    for e in parsed["errors"]:
        print(red("[-] {}".format(e)))
    print(white("[*] Saved: {}".format(filepath)))

    return dict(action=action, values=values, write_ok=write_ok,
                info=parsed["info"], errors=parsed["errors"],
                raw=stdout, output=filepath)


# ---------------------------------------------------------------------------

def msf_full_recon(target_ip, port=DEFAULT_PORT,
                   uid_from=0, uid_to=10, timeout=DEFAULT_TIMEOUT):
    """
    Convenience chain: detect -> banner -> findunitid -> sample register read.
    """
    results = {}
    print(yellow("\n[MSF] ===== Full Recon: {} =====".format(target_ip)))

    results["modbusdetect"] = msf_modbusdetect(target_ip, port, timeout=timeout)
    if not results["modbusdetect"]["detected"]:
        print(yellow("[!] Detection inconclusive - continuing recon anyway."))

    results["banner_grabbing"] = msf_modbus_banner_grabbing(
        target_ip, port, timeout=timeout)

    results["findunitid"] = msf_modbus_findunitid(
        target_ip, port, uid_from=uid_from, uid_to=uid_to, timeout=timeout)

    uid = (results["findunitid"]["unit_ids"] or [1])[0]
    results["modbusclient"] = msf_modbusclient(
        target_ip, port,
        unit_number=uid, action="READ_HOLDING_REGISTERS",
        data_address=0, number=16, timeout=timeout,
    )
    print(yellow("[MSF] ===== Recon Complete =====\n"))
    return results


# ===========================================================================
# CLI entry point  -  Python 2/3 compatible (no argparse)
# ===========================================================================

if __name__ == "__main__":
    import sys

    def _usage():
        print("Usage: python MetasploitBridge.py <target_ip> [options]")
        print("")
        print("Options:")
        print("  --module    detect | banner | finduid | client | recon  (default: recon)")
        print("  --port      target port (default: 502)")
        print("  --action    modbusclient action (default: READ_HOLDING_REGISTERS)")
        print("  --address   data address (default: 0)")
        print("  --number    values to read (default: 8)")
        print("  --uid       unit ID (default: 1)")
        print("  --data      value to write")
        print("  --uid-from  UID scan start (default: 0)")
        print("  --uid-to    UID scan end (default: 254)")
        print("")
        print("Examples:")
        print("  python MetasploitBridge.py 192.168.159.128 --port 5020 --module recon --uid-from 0 --uid-to 10")
        print("  python MetasploitBridge.py 192.168.159.128 --port 5020 --module detect")
        print("  python MetasploitBridge.py 192.168.159.128 --port 5020 --module client --action WRITE_REGISTER --address 0 --data 9999")
        sys.exit(0)

    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        _usage()

    target = args[0]

    def _get(flag, default):
        if flag in args:
            idx = args.index(flag)
            if idx + 1 < len(args):
                return args[idx + 1]
        return default

    module   = _get("--module",   "recon")
    port     = int(_get("--port",     str(DEFAULT_PORT)))
    action   = _get("--action",   "READ_HOLDING_REGISTERS")
    address  = int(_get("--address",  "0"))
    number   = int(_get("--number",   "8"))
    uid      = int(_get("--uid",      "1"))
    data     = _get("--data",     None)
    uid_from = int(_get("--uid-from", "0"))
    uid_to   = int(_get("--uid-to",   "254"))

    if module == "detect":
        msf_modbusdetect(target, port)
    elif module == "banner":
        msf_modbus_banner_grabbing(target, port)
    elif module == "finduid":
        msf_modbus_findunitid(target, port, uid_from=uid_from, uid_to=uid_to)
    elif module == "client":
        msf_modbusclient(target, port,
                         unit_number=uid,
                         action=action,
                         data_address=address,
                         number=number,
                         data=data)
    elif module == "recon":
        msf_full_recon(target, port, uid_from=uid_from, uid_to=uid_to)
    else:
        print("Unknown module '{}'. Use --help.".format(module))
        sys.exit(1)