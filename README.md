# ModTester

**ModTester** is a unified Modbus protocol pentesting framework. It aggregates multiple tools for exploiting Modbus vulnerabilities into a single accessible toolkit, providing a consistent interface across a wide range of attack and reconnaissance techniques — including native Python modules, Metasploit SCADA auxiliary integration, and standardised security report generation.

> **Original authors:** Danel López ([@dangoro94](https://github.com/dangoro94)), Santiago Figueroa ([@sfl0r3nz05](https://github.com/sfl0r3nz05))
> **Maintainers:** Santiago Figueroa ([@sfl0r3nz05](https://github.com/sfl0r3nz05))

---

## Table of Contents

1. [Features](#features)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Modules](#modules)
6. [Metasploit Integration](#metasploit-integration)
7. [Report Generation](#report-generation)
8. [Testing with Docker](#testing-with-docker)
9. [Documentation](#documentation)

---

## Features

- **17 modules** covering discovery, enumeration, read exploitation, write exploitation, denial of service, and report generation
- **Metasploit SCADA bridge** — wraps `auxiliary/scanner/scada/modbusdetect`, `modbus_banner_grabbing`, `modbus_findunitid`, and `modbusclient` without any deprecated RPC library
- **Standardised report generator** — produces a `.docx` security report mapped to CVSS v3.1, CWE, and IEC/ISA 62443 Security Requirements with no CVE assignment required
- **Tab-completion** and a Metasploit-style `use / set / exploit` interface
- Python 2.7 / 3.x compatible

---

## Requirements

| Component | Version |
|-----------|---------|
| Python | 2.7 (primary) |
| Metasploit Framework | 6.x (`msfconsole` on PATH) |

Install Metasploit on Ubuntu/Debian:

```bash
chmod +x install_metasploit.sh
sudo ./install_metasploit.sh
```

Run `msfconsole -q` once interactively to complete first-time setup before using the bridge.

---

## Usage

```
sudo python2 modTester.py
```

```
 _______
< ModTester >
 -------
           ________
|\   /|       |      ________
| \_/ | _  _| |  __  __  |  __ __
|     |/ \/ | | /_  /_   | /_  |_\
|     |\_/\_/ | \__ _/   | \__ | \

          --=[MODBUS Pentesting Toolkit
       --+--=[Version  : 1.1
       --+--=[Modules  : 18
       --+--=[Coder(s) : Danel López / Santiago Figueroa
       --+--=[Maintainer(s) : Santiago Figueroa
          --=[github   : github.com/dangoro94 / github.com/sfl0r3nz05

ModTester > help

 Command  Description
 -------  -----------
 back     Move back from the current context
 exit     Exit the console
 exploit  Run module
 help     Help menu
 show     Displays modules of a given type, or all modules
 set      Sets a variable to a value
 use      Selects a module by name
```

### Basic workflow

```
ModTester > show modules          # list all available modules
ModTester > use modbus/scanner/discover
SMOD modbus(discover) > show options
SMOD modbus(discover) > set RHOST 192.168.1.100
SMOD modbus(discover) > set RPORT 502
SMOD modbus(discover) > exploit
SMOD modbus(discover) > back
```

---

## Modules

```
ModTester > show modules

 Modules                                   Description
 -------                                   -----------
 modbus/dos/floodingAttack                 Flooding Attack with Hping script
 modbus/dos/writeSingleCoils               DOS Write Single Coil Function
 modbus/dos/writeSingleCoilsID             DOS Write Single Coil Function (by UID)
 modbus/dos/writeSingleRegister            DOS Write Single Register
 modbus/dos/writeSingleRegisterID          DOS Write Single Register (by UID)
 modbus/msf/modbusBannerGrabbing           Device fingerprinting via Modbus FC43
 modbus/msf/modbusClient                   Read/Write coils and registers (8 actions)
 modbus/msf/modbusUIDScan                  Enumerate valid Modbus Unit IDs
 modbus/msf/modbusdetect                   Detect Modbus/TCP service
 modbus/report/report                      Generate standardised ICS/OT security report
 modbus/scanner/coilDiscover               Modbus Coil status discover
 modbus/scanner/discover                   Check Modbus Protocols
 modbus/scanner/discreteInputDiscover      Modbus Discrete Input Scanner
 modbus/scanner/getfunc                    Enumeration Function on Modbus
 modbus/scanner/holdingRegisterDiscover    Modbus Holding Register Scanner
 modbus/scanner/inputRegisterDiscover      Modbus Input Register Scanner
 modbus/scanner/portDiscover               Port scan with Hping
 modbus/scanner/uid                        Brute Force UID
```

---

## Metasploit Integration

ModTester integrates four Metasploit SCADA auxiliary modules via a subprocess bridge (`System/Core/MetasploitBridge.py`) — no pymetasploit3 or MSF RPC required.

### Modules

| ModTester module | MSF auxiliary | Function |
|-----------------|---------------|----------|
| `modbus/msf/modbusdetect` | `auxiliary/scanner/scada/modbusdetect` | Confirm Modbus/TCP service presence |
| `modbus/msf/modbusBannerGrabbing` | `auxiliary/scanner/scada/modbus_banner_grabbing` | FC43 device fingerprinting |
| `modbus/msf/modbusUIDScan` | `auxiliary/scanner/scada/modbus_findunitid` | Unit ID enumeration (0–254) |
| `modbus/msf/modbusClient` | `auxiliary/scanner/scada/modbusclient` | Read/write all register types (8 actions) |

### Example — Full recon chain

```
ModTester > use modbus/msf/modbusdetect
SMOD modbus(modbusdetect) > set RHOSTS 192.168.1.100
SMOD modbus(modbusdetect) > set RPORT 502
SMOD modbus(modbusdetect) > exploit

ModTester > use modbus/msf/modbusBannerGrabbing
SMOD modbus(modbusBannerGrabbing) > set RHOSTS 192.168.1.100
SMOD modbus(modbusBannerGrabbing) > exploit

ModTester > use modbus/msf/modbusClient
SMOD modbus(modbusClient) > set RHOSTS 192.168.1.100
SMOD modbus(modbusClient) > set ACTION READ_HOLDING_REGISTERS
SMOD modbus(modbusClient) > set NUMBER 16
SMOD modbus(modbusClient) > exploit
```

### Standalone bridge CLI

```bash
# Full recon (detect → banner → UID scan → register read)
python2 System/Core/MetasploitBridge.py 192.168.1.100 --port 502 --module recon

# Individual modules
python2 System/Core/MetasploitBridge.py 192.168.1.100 --port 502 --module detect
python2 System/Core/MetasploitBridge.py 192.168.1.100 --port 502 --module banner
python2 System/Core/MetasploitBridge.py 192.168.1.100 --port 502 --module finduid --uid-from 0 --uid-to 10
python2 System/Core/MetasploitBridge.py 192.168.1.100 --port 502 --module client \
    --action WRITE_REGISTER --address 0 --data 9999
```

### Supported `modbusClient` actions

| Action | Modbus FC | Description |
|--------|-----------|-------------|
| `READ_COILS` | FC01 | Read coil status |
| `READ_DISCRETE_INPUTS` | FC02 | Read discrete inputs |
| `READ_HOLDING_REGISTERS` | FC03 | Read holding registers |
| `READ_INPUT_REGISTERS` | FC04 | Read input registers |
| `WRITE_COIL` | FC05 | Write single coil — set `DATA` to `0` or `1` |
| `WRITE_REGISTER` | FC06 | Write single register — set `DATA` to integer |
| `WRITE_COILS` | FC15 | Write multiple coils — set `DATA_COILS` to `"1,0,1,1"` |
| `WRITE_REGISTERS` | FC16 | Write multiple registers — set `DATA` to space-separated values |

---

## Report Generation

After running any combination of ModTester modules, generate a standardised security report directly from the console:

```
ModTester > use modbus/report/report
SMOD modbus(report) > show options

 Name      Current Setting       Required  Description
 ----      ---------------       --------  -----------
 TARGET                          yes       Target IP address (must match Output file names)
 PORT      502                   no        Target port (report metadata only)
 ASSESSOR  ModTester             no        Name of the assessor
 ORG       Target Organisation   no        Name of the assessed organisation
 OUTDIR                          no        Output directory (default: ModTester/Output/)
 OUTPUT                          no        Report filename (default: auto-generated)

SMOD modbus(report) > set TARGET 192.168.1.100
SMOD modbus(report) > set PORT 502
SMOD modbus(report) > set ASSESSOR "ICS Security Team"
SMOD modbus(report) > set ORG "Acme Industrial"
SMOD modbus(report) > exploit

[*] Scanning Output/ for findings matching target: 192.168.1.100
[Report] 6 finding(s) matched from 12 output file(s).
[Report] Generated: /home/user/ModTester/Output/ModTester_Report_192.168.1.100_20260225_120000.docx
[+] Report generated: Output/ModTester_Report_192.168.1.100_20260225_120000.docx
```

### Report structure

| Section | Content |
|---------|---------|
| Cover page | Target, assessor, date, findings count by severity |
| 1. Executive Summary | Protocol context, finding counts, no-CVE rationale |
| 2. Assessment Scope | Target, port, date, tool, assessor |
| 3. Standardisation Framework | CVSS v3.1 / CWE / IEC 62443 explanation |
| 4. Findings Summary | Colour-coded table — all findings with CVSS score and IEC 62443 SR |
| 5. Detailed Findings | Per-finding: description, impact, references table, remediation, evidence |
| 6. Methodology | Phase-by-phase test approach |
| 7. References | Standards, tools, CVE/CWE/IEC links |

### Standardisation layers (no CVE required)

Modbus vulnerabilities are protocol design weaknesses — they have no CVEs. ModTester maps each finding to three complementary standards:

| Standard | Purpose | Example |
|----------|---------|---------|
| **CVSS v3.1** | Severity scoring | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` → 9.1 Critical |
| **CWE** | Weakness classification | CWE-306 Missing Authentication for Critical Function |
| **IEC/ISA 62443** | OT compliance mapping | SR 2.1 Authorization Enforcement |

---

## Testing with Docker

Use the `oitc/modbus-server` Docker image to test ModTester safely against a simulated PLC environment:

```bash
# Start server with pre-configured registers (motor RPM, valve states, sensor readings)
docker run --network host --rm \
  -v $(pwd)/server_config.json:/server_config.json \
  oitc/modbus-server:latest -f /server_config.json

# Server starts on 0.0.0.0:5020
# Watch all incoming Modbus requests in real time:
docker logs -f $(docker ps -q --filter ancestor=oitc/modbus-server)
```

The included `server_config.json` pre-populates:
- **Coils 0–7**: motor on/off, valve open/closed, pump and alarm states
- **Holding registers 0–15**: RPM setpoints (1500, 3000, 4500), temperature limits, serial number
- **Input registers 0–7**: sensor readings (RPM=2350, pressure=1875, temp=42°C, ADC values)
- **Discrete inputs 0–5**: sensor active/inactive states

After testing, reset device state by restarting the container.

---

## Documentation

| Document | Language | Link |
|----------|----------|------|
| Developer Guide | Spanish | [Guía_de_desarrollo.pdf](./documentation/GUIA_DESARROLLO_MODTESTER.pdf) |
| Application Manual | Spanish | [documentacion_ModTester.pdf](./documentation/documentacion_ModTester.pdf) |
| Attack Demo — URMSIM robot | Video | [attack_sample.mp4](./documentation/attack_sample.mp4) |
| Attack Demo 2 — URMSIM robot | Video | [attack_sample2.mp4](./documentation/attack_sample2.mp4) |
| Test Runbook | English | [Test_Runbook.md](./TEST_RUNBOOK.md) |

---

## File Structure

```
ModTester/
├── modTester.py
├── server_config.json          # Docker test server configuration
├── install_metasploit.sh       # Metasploit installer (Ubuntu/Debian)
├── Application/
│   └── modules/
│       └── modbus/
│           ├── dos/            # Denial-of-service modules (5)
│           ├── msf/            # Metasploit bridge modules (4)
│           ├── report/         # Report generation module (1)
│           └── scanner/        # Reconnaissance modules (8)
├── System/
│   └── Core/
│       ├── MetasploitBridge.py # MSF subprocess bridge
│       ├── ReportGenerator.py  # DOCX report engine
│       ├── Interface.py
│       ├── Loader.py
│       └── ...
└── Output/                     # All module results saved here
```

---

## License

This project is for educational and authorised security testing purposes only. Always obtain explicit written permission before testing any Modbus device or network.