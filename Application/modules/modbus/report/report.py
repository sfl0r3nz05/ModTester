#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
modbus/report/report
--------------------
ModTester module that generates a standardised ICS/OT security assessment
report (.docx) from all findings accumulated in the Output/ directory.

  use modbus/report/report
  show options
  set TARGET    192.168.159.128
  set PORT      5020
  set ASSESSOR  ICS Security Team
  set ORG       Acme Industrial
  exploit

Note: do NOT wrap values in quotes - ModTester includes them literally.
The report is written to Output/ and the path is printed on completion.
Node.js and the 'docx' npm package must be installed:
  npm install -g docx
"""

from __future__ import print_function

import sys
import os

# Reach System/Core from anywhere ModTester is launched
_CORE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'System', 'Core')
)
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import ReportGenerator


class Module(object):

    info = {
        'Name'        : 'ModTester Report Generator',
        'Description' : 'Generate standardised ICS/OT security report (CVSS/CWE/IEC 62443)',
        'Author'      : 'ModTester / ReportGenerator',
        'Reference'   : 'IEC 62443 / CVSS v3.1 / CWE / PTES',
    }

    options = {
        'TARGET'   : ['',                    True,  'Target IP (must match Output file names)'],
        'PORT'     : ['502',                 False, 'Target port (report metadata only)'],
        'ASSESSOR' : ['ModTester',           False, 'Assessor name (no quotes needed)'],
        'ORG'      : ['Target Organisation', False, 'Organisation name (no quotes needed)'],
        'SCANDIR'  : ['',                    False, 'Dir containing Output .txt files (default: ModTester/Output/)'],
        'OUTPUT'   : ['',                    False, 'Full path for report file (default: auto in SCANDIR)'],
    }

    def exploit(self):
        def _clean(val):
            # Strip surrounding quotes that ModTester includes literally when
            # the user wraps a value in "..." on the command line
            v = val.strip()
            if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                v = v[1:-1]
            if len(v) >= 2 and v[0] == "'" and v[-1] == "'":
                v = v[1:-1]
            return v

        target_ip    = _clean(self.options['TARGET'][0])
        port         = int(_clean(self.options['PORT'][0]) or '502')
        assessor     = _clean(self.options['ASSESSOR'][0])
        organisation = _clean(self.options['ORG'][0])

        # SCANDIR: where Output .txt files live (read from)
        # OUTPUT:  full path of the generated .docx (written to SCANDIR if not set)
        scandir = _clean(self.options['SCANDIR'][0])
        if not scandir:
            _here   = os.path.dirname(os.path.abspath(__file__))
            scandir = os.path.abspath(
                os.path.join(_here, '..', '..', '..', '..', 'Output')
            )

        report_path = _clean(self.options['OUTPUT'][0]) or None

        if not target_ip:
            print("[-] TARGET is required. Use: set TARGET <ip>")
            return None

        if not os.path.isdir(scandir):
            print("[-] Scan directory not found: {}".format(scandir))
            print("    Set it with: set SCANDIR /path/to/Output/")
            return None

        print("[*] Scanning {} for findings matching: {}".format(scandir, target_ip))

        path = ReportGenerator.generate_report(
            target_ip    = target_ip,
            port         = port,
            output_dir   = scandir,
            assessor     = assessor,
            organisation = organisation,
            report_path  = report_path,
        )

        if path:
            print("[+] Report generated: {}".format(path))
        else:
            print("[-] Report generation failed.")
            print("    Verify Node.js is installed: node --version")
            print("    Verify docx package:         node -e \"require('docx'); console.log('OK')\"")
            print("    Install if missing:          npm install -g docx")

        return path