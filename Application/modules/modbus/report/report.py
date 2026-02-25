#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
modbus/report/report
--------------------
ModTester module: generates a standardised ICS/OT security report (.docx)
from findings in the Output/ directory. Zero external dependencies.

  use modbus/report/report
  show options
  set TARGET 192.168.159.128
  set PORT 5020
  exploit

Note: ModTester's set command only captures the first word after the key.
      Use underscores for multi-word values: set ASSESSOR ICS_Security_Team
      The report will display them with spaces automatically.
"""

from __future__ import print_function

import sys
import os

_CORE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'System', 'Core')
)
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import ReportGenerator


class Module(object):

    info = {
        'Name'        : 'ModTester Report Generator',
        'Description' : 'Generate ICS/OT security report (CVSS/CWE/IEC 62443) - no Node.js needed',
        'Author'      : 'ModTester',
        'Reference'   : 'IEC 62443 / CVSS v3.1 / CWE',
    }

    options = {
        'TARGET'   : ['',          True,  'Target IP (must match Output file names)'],
        'PORT'     : ['502',       False, 'Target port (report metadata only)'],
        'ASSESSOR' : ['ModTester', False, 'Assessor name (use underscores: ICS_Team)'],
        'ORG'      : ['Target',    False, 'Organisation name (use underscores: Acme_Industrial)'],
    }

    def exploit(self):
        target_ip    = self.options['TARGET'][0].strip()
        port         = int(self.options['PORT'][0].strip() or '502')
        # Replace underscores with spaces for display in the report
        assessor     = self.options['ASSESSOR'][0].strip().replace('_', ' ')
        organisation = self.options['ORG'][0].strip().replace('_', ' ')

        if not target_ip:
            print("[-] TARGET is required. Use: set TARGET <ip>")
            return None

        # Output directory: same directory as this script's ../../../../Output/
        _here   = os.path.dirname(os.path.abspath(__file__))
        scandir = os.path.abspath(
            os.path.join(_here, '..', '..', '..', '..', 'Output')
        )

        if not os.path.isdir(scandir):
            print("[-] Output directory not found: {}".format(scandir))
            return None

        print("[*] Scanning {} for findings matching: {}".format(scandir, target_ip))

        path = ReportGenerator.generate_report(
            target_ip    = target_ip,
            port         = port,
            output_dir   = scandir,
            assessor     = assessor,
            organisation = organisation,
        )

        if path and os.path.isfile(path):
            size = os.path.getsize(path)
            print("[+] Report saved: {} ({} bytes)".format(path, size))
        else:
            print("[-] Report generation failed - check the error above.")

        return path