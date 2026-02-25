#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
modbus/msf/modbusUIDScan
-------------------------
ModTester module wrapper for:
  auxiliary/scanner/scada/modbus_findunitid

Enumerates valid Modbus Unit IDs (0-254) using FC04 probes.
A valid UID echoes back FC04; an invalid one returns exception 0x84.

BENICE throttles the probe rate — recommended for fragile field devices.
"""

import sys
import os

_CORE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'System', 'Core'))
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import MetasploitBridge as msf


class Module(object):

    info = {
        'Name'        : 'MSF Modbus UID Scanner',
        'Description' : 'Enumerate valid Modbus Unit IDs via Metasploit auxiliary',
        'Author'      : 'MetasploitBridge / ModTester',
        'Reference'   : 'auxiliary/scanner/scada/modbus_findunitid',
    }

    options = {
        'RHOSTS'      : ['',    True,  'Target IP address'],
        'RPORT'       : ['502', False, 'Target port (default 502)'],
        'UNIT_ID_FROM': ['0',   False, 'Start of Unit ID scan range'],
        'UNIT_ID_TO'  : ['254', False, 'End of Unit ID scan range'],
        'BENICE'      : ['0',   False, 'Seconds to sleep between probes (0 = fast)'],
        'TIMEOUT'     : ['300', False, 'Execution timeout in seconds'],
    }

    def exploit(self):
        target   = self.options['RHOSTS'][0]
        port     = int(self.options['RPORT'][0])
        uid_from = int(self.options['UNIT_ID_FROM'][0])
        uid_to   = int(self.options['UNIT_ID_TO'][0])
        be_nice  = int(self.options['BENICE'][0])
        timeout  = int(self.options['TIMEOUT'][0])

        result = msf.msf_modbus_findunitid(
            target_ip = target,
            port      = port,
            uid_from  = uid_from,
            uid_to    = uid_to,
            be_nice   = be_nice,
            timeout   = timeout,
        )
        return result