#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
modbus/msf/modbusdetect
-----------------------
ModTester module wrapper for:
  auxiliary/scanner/scada/modbusdetect

Confirms whether a Modbus/TCP service is present on the target by
sending a crafted probe and checking for a valid MBAP header response.
"""

import sys
import os

# Reach MetasploitBridge regardless of working directory
_CORE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'System', 'Core'))
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import MetasploitBridge as msf


class Module(object):

    info = {
        'Name'        : 'MSF Modbus Detect',
        'Description' : 'Detect Modbus/TCP service via Metasploit auxiliary',
        'Author'      : 'MetasploitBridge / ModTester',
        'Reference'   : 'auxiliary/scanner/scada/modbusdetect',
    }

    # options[key] = [current_value, required (bool), description]
    options = {
        'RHOSTS'  : ['', True,  'Target IP address'],
        'RPORT'   : ['502', False, 'Target port (default 502)'],
        'UNIT_ID' : ['1',   False, 'Modbus Unit ID to probe'],
        'TIMEOUT' : ['120', False, 'Execution timeout in seconds'],
    }

    def exploit(self):
        target  = self.options['RHOSTS'][0]
        port    = int(self.options['RPORT'][0])
        uid     = int(self.options['UNIT_ID'][0])
        timeout = int(self.options['TIMEOUT'][0])

        result = msf.msf_modbusdetect(
            target_ip = target,
            port      = port,
            unit_id   = uid,
            timeout   = timeout,
        )
        return result