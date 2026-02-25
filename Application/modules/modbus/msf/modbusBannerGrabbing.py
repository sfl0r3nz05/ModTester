#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
modbus/msf/modbusBannerGrabbing
--------------------------------
ModTester module wrapper for:
  auxiliary/scanner/scada/modbus_banner_grabbing

Sends a Modbus FC43 (Read Device Identification) request to retrieve
vendor name, product code, firmware revision and other identity objects
from the target device. Very useful for fingerprinting PLCs and RTUs.
"""

import sys
import os

_CORE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'System', 'Core'))
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import MetasploitBridge as msf


class Module(object):

    info = {
        'Name'        : 'MSF Modbus Banner Grabbing',
        'Description' : 'Device fingerprinting via Modbus FC43 (Read Device ID)',
        'Author'      : 'MetasploitBridge / ModTester',
        'Reference'   : 'auxiliary/scanner/scada/modbus_banner_grabbing',
    }

    options = {
        'RHOSTS'  : ['', True,  'Target IP address'],
        'RPORT'   : ['502', False, 'Target port (default 502)'],
        'TIMEOUT' : ['120', False, 'Execution timeout in seconds'],
    }

    def exploit(self):
        target  = self.options['RHOSTS'][0]
        port    = int(self.options['RPORT'][0])
        timeout = int(self.options['TIMEOUT'][0])

        result = msf.msf_modbus_banner_grabbing(
            target_ip = target,
            port      = port,
            timeout   = timeout,
        )
        return result