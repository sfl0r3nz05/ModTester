#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
modbus/msf/modbusClient
------------------------
ModTester module wrapper for:
  auxiliary/scanner/scada/modbusclient

Covers all 8 Modbus read/write actions through a single configurable module.
Set ACTION to one of:

  READ_COILS              READ_DISCRETE_INPUTS
  READ_HOLDING_REGISTERS  READ_INPUT_REGISTERS
  WRITE_COIL              WRITE_REGISTER
  WRITE_COILS             WRITE_REGISTERS

For read actions:   set NUMBER to control how many values are returned.
For single writes:  set DATA to the value (e.g. "1" for coil, "1234" for register).
For WRITE_COILS:    set DATA_COILS as comma-separated bits, e.g. "1,0,1,1".
For WRITE_REGISTERS:set DATA as space-separated word values, e.g. "100 200 300".
"""

import sys
import os

_CORE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..', 'System', 'Core'))
if _CORE not in sys.path:
    sys.path.insert(0, _CORE)

import MetasploitBridge as msf


class Module(object):

    info = {
        'Name'        : 'MSF Modbus Client',
        'Description' : 'Read/Write Modbus coils and registers via Metasploit auxiliary',
        'Author'      : 'MetasploitBridge / ModTester',
        'Reference'   : 'auxiliary/scanner/scada/modbusclient',
    }

    options = {
        'RHOSTS'       : ['',                        True,  'Target IP address'],
        'RPORT'        : ['502',                     False, 'Target port (default 502)'],
        'UNIT_NUMBER'  : ['1',                       False, 'Modbus Unit ID'],
        'ACTION'       : ['READ_HOLDING_REGISTERS',  True,  'Modbus action to perform (see module description)'],
        'DATA_ADDRESS' : ['0',                       False, 'Start register/coil address'],
        'NUMBER'       : ['8',                       False, 'Number of values to read (read actions only)'],
        'DATA'         : ['',                        False, 'Value to write (single-write actions)'],
        'DATA_COILS'   : ['',                        False, 'Comma-separated bit string for WRITE_COILS'],
        'HEXDUMP'      : ['false',                   False, 'Print hex dump of raw response (true/false)'],
        'TIMEOUT'      : ['120',                     False, 'Execution timeout in seconds'],
    }

    def exploit(self):
        target      = self.options['RHOSTS'][0]
        port        = int(self.options['RPORT'][0])
        unit        = int(self.options['UNIT_NUMBER'][0])
        action      = self.options['ACTION'][0].upper()
        data_addr   = int(self.options['DATA_ADDRESS'][0])
        number      = int(self.options['NUMBER'][0])
        data        = self.options['DATA'][0]       or None
        data_coils  = self.options['DATA_COILS'][0] or None
        hexdump     = self.options['HEXDUMP'][0].lower() == 'true'
        timeout     = int(self.options['TIMEOUT'][0])

        result = msf.msf_modbusclient(
            target_ip    = target,
            port         = port,
            unit_number  = unit,
            action       = action,
            data_address = data_addr,
            number       = number,
            data         = data,
            data_coils   = data_coils,
            hexdump      = hexdump,
            timeout      = timeout,
        )
        return result