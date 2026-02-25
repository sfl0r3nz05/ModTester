#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Banner.py  –  System/Core/Banner.py
-------------------------------------
Prints the ModTester ASCII banner on startup.

Change from v1.0: module count is now passed in from Interface.init()
(which gets it from Loader) so it updates automatically whenever new
modules are added – including the new modbus/msf/* family.
"""

from Colors import bcolors

VERSION = '1.1'

class Banner:
    def __init__(self, version, moduleNumber):
        self.version      = version
        self.moduleNumber = moduleNumber
        self.print_banner()

    def print_banner(self):
        print(bcolors.OKBLUE + r' _______ ')
        print(r'< ModTester >')
        print(r' ------- ')
        print(r'           ________                    ')
        print(r'|\   /|       |      ________         ')
        print(r'| \_/ | _  _| |  __  __  |  __ __      ')
        print(r'|     |/ \/ | | /_  /_   | /_  |_\    ')
        print(r'|     |\_/\_/ | \__ _/   | \__ | \    ')
        print(bcolors.ENDC)
        print(bcolors.BOLD + '          --=[MODBUS Pentesting Toolkit')
        print('       --+--=[Version  : ' + bcolors.OKBLUE + str(self.version)      + bcolors.ENDC + bcolors.BOLD)
        print('       --+--=[Modules  : ' + bcolors.OKBLUE + str(self.moduleNumber) + bcolors.ENDC + bcolors.BOLD)
        print('       --+--=[Coder(s) : Danel Lopez / Santiago Figueroa')
        print('          --=[github   : github.com/dangoro94 / github.com/sfl0r3nz05')
        print(bcolors.ENDC)