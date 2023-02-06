import sys
import os

sys.path.append(os.path.abspath(os.path.dirname(__file__) + '/System'))
from System.Core import Interface

args = sys.argv
args.pop(0)
Interface.init()
Interface.mainLoop(args)
