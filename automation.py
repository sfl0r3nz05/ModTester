import os
import redis
import json
import subprocess

data = None
processes = []
names = {
    "coilDiscover": "modbus/scanner/coilDiscover",
    "discover": "modbus/scanner/discover",
    "discreteInputDiscover": "modbus/scanner/discreteInputDiscover",
    "getfunc": "modbus/scanner/getfunc",
    "holdingRegisterDiscover": "modbus/scanner/holdingRegisterDiscover",
    "inputRegisterDiscover": "modbus/scanner/inputRegisterDiscover",
    "portDiscover": "modbus/scanner/portDiscover",
    "uid": "modbus/scanner/uid",
    "writeSingleCoils": "modbus/dos/writeSingleCoils",
    "writeSingleCoilsID": "modbus/dos/writeSingleCoilsID",
    "writeSingleRegister": "modbus/dos/writeSingleRegister",
    "writeSingleRegisterID": "modbus/dos/writeSingleRegisterID",
    "floodingAttack": "modbus/dos/floodingAttack"
}
redist = redis.Redis(
    host='redis',
    port=6379,
    password='')

redist.set("finished", 0)

with open('parameters.json') as f:
    data = json.load(f)
    print(data["attacks"][0])
while True:
    while len(data["attacks"]) != 0:
        if redist.get("finished") == "0":
            redist.set("finished", 1)
            # os.system("python2 -d modTester.py {0} {1}".format(names[data["attacks"][0]], data["ips"][0]))
            command = "python2 modTester.py {0} {1}".format(names[data["attacks"][0]], data["ips"][0])
            processes.append(subprocess.Popen(command, shell=True))
            data["attacks"].pop(0)
