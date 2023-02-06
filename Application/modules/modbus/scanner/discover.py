import os
import threading
import redis

from System.Core.Global import *
from System.Core.Colors import *
from System.Core import Modbus, Loader
from System.Lib import ipcalc

class Module:

	info = {
		'Name': 'Modbus Discover',
		'Author': ['@enddo'],
		'Description': ("Check Modbus Protocols"),

        }
	options = {
		'RHOSTS'	:[''		,True	,'The target address range or CIDR identifier'],
		'RPORT'		:[502		,False	,'The port number for modbus protocol'],
		'Threads'	:[1		,False	,'The number of concurrent threads'],
		'Output'	:[True		,False	,'The stdout save in output directory']
	}
	output = ''

	def exploit(self):
		redist = redis.Redis(
			host='redis',
			port=6379,
			password='')
		count = 1
		moduleName 	= self.info['Name']
		print bcolors.OKBLUE + '[+]' + bcolors.ENDC + ' Module ' + moduleName + ' Start'
		ips = list()
		for ip in ipcalc.Network(self.options['RHOSTS'][0]):
			ips.append(str(ip))
		while ips:
			for i in range(int(self.options['Threads'][0])):
				if(len(ips) > 0):
					thread 	= threading.Thread(target=self.do,args=(ips.pop(0),redist, count))
					thread.start()
					THREADS.append(thread)
					count += 1
				else:
					break
			for thread in THREADS:
				thread.join()
		if(self.options['Output'][0]):
			open(mainPath + '/Output/' + moduleName + '_' + self.options['RHOSTS'][0].replace('/','_') + '.txt','a').write('='*30 + '\n' + self.output + '\n\n')
		self.output 	= ''
		redist.set("finished", 0)

	def printLine(self,str,color):
		self.output += str + '\n'
		if(str.find('[+]') != -1):
			print str.replace('[+]',color + '[+]' + bcolors.ENDC)
		elif(str.find('[-]') != -1):
			print str.replace('[-]',color + '[-]' + bcolors.ENDC)
		else:
			print str

	def do(self, ip, erd, counter):
		result = Modbus.connectToTarget(ip,self.options['RPORT'][0])
		if (result != None):
			self.printLine('[+] Modbus is running on : ' + ip,bcolors.OKGREEN)
			name = 'discover ip %s'%counter
			erd.set(name , ip)
			#plugins = Loader.plugins(modulesPath)
			#plugins.crawler()
			#plugins.load()
			#pluginNumber = len(plugins.pluginTree)
			#modules = plugins.modules
			#modules["modbus/dos/writeSingleRegister"].options["RHOSTS"][0] = ip
			#modules["modbus/dos/writeSingleRegister"].options["RegisterAddr"][0] = "7"
			#modules["modbus/dos/writeSingleRegister"].options["RegisterValue"][0] = "7"
			#modules["modbus/dos/writeSingleRegister"].exploit()
		else:
			self.printLine('[-] Modbus is not running on : ' + ip,bcolors.WARNING)

