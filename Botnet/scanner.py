import sys
import ifcfg
import nmap 
import socket
import unicodedata
from scapy.all import srp,Ether,ARP,conf 

sys.path.append("./")

class Scanner:
	def __init__(self):
		self.lmachine = []
		self.nm = nmap.PortScanner()

	def find_Mask(self,interface):
		broadcast = unicodedata.normalize('NFKD', interface['broadcast']).encode('ascii','ignore')

		if interface['netmask'] == None:
   			netmask = Netlib.broadcast2Mask(broadcast)
		else:
			netmask = unicodedata.normalize('NFKD', interface['netmask']).encode('ascii','ignore') 
		return netmask

	def find_Ip(self,interface,netmask):
		broadcast = unicodedata.normalize('NFKD', interface['broadcast']).encode('ascii','ignore')

		if interface['inet'] == None:
			ips = Netlib.broadcast2Ip(broadcast,netmask)
		else:
			ips = unicodedata.normalize('NFKD', interface['inet']).encode('ascii','ignore') + Netlib.maskConverter(netmask)
		return ips
	
	def scanIp(self,Ip,Mac):
		self.nm.scan(Ip,'1-8000')
		ports = []
		for protocol in self.nm[Ip].all_protocols():
			lport = self.nm[Ip][protocol].keys()
			lport.sort()
			for port in lport:
				name = self.nm[Ip][protocol][port]['name']
				state = self.nm[Ip][protocol][port]['state']
				product = self.nm[Ip][protocol][port]['product']
				p = Port(port,name,state,product,protocol)
				ports.append(p)
		m = Machine(Ip,Mac,ports)
		if 'hostnames' in self.nm[Ip]:
			m.hostname = self.nm[Ip]['hostnames']
		self.lmachine.append(m)
		# m.Print()

	def findLocals(self):
		for name, interface in ifcfg.interfaces().items():
			if name != 'lo':
				if 'broadcast' in interface:
					netmask = self.find_Mask(interface)
					ips = self.find_Ip(interface,netmask)
					rede = unicodedata.normalize('NFKD', name).encode('ascii','ignore')
					
					# print ("\n[*] %s" %name)
					# print ("(*) Interface: %s" % rede)
					# print ("(*) Ip: %s" % ips)
					# print ("(*) Mascara: %s" % netmask)
					
					conf.verb = 0 
					ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips), timeout = 2, iface=rede)
					for snd,rcv in ans:     
						Mac,Ip = rcv.sprintf(r"%Ether.src% %ARP.psrc%").split()
						find = False
						for m in self.lmachine:
							if m.Ip  == Ip:
								find = True
								break
						if find == False:		
							self.scanIp(Ip,Mac)					
		# print "\n[*] Scan Complete!" 
		
class Port:
	def __init__(self,port,name,state,product,protocol):
		self.port = port
		self.name = name
		self.state = state
		self.product = product
		self.protocol = protocol
	
	def getPort(self):
		return self.port

	def getName(self):
		return self.name
	
	def getState(self):
		return self.state
	
	def getProduct(self):
		return self.product
	
	def getProtocol(self):
		return self.protocol

class Machine:
	def __init__(self,Ip,Mac,ports):
		self.Ip = Ip
		self.Mac = Mac
		self.ports = ports

	def getIp(self):
		return self.Ip

	def getMac(self):
		return self.Mac

	def getPorts(self):
		return self.ports
	
	def getHostnames(self):
		try:
			return self.hostname
		except:
			return ''


	def Print(self):
		print '** I am ' + self.Ip 
		print '-- My Mac is: ' + self.Mac
		try:	
			print '-- This arsys.path.append("./")e my houses:  ',
			for i in self.hostname:
				print i['name'],
		except:
			pass
		print ' '
		print '-- My Ports are: '
		print ' '
		for p in self.ports:
			print '---- Hi I am the port ' + str(p.getPort()) + " !"
			print '---- You can call me  ' + p.getName() + " ."
			print '---- But my nickname is ' + p.getProduct() + " ."
			print '---- Today my mood is ' + p.getState() + " !"
			print '---- And i can talk by  ' + p.getProtocol() + "." 
			print 'Bye Bye'
			print ' '



class Netlib: 	
	@staticmethod
	def maskConverter(s):
		return {
			"0.0.0.0"   : "/0",
			"128.0.0.0" : "/1",
			"192.0.0.0" : "/2",
			"224.0.0.0" : "/3",
			"240.0.0.0" : "/4",
			"248.0.0.0" : "/5",
			"252.0.0.0" : "/6",
			"254.0.0.0" : "/7",
			"255.0.0.0" : "/8",
			"255.128.0.0" : "/9",
			"255.192.0.0" : "/10",
			"255.224.0.0" : "/11",
			"255.240.0.0" : "/12",
			"255.248.0.0" : "/13",
			"255.252.0.0" : "/14",
			"255.254.0.0" : "/15",
			"255.255.0.0" : "/16",
			"255.255.128.0" : "/17",
			"255.255.192.0" : "/18",
			"255.255.224.0" : "/19",
			"255.255.240.0" : "/20",
			"255.255.248.0" : "/21",
			"255.255.252.0" : "/22",
			"255.255.254.0" : "/23",
			"255.255.255.0" : "/24",
			"255.255.255.128" : "/25",
			"255.255.255.192" : "/26",
			"255.255.255.224" : "/27",
			"255.255.255.240" : "/28",
			"255.255.255.248" : "/29",
			"255.255.255.252" : "/30",
			"255.255.255.254" : "/31",
			"255.255.255.255" : "/32"
		}.get(s, '/16')    
	
	@staticmethod
	def broadcast2Mask(s):
		last = 0
		points = 0
		r = ''
		for i in range(0,len(s)):
			if s[i] == '.' or points == 3:
				if s[last : i] == '255':
					r = r + 0
					points += 1
					while points < 3:
						r = r + '.0'
						points += 1
					return r
				elif points == 3:
					return r + '0'
				else:
					r = r + '255.'
					last = i + 1
					points += 1
	@staticmethod
	def broadcast2Ip(s, mask):
		last = 0
		points = 0
		for i in range(0,len(s)):
			if s[i] == '.' or points == 3:
				if s[last : i] == '255':
					r = s[0 : last - 1]
					while points < 3:
						r = r + '.0'
						points += 1
					return r + Netlib.maskConverter(mask)
				elif points == 3:
					r  = s[0 : last] + '0'
					return r + Netlib.maskConverter(mask)
				else:
					last = i + 1
					points += 1




def main():
	try:
		scan = Scanner()
		scan.findLocals()
		scan.scanIp(socket.gethostbyname('lightron.org'),'')
		scan.scanIp(socket.gethostbyname('www.desentupidorarolabosta.com.br'),'')
	except KeyboardInterrupt:
		print "Exit"
		sys.exit()

if __name__ == "__main__":
    main()