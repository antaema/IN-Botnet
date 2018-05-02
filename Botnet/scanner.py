import sys
import ifcfg
import nmap 
import unicodedata
from scapy.all import srp,Ether,ARP,conf 

class Port:
	def __Init__(self,port,name,state,product,protocol):
		self.port = port
		self.name = name
		self.state = state
		self.product = product
		self.protocol = protocol

class Machine:
	def __Init__(self,Ip,Mac,ports):
		self.Ip = Ip
		self.Mac = Mac
		self.ports = ports
	def Print(self):
		print '** I am ' + Ip

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


lips = []
lmac = []
nm = nmap.PortScanner()
for name, interface in ifcfg.interfaces().items():
    if name != 'lo':
   		broadcast = unicodedata.normalize('NFKD', interface['broadcast']).encode('ascii','ignore')

   		if interface['netmask'] == None:
   			netmask = Netlib.broadcast2Mask(broadcast)
		else:
			netmask = unicodedata.normalize('NFKD', interface['netmask']).encode('ascii','ignore') 
        
		if interface['inet'] == None:
			ips = Netlib.broadcast2Ip(broadcast,netmask)
		else:
			ips = unicodedata.normalize('NFKD', interface['inet']).encode('ascii','ignore') + Netlib.maskConverter(netmask)

		interface = unicodedata.normalize('NFKD', name).encode('ascii','ignore')
		print ("\n[*] %s" %name)
		print ("(*) Interface: %s" % interface)
		print ("(*) Mascara: %s" % ips)
		conf.verb = 0 
		ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips), timeout = 2, iface=interface)
		for snd,rcv in ans:     
			Mac,Ip = rcv.sprintf(r"%Ether.src% %ARP.psrc%").split()
			if Ip not in lips:
				lmac.append(Mac)
				lips.append(Ip)
				nm.scan (Ip,'1-1200')
				print '[*] Ip',
				print Ip
				print nm[Ip]
print "\n[*] Scan Complete!" 


host = 0
for host in nm.all_hosts():
	print('----------------------------------------------------')
	print('Host : %s (%s)' % (host, nm[host].hostname()))
	print('Operational System : %s' % nm[host]['osclass'])
	print('State : %s' % nm[host].state())

	for proto in nm[host].all_protocols():
		print('----------')
		print('Protocol : %s' % proto)

	lport = nm[host][proto].keys()
	lport.sort()
	for port in lport:
		print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

	print('----------------------------------------------------')
	# print result as CSV
	print(nm.csv())

