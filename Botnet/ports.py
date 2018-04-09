import nmap 

nm = nmap.PortScanner()
nm.scan('172.16.0.1', '22-443') # scan host 192.168.1.1, ports from 22 to 443

host = 0
for host in nm.all_hosts():
	print('Host : %s (%s)' % (host, nm[host].hostname()))
	print('State : %s' % nm[host].state())

	for proto in nm[host].all_protocols():
		print('----------')
		print('Protocol : %s' % proto)

	lport = nm[host][proto].keys()
	lport.sort()
	for port in lport:
		print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

	print('----------------------------------------------------')
	print(nm.csv())
