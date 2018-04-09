import sys
import ifcfg
from scapy.all import srp,Ether,ARP,conf 
import nmap 
import unicodedata

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

lips = []
lmac = []
nm = nmap.PortScanner()
for name, interface in ifcfg.interfaces().items():
    try:
        if name != 'lo' :
            netmask = unicodedata.normalize('NFKD', interface['netmask']).encode('ascii','ignore') 
            ips = unicodedata.normalize('NFKD', interface['inet']).encode('ascii','ignore') + maskConverter(netmask)
            interface = unicodedata.normalize('NFKD', name).encode('ascii','ignore')
            print ("\n[*] %s" %name)
            print ("(*) Interface: %s" % interface)
            print ("(*) Mascara: %s" % ips)
            conf.verb = 0 
            nm.scan (ips,'1-65535')
            print nm.all_hosts()
    except:
        pass
print lips
print "\n[*] Scan Complete!" 


# for x in lips:
#     nm.scan(x, '0-2496')
#     print nm[x].hostnames()


