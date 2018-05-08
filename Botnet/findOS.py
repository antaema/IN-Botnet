import os
import sys
from scapy.all import *
load_module("nmap")

sys.path.append("../scapy")
target="192.168.1.150"
oport = 80
cport = 81
sigs = nmap_sig(target, oport, cport)
res =  nmap_search(sigs)

accuracy = res[0]
data = res[1]
results = data
print results,accuracy