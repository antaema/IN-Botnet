class Machine:
    def __init__(self, Ip, Mac, ports):
        self.Ip = Ip
        self.Mac = Mac
        self.ports = ports
        self.hostname = ' '
    
    def Print(self):
        print '** I am ' + self.Ip 
        print '-- My Mac is: ' + self.Mac
        try:	
            print '-- This are my houses:  ',
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

	