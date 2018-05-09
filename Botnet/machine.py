class Machine:
    def __init__(self, Ip, Mac, ports):
        self.Ip = Ip
        self.Mac = Mac
        self.ports = ports
        self.hostname = ' '
        self.so = ''
        self.accuracy = ''
    
    def Print(self):
        print '** IP ' + self.Ip 
        print '-- MAC: ' + self.Mac
        print '-- Hostnames:  ',
        for i in self.hostname:
            print i['name'],
        print ' '
        print '-- Possibles SO\'s: ' , 
        for os in self.so:
            print os + ' ',
        print ' '
        print '-- Accuracy: ' ,
        print self.accuracy
        print '-- Ports: '
        for p in self.ports:
            print '---- Port: ' + str(p.getPort()) + " !"
            print '---- Name:  ' + p.getName() + " ."
            print '---- Product: ' + p.getProduct() + " ."
            print '---- State: ' + p.getState() + " !"
            print '---- Protocol:  ' + p.getProtocol() + "." 
            print 'Bye Bye'
            print ' '
        print '\n\n'

    
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

	