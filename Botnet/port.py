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