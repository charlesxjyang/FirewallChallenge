import pandas as pd
import numpy as np
#silence warnings
pd.options.mode.chained_assignment = None  # default='warn'

class IPrange:
    
    def __init__(self,addr:str):
        if '-' in addr:
            self.lower,self.upper = addr.split('-')
            self.lower,self.upper = self.convert_IP_to_int(self.lower),self.convert_IP_to_int(self.upper)
        else:
            num_addr = self.convert_IP_to_int(addr)
            self.lower = num_addr
            self.upper = num_addr
            
    def convert_IP_to_int(self,IPaddr:str):
        a,b,c,d = [int(x) for x in IPaddr.split(".")]
        a,b,c,d = 255*255*255*a,255*255*b,255*c,d
        return a+b+c+d

    def check_in_range(self,IPaddr:str):
        num_addr = self.convert_IP_to_int(IPaddr)
        if (num_addr>=self.lower)&(num_addr<=self.upper):
            return True
        else:
            return False

class FireWall:
    
    def __init__(self,rulesFilePath):
        self.rulesFilePath = rulesFilePath
        #initialize data storage structure
        self.initializePolicyStorage()
        #read csv
        self.readRules()


    def initializePolicyStorage(self):
        d = {('inbound','tcp'):np.zeros(65535+1,dtype=int), ('inbound','udp'):np.zeros(65535+1,dtype=int),
             ('outbound','tcp'):np.zeros(65535+1,dtype=int), ('outbound','udp'):np.zeros(65535+1,dtype=int)}
        self.rules = pd.DataFrame(d)
    
    def updatePolicy(self,direction:str,protocol:str,port:str,IPAddress:str):
        
        def updateSinglePort(direction:str,protocol:str,singleport:int,IPAddress:str):
            data_record = self.rules[direction,protocol][singleport]
            if isinstance(data_record,list):
                self.rules[direction,protocol][singleport].append(IPrange(IPAddress)) #don't use data_record because of index vs view issues in panda
            else:
                self.rules[direction,protocol][singleport] = [IPrange(IPAddress)]
                
            return
        
        if '-' in port:
            start_port,end_port = port.split('-')
            start_port,end_port = int(start_port),int(end_port)+1
            for port_num in range(start_port,end_port):
                updateSinglePort(direction,protocol,port_num,IPAddress)
        else: #only one port number, not range
            updateSinglePort(direction,protocol,int(port),IPAddress)
    
    def readRules(self):
        with open(self.rulesFilePath) as f:
            for line in f:
                direction,protocol,port,IPAddress = line.split(',')
                if "direction" in direction: #check if we're at header
                    continue
                else:
                    self.updatePolicy(direction,protocol,port,IPAddress)
    
    def accept_packet(self,direction:str,protocol:str,port:int,ip_address:str):
        data_record = self.rules[direction,protocol][port]
        if isinstance(data_record,list):
            return any([ip_object.check_in_range(ip_address) for ip_object in data_record])
        else:
            #if not list, then we havent initialized
            return False