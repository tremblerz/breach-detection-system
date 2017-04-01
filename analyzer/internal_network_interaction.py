import multiprocessing
from utilities.addresses import *
import networkx as nx

class InternalInteraction(multiprocessing.Process):
    """docstring for InternalInteraction"""

    def __init__(self, arg):
        super(InternalInteraction, self).__init__()
        self.parsed_packet = arg
        #self.graph = 

    def generate_graph(self):
        """Summary
        
        Returns:
            TYPE: Description
        """
        pass        

    def run(self):
        """Summary
        
        Returns:
            TYPE: Description
        """
        srcIP = extractSrcIP(self.arg)
        destIP = extractDestIP(self.arg)
        if isPrivateIP(srcIP) and isPrivateIP(destIP):
            #generate_graph(srcIP, destIP)
        else:
            return None