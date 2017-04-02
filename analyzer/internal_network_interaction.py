import multiprocessing
from utilities.addresses import *
from utilities.handlers import file_load
import re
import time
from utilities.sqlite import execute_query
#import networkx as nx


class InternalInteraction(multiprocessing.Process):
    """docstring for InternalInteraction"""

    def __init__(self, arg):
        super(InternalInteraction, self).__init__()
        self.parsed_packet = arg
        # self.graph =

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
        srcIP = extractSrcIP(self.parsed_packet)
        destIP = extractDestIP(self.parsed_packet)
        # if True:
        #generate_graph(srcIP, destIP)
        payload = getPayload(self.parsed_packet)
        # print(self.parsed_packet)
        if payload is not None:
            fingerprints = file_load(
                '/home/abhi/Downloads/CourseMaterial/Networking/Information_Security/projects/breach-detection-system/datasets/shell_commands.txt')
            #print(fingerprints)
            score = 1.0
            cmd_list = ""
            for command in fingerprints:
                #match_obj = re.match(command, payload['application_data'], re.M)
                if command in payload['application_data']:
                    score += 1.0
                    cmd_list += ", " + command
                else:
                    pass
                #print(score)
                #print(score/5)
                #print((score/5)*100)
            if score > 0:
                score = (score/5)*100
                print("[BREACH]" + "shell commands found in payload, following commands were executed\n"
                    + cmd_list)
                query = "INSERT INTO bds_packet (timestamp, source, destination, breach_confidence, mac) VALUES ('%s', '%s', '%s', '%s', '%s')"%(str(time.strftime("%d/%m/%Y")), srcIP, destIP, str(int(score)), self.parsed_packet['dst_mac_addr'])
                print("[DEBUG]: " + query)
                execute_query(query)
            #return score
            else:
                pass
        else:
            pass
            #print("[DEBUG]: Payload is empty")
        # else:
            # return None
