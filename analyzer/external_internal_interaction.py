import multiprocessing
from analyzer.IP2LocationPythonmaster.IP2Location import IP2Location
import numpy as np

from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import confusion_matrix, zero_one_loss


class ExternalInternalInteraction(multiprocessing.Process):
    """docstring for ExternalInternalInteraction"""

    def __init__(self, arg):
        super(ExternalInternalInteraction, self).__init__()
        self.arg = arg

    def parse_dest_ip(self):
    	dest_ip = self.arg["IP"]["DST_addr"]
    	return dest_ip

    """def parse_src_ip(self):
    	src_ip = self.arg["IP"]["IP_addr"]
    	return src_ip"""

    def find_region(self, ip):
    	dest_ip = self.parse_dest_ip()
    	IP2locObj = IP2Location()
    	IP2locObj.open("/home/theprototype/breach-detection-system/analyzer/IP2LocationPythonmaster/data/IP-COUNTRY.BIN")
    	country = IP2locObj.get_all(dest_ip)
    	return country.country_long

    def check_ip_vuln(self, country, ip):
		newDict = {}
		f = open('/home/theprototype/breach-detection-system/analyzer/data/vuln_countries.txt', 'r')
		for line in f:
			splitLine = line.split()
			newDict[splitLine[0]] = ' '.join(splitLine[1:])
		check_country = self.find_region(ip)
		
		#return newDict["2"]
		with open('/home/theprototype/breach-detection-system/analyzer/data/malicious_ips.txt', 'r') as f1:
			newLine = f1.read().split('\n')
		if check_country == newDict["1"] or check_country == newDict["2"]:
			if ip in newLine:
				return 'Malware Detected'
			else:
				return 'Suspicious Activity'
		if check_country == newDict["3"] or check_country == newDict["4"] or check_country == newDict["5"]:
			if ip in newLine:
				return 'Malware Detected'
			else:
				return 'Less probable malware'
    def run(self):
    	dest_ip = self.parse_dest_ip()
    	#print(dest_ip)
    	# print(self.arg)
    	country = self.find_region(dest_ip)
    	print(country)	
    	vuln = self.check_ip_vuln(country, dest_ip)
    	#src_ip = self.parse_src_ip()
    	if vuln == 'Malware Detected':
            print("[DANGER] Confirmed threat:")
    	# 	#insert_values(src_ip, dest_ip, 60, 'Potential threat is there')
    	if vuln == 'Suspicious Activity':
            print("Suspicious Behavior")
        if vuln == 'Less probable malware':
        	print("Less suspicious behavior")
        else:
        	print("Normal behavior")
     	#print(vuln)
    		#inser_values(src_ip, dest_ip, 20, 'Not a potential threat')
        pass
