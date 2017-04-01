import multiprocessing
from analyzer.IP2LocationPythonmaster.IP2Location import IP2Location
import numpy as np



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
    	IP2locObj.open("/home/abhi/Downloads/CourseMaterial/Networking/Information_Security/projects/breach-detection-system/analyzer/IP2LocationPythonmaster/data/IP-COUNTRY.BIN")
    	country = IP2locObj.get_all(dest_ip)
    	return country.country_long

    def check_ip_vuln(self, country, ip):
		newDict = {}
		f = open('/home/abhi/Downloads/CourseMaterial/Networking/Information_Security/projects/breach-detection-system/analyzer/data/vuln_countries.txt', 'r')
		for line in f:
			splitLine = line.split()
			newDict[splitLine[0]] = ' '.join(splitLine[1:])
		check_country = self.find_region(ip)
		
		#return newDict["2"]
		if check_country == newDict["1"] or check_country == newDict["2"]:
			return 1
		else:
			return 0
    def run(self):
    	dest_ip = self.parse_dest_ip()
    	#print(dest_ip)
    	country = self.find_region(dest_ip)
    	print(country)	
    	vuln = self.check_ip_vuln(country, dest_ip)
    	#src_ip = self.parse_src_ip()
    	if vuln == 1:
            print("[DANGER] Potential threat:")
    		#insert_values(src_ip, dest_ip, 60, 'Potential threat is there')
    	else:
            print("Normal traffic")
    		#inser_values(src_ip, dest_ip, 20, 'Not a potential threat')
        pass
