# Intelligent Breach Detection System
### Components
#### Interceptor
##### This component captures the ongoing traffic on a system with the help of packet capture library pcap. Various filters and parsers do the job of retreiving useful information out of the packet. Currently python-pcapy package is being used.
#### 2. Analyzer
##### Analyzer runs different set of algorithms for detecting malicious pattern and abnormal behaviour. 
#### 3. Dashboard
##### This component is for Administrators and Network activity moderators through which they can spot various activities happening in their networks.