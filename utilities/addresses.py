#from IPy import IP
#from IPy import IP
from struct import unpack
from socket import AF_INET, inet_pton

def lookup(ip_address):
    """Summary
    
    Args:
        ip_address (TYPE): Description
    
    Returns:
        TYPE: Description
    """
    return IP(ip_address).iptype() == 'PRIVATE'

def isPrivateIP(ip_address):
    f = unpack('!I',inet_pton(AF_INET,ip_address))[0]
    private = (
        [ 2130706432, 4278190080 ], # 127.0.0.0,   255.0.0.0   http://tools.ietf.org/html/rfc3330
        [ 3232235520, 4294901760 ], # 192.168.0.0, 255.255.0.0 http://tools.ietf.org/html/rfc1918
        [ 2886729728, 4293918720 ], # 172.16.0.0,  255.240.0.0 http://tools.ietf.org/html/rfc1918
        [ 167772160,  4278190080 ], # 10.0.0.0,    255.0.0.0   http://tools.ietf.org/html/rfc1918
    ) 
    for net in private:
        if (f & net[1]) == net[0]:
            return True
    return False

def extractSrcIP(parsed_packet):
    """Summary
    
    Args:
        parsed_packet (TYPE): Description
    
    Returns:
        TYPE: Description
    """
    #print(parsed_packet)
    return parsed_packet['IP']['SRC_addr']

def extractDestIP(parsed_packet):
    """Summary
    
    Args:
        parsed_packet (TYPE): Description
    
    Returns:
        TYPE: Description
    """
    #print(parsed_packet)
    return parsed_packet['IP']['DST_addr']

def getPayload(parsed_packet):
    """Summary
    
    Args:
        parsed_packet (TYPE): Description
    
    Returns:
        TYPE: Description
    """
    if 'TCP' in parsed_packet['IP']:
        #print(parsed_packet['IP'])
        payload = parsed_packet['IP']['TCP']['PAYLOAD']
        return payload
    elif 'UDP' in parsed_packet['IP']:
        payload = parsed_packet['IP']['UDP']['PAYLOAD']
        return payload
    else:
        return None
