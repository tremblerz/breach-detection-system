from IPy import IP

def isPrivateIP(ip_address):
    """Summary
    
    Args:
        ip_address (TYPE): Description
    
    Returns:
        TYPE: Description
    """
    return IP(ip_address).iptype() == 'PRIVATE'

def extractSrcIP(parsed_packet):
    """Summary
    
    Args:
        parsed_packet (TYPE): Description
    
    Returns:
        TYPE: Description
    """
    return parsed_packet['IP']['SRC_addr']

def extractDestIP(parsed_packet):
    """Summary
    
    Args:
        parsed_packet (TYPE): Description
    
    Returns:
        TYPE: Description
    """
    return parsed_packet['IP']['DST_addr']