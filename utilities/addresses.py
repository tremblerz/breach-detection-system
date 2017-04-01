import IPy

def isPrivateIP(ip_address):
    """Summary
    
    Args:
        ip_address (TYPE): Description
    
    Returns:
        TYPE: Description
    """
    return IPy.IP(ip_address).iptype() == 'PRIVATE'

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

def getPayload(parsed_packet):
    """Summary
    
    Args:
        parsed_packet (TYPE): Description
    
    Returns:
        TYPE: Description
    """
    if parsed_packet['IP']['TCP']:
        payload = parsed_packet['IP']['TCP']['PAYLOAD']
    elif parsed_packet['IP']['UDP']:
        payload = parsed_packet['IP']['TCP']['PAYLOAD']
    else:
        return None
