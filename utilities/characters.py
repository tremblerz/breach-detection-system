def eth_addr(address):
    """Summary
    
    Args:
        address (TYPE): Description
    
    Returns:
        TYPE: Description
    """
    hex_addr = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(address[0]), ord(
        address[1]), ord(address[2]), ord(address[3]), ord(address[4]), ord(address[5]))
    return hex_addr
