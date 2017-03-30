from utilities.system_utilities import abort
import pcapy
from parameters import *

def sniffer_scheduler(session_handler):
    """Summary
    
    Args:
        session_handler (TYPE): Description
    
    Returns:
        TYPE: Description
    """
    while (True):
        (header, packet) = session_handler.next()
        print("%s: captured %d bytes, truncated to %d bytes" %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
        parse_packet(packet)        

def main(argv):
    """Summary
    
    Args:
        argv (TYPE): Description
    
    Returns:
        TYPE: Description
    """
    all_devices = pcapy.findalldevs()
    for device in all_devices:
        print(device)

    device_capture = raw_input("Enter the device to be sniffed")
    if device in all_devices:
        session_handler = pcapy.open_live(device, SNAPLEN, PROMISCOUS_MODE, CAPTURE_TIMEOUT)
        sniffer_scheduler()
    else:
        error_message = 'Device specified is not present in the list'
        abort(-1, error_message)