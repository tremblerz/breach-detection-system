from utilities.system_utilities import abort
import pcapy
from parameters import *
import sys
from datetime import datetime
import multiprocessing

class Sniffer(multiprocessing.Process):
    """docstring for Sniffer"""
    def __init__(self, arg):
        super(Sniffer, self).__init__()
        self.arg = arg
        self.session_handler = pcapy.open_live(
            device, SNAPLEN, PROMISCOUS_MODE, CAPTURE_TIMEOUT)
        
    def run(session_handler):
        """Summary

        Args:
            session_handler : File descriptor for the packet capturing sniffer interface

        Returns:
            error_code (Integer): Error code specifying the error occurred during the packet sniffing purpose
        """
        while (True):
            (header, packet) = self.session_handler.next()
            print("%s: captured %d bytes, truncated to %d bytes" %
                  (datetime.now(), header.getlen(), header.getcaplen()))


def main(argv):
    """Summary

    Args:
        argv (TYPE): Description

    Returns:
        TYPE: Description
    """
    all_devices = pcapy.findalldevs()
    print(all_devices)
    for device in all_devices:
        print(device)

    device_capture = raw_input("Enter the device to be sniffed: ")
    if device_capture in all_devices:
        sniffer_process = Sniffer()
        sniffer_process.run()
    else:
        error_message = 'Device specified is not present in the list'
        abort(-1, error_message)

if __name__ == "__main__":
    main(sys.argv)
