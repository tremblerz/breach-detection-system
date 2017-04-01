from utilities.system_utilities import abort
from utilities.handlers import handle_ctrl_c
from utilities.characters import eth_addr
import pcapy
from parameters import *
import sys
from datetime import datetime
import multiprocessing
from struct import unpack
import socket
from analyzer.core_analyzer import analyzerSchedular
import time

class Sniffer(multiprocessing.Process):
    """docstring for Sniffer"""

    def __init__(self, device):
        super(Sniffer, self).__init__()
        self.device = device
        self.session_handler = pcapy.open_live(
            device, SNAPLEN, PROMISCOUS_MODE, CAPTURE_TIMEOUT)
        self.TOTAL_COUNT = 0

    def run(self):
        """Summary

        Args:
            session_handler : File descriptor for the packet capturing sniffer interface

        Returns:
            error_code (Integer): Error code specifying the error occurred during the packet sniffing purpose
        """
        while (True):
            (header, packet) = self.session_handler.next()
            self.TOTAL_COUNT += 1
            print("[%d] %s: captured %d bytes, truncated to %d bytes" % (
                self.TOTAL_COUNT, datetime.now(), header.getlen(), header.getcaplen()))


class Parser(multiprocessing.Process):
    """docstring for Wait"""

    def __init__(self, queue, packet):
        super(Parser, self).__init__()
        self.packet = packet
        self.queue = queue

    def parse_eth(self):
        """Summary

        Returns:
            TYPE: Description
        """
        eth_header = self.packet[:ETH_LENGTH]
        eth = unpack('!6s6sH', eth_header)
        eth_protocol = socket.ntohs(eth[2])
        DEST_MAC_ADDR = eth_addr(self.packet[0:6])
        SRC_MAC_ADDR = eth_addr(self.packet[6:12])
        return {'eth_header': eth_addr, 'eth': eth, 'eth_protocol': eth_protocol,
                'dst_mac_addr': DEST_MAC_ADDR, 'src_mac_addr': SRC_MAC_ADDR}

    def parse_IP(self, parsed_data):
        """Summary

        Args:
            parsed_data (TYPE): Description

        Returns:
            TYPE: Description
        """
        ip_header = self.packet[ETH_LENGTH:20+ETH_LENGTH]
        ip_header = unpack('!BBHHHBBH4s4s', ip_header)
        version_ihl = ip_header[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = ip_header[5]
        protocol = ip_header[6]
        s_addr = socket.inet_ntoa(ip_header[8])
        d_addr = socket.inet_ntoa(ip_header[9])
        return {'version': version, 'IP_header_length': ihl, 'ttl': ttl,
                'protocol': protocol, 'SRC_addr': s_addr, 'DST_addr': d_addr,
                'iph_length': iph_length}

    def parse_TCP(self, parsed_data):
        """Summary

        Args:
            parsed_data (TYPE): Description

        Returns:
            TYPE: Description
        """
        tcp_index = parsed_data['IP']['iph_length'] + ETH_LENGTH
        tcp_header = self.packet[tcp_index:tcp_index+20]

        tcp_header = unpack('!HHLLBBHHH', tcp_header)

        source_port = tcp_header[0]
        dest_port = tcp_header[1]
        sequence = tcp_header[2]
        acknowledgement = tcp_header[3]
        doff_reserved = tcp_header[4]
        tcph_length = doff_reserved >> 4

        return {'source_port': source_port, 'dest_port': dest_port, 'sequence': sequence,
                'acknowledgement': acknowledgement, 'doff_reserved': doff_reserved,
                'tcph_length': tcph_length}

    def parse_ICMP(self, parsed_data):
        """Summary

        Args:
            parsed_data (TYPE): Description

        Returns:
            TYPE: Description
        """
        icmp_index = parsed_data['IP']['iph_length'] + ETH_LENGTH
        icmp_header = self.packet[icmp_index:icmp_index+4]

        # now unpack them :)
        icmp_header = unpack('!BBH', icmp_header)

        icmp_type = icmp_header[0]
        code = icmp_header[1]
        checksum = icmp_header[2]

        return {'icmp_type': icmp_type, 'code': code, 'checksum': checksum}

    def parse_UDP(self, parsed_data):
        """Summary

        Args:
            parsed_data (TYPE): Description

        Returns:
            TYPE: Description
        """
        udp_index = parsed_data['IP']['iph_length'] + ETH_LENGTH
        udp_header = self.packet[udp_index:udp_index+UDPH_LENGTH]

        # now unpack them :)
        udp_header = unpack('!HHHH', udp_header)

        source_port = udp_header[0]
        dest_port = udp_header[1]
        length = udp_header[2]
        checksum = udp_header[3]

        return {'source': source_port, 'dest_port': dest_port,
                'length': length, 'checksum': checksum}

    def parse_application(self, parsed_data, h_size):
        """Summary

        Args:
            parsed_data (TYPE): Description

        Returns:
            TYPE: Description
        """
        application_data = self.packet[h_size:]
        return {'application_data': application_data}

    def run(self):
        # print(len(self.packet))
        parsed_data = self.parse_eth()
        if parsed_data['eth_protocol'] == IP_PROTOCOL:
            parsed_data['IP'] = self.parse_IP(parsed_data)
            if parsed_data['IP']['protocol'] == TCP_PROTOCOL:
                parsed_data['IP']['TCP'] = self.parse_TCP(parsed_data)
                h_size = ETH_LENGTH + parsed_data['IP']['iph_length'] + parsed_data['IP']['TCP']['tcph_length']
                parsed_data['IP']['TCP']['PAYLOAD'] = self.parse_application(parsed_data, h_size)
            elif parsed_data['IP']['protocol'] == ICMP_PROTOCOL:
                parsed_data['IP']['ICMP'] = self.parse_ICMP(parsed_data)
                h_size = ETH_LENGTH + parsed_data['IP']['iph_length'] + ICMPH_LENGTH
                parsed_data['IP']['ICMP']['PAYLOAD'] = self.parse_application(parsed_data, h_size)
            elif parsed_data['IP']['protocol'] == UDP_PROTOCOL:
                parsed_data['IP']['UDP'] = self.parse_UDP(parsed_data)
                h_size = ETH_LENGTH + parsed_data['IP']['iph_length'] + UDPH_LENGTH
                parsed_data['IP']['UDP']['PAYLOAD'] = self.parse_application(parsed_data, h_size)
            else:
                print("Unidentified transport layer protocol number " +
                      str(parsed_data['IP']['protocol']) + "!")
            #print(parsed_data)
            self.parsed_data = parsed_data
            #print("putting in queue")
            self.queue.put(self.parsed_data)
        else:
            self.parsed_data = "Without ethernet header"


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
        """sniffer_process = Sniffer(device_capture)
        print_process = Wait()
        sniffer_process.start()
        print_process.start()"""
        pcap = pcapy.open_live(device_capture, SNAPLEN,
                               PROMISCOUS_MODE, CAPTURE_TIMEOUT)
        TOTAL_COUNT = 0
        while(True):
            (header, packet) = pcap.next()
            TOTAL_COUNT += 1
            queue = multiprocessing.Queue()
            print("[%d] %s: captured %d bytes, truncated to %d bytes" % (
                TOTAL_COUNT, datetime.now(), header.getlen(), header.getcaplen()))
            parse_object = Parser(queue, packet)
            parse_object.start()
            
            analysis = analyzerSchedular(queue.get())
            analysis.start()
    else:
        error_message = 'Device specified is not present in the list'
        abort(-1, error_message)

if __name__ == "__main__":
    handle_ctrl_c()
    main(sys.argv)
