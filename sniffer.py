
import socket
import struct
import textwrap


def main():
    pc = pcap.pcap()

    pc.setfilter('icmp')

    # LINUX:
    # conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    
    # WINDOWS:
    conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP
    
    while a == 1:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))


# Unpack Ethernet frame:
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# Format MAC address (ie AA:BB:CC:EE:FF):
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


main()
















