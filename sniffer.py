#!/usr/bin/python3

import socket
from struct import *
import sys
from auxiliar import *

# Ethernet Header -> 14 bytes
# IP Header -> 20 bytes
# TCP Header -> 14 bytes
# UDP Header -> 8 bytes
# ICMP Header -> 4 bytes

def format_MAC(mac):
    string = map('{:02x}'.format, mac)
    mac_address = ':'.join(string).upper()
    return mac_address

try:
    raw_socket = socket.socket(
        socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

except socket.error as e:
    print("Error happend while creating the raw socket. Error code: " +
          str(e[0]) + ", Error message: " + e[1])
    sys.exit(1)

while True:
    packet = raw_socket.recvfrom(65565)[0]  # informação recebida em bytes

    # FRAMES Ethernet

    ethernet_header = packet[0:14]

    # 6s -> 6 char (string), H -> unsigned short, integer, 2 bytes
    (destination_MAC, source_MAC, ethernet_type) = unpack('! 6s 6s H', ethernet_header)

    destination_MAC = format_MAC(destination_MAC)
    source_MAC = format_MAC(source_MAC)
    ethernet_type = socket.htons(ethernet_type)

    print('[Ethernet] -> Destination:' + str(destination_MAC) +
          ' | Source:' + str(source_MAC) + ' | Type:' + str(ethernet_type))

    # PACOTES IP

    ip_header = packet[14:34]

    # Estrutura IP
    version_iheader_length = ip_header[0]
    version = version_iheader_length >> 4
    ip_header_length = (version_iheader_length & 15) * 4

    (ttl, protocol, source_address, destination_address) = unpack('! 8x B B 2x 4s 4s', ip_header)

    source_address = socket.inet_ntoa(source_address)
    destination_address = socket.inet_ntoa(destination_address)

    print('[IP] -> Version:' + str(version) + ' | Header Length:' + str(ip_header_length) + ' | TTL:' + str(ttl) +
          ' | Protocol:' + str(protocol) + ' | Source:' + str(source_address) + ' | Destination:' + str(destination_address))

    # ICMP (1), TCP (6), and UDP (17)

    if protocol == 6: # TCP

        tcp_header = packet[34:48]

        # H -> 2 bytes (integer), L -> 4 bytes (integer)
        (source_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = unpack('! H H L L H', tcp_header)

        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1

        print('[TCP] -> Source Port:' + str(source_port) + ' | Destination Port:' + str(dest_port) + ' | Sequence Number:' + str(sequence) + ' | Acknowledgment Number:' + str(acknowledgment) + ' | Data Offset:' +
              str(offset_reserved_flags) + ' [TCP Flags] -> URG:' + str(flag_urg) + ' ACK:' + str(flag_ack) + ' PSH:' + str(flag_psh) + ' RST:' + str(flag_rst) + ' SYN:' + str(flag_syn) + ' FIN:' + str(flag_fin))

        # Data begins at headers_size byte
        #headers_size = ip_header_length + offset * 4
        #data_size = len(packet) - headers_size
        #data = packet[headers_size:]

        print('TCP Data: ' + str(packet[:48]))

    elif protocol == 1: # ICMP

        icmp_header = packet[34:38]

        # B -> 1 bytes (integer), H -> 2 bytes (integer)
        (icmp_type, code, checksum) = unpack('! B B H', icmp_header)

        print('[ICMP] -> Type:' + str(icmp_type) + ' | Code:' + str(code) + ' | Checksum:' + str(checksum))

        data = packet[38:]
        print('ICMP Data: ' + str(data))

    elif protocol == 17: # UDP

        udp_header = packet[34:42]

        (source_port, dest_port, length, checksum) = unpack('! H H H H', udp_header)
        print('[UDP] -> Source Port:' + str(source_port) + ' | Destination Port:' + str(dest_port) + ' | Length:' + str(length) + ' | Checksum:' + str(checksum))

        data = packet[42:]
        print('UDP Data: ' + str(data))

    else:
    	print('[IP Header] -> protocol: ' + str(protocol))
    	print('IP Data:' + str(packet[34:]))

    
    print('\n')
