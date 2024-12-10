import socket
import struct
import textwrap

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t - '
DATA_TAB_2 = '\t\t - '
DATA_TAB_3 = '\t\t\t - '
DATA_TAB_4 = '\t\t\t\t - '

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        if eth_proto == 8:  # IPv4
            try:
                version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
                print(TAB_1 + 'IPv4 Packet:')
                print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
                print(TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

                if proto == 1:  # ICMP
                    icmp_type, code, checksum, data = icmp_packet(data)
                    print(TAB_1 + 'ICMP Packet:')
                    print(TAB_2 + 'Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))
                    print(TAB_2 + 'Data:')
                    print(format_multi_line(DATA_TAB_3, data))

                elif proto == 6:  # TCP
                    src_port, dest_port, sequence, acknowledgment, flags, data = tcp_segment(data)
                    print(TAB_1 + 'TCP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                    print(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                    print(TAB_2 + 'Flags:')
                    print(TAB_3 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(*flags))
                    print(TAB_2 + 'Data:')
                    print(format_multi_line(DATA_TAB_3, data))

                elif proto == 17:  # UDP
                    src_port, dest_port, size, data = udp_segment(data)
                    print(TAB_1 + 'UDP Segment:')
                    print(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, size))

                else:
                    print(TAB_1 + 'Data:')
                    print(format_multi_line(DATA_TAB_2, data))

            except ValueError as e:
                print(TAB_1 + 'IPv4 Packet Error:', e)

        else:
            print(TAB_1 + 'Data:')
            print(format_multi_line(DATA_TAB_1, data))


def ethernet_frame(data):
    """Unpacks Ethernet frame."""
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def get_mac_addr(bytes_addr):
    """Returns properly formatted MAC address."""
    return ':'.join('{:02x}'.format(b) for b in bytes_addr).upper()


def ipv4_packet(data):
    """Unpacks IPv4 packet."""
    if len(data) < 20:
        raise ValueError("Data is less than 20 bytes, invalid IPv4 packet.")
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]


def ipv4(addr):
    """Returns properly formatted IPv4 address."""
    return '.'.join(map(str, addr))


def icmp_packet(data):
    """Unpacks ICMP packet."""
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_segment(data):
    """Unpacks TCP segment."""
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = (
        (offset_reserved_flags & 32) >> 5,  # URG
        (offset_reserved_flags & 16) >> 4,  # ACK
        (offset_reserved_flags & 8) >> 3,   # PSH
        (offset_reserved_flags & 4) >> 2,   # RST
        (offset_reserved_flags & 2) >> 1,   # SYN
        offset_reserved_flags & 1           # FIN
    )
    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]


def udp_segment(data):
    """Unpacks UDP segment."""
    src_port, dest_port, size = struct.unpack('! H H H', data[:6])
    return src_port, dest_port, size, data[8:]


def format_multi_line(prefix, string, size=80):
    """Formats multi-line data for display."""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


main()
