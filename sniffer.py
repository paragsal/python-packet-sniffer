import socket
import struct
# import textwrap

def main():
    # #conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    # conn = socket.socket()
    # host = socket.gethostname()  # Get local machine name
    # port = 4573
    # conn.bind((host, port))
    # conn.recvfrom(65536)
    # print('start')
    # while True:
    #     c, addr = conn.accept()  # Establish connection with client.
    #     print(addr)
    #     conn.close()
    # # while True:
    # #     raw_data, addr = conn.recvfrom(65536)
    # #     dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
    # #     print("\nEthernet frame: ")
    # #     print('Destination {}, Source {}, Protocol {]'.format(dest_mac, src_mac, eth_proto))

    # # Get host
    # host = socket.gethostbyname(socket.gethostname())
    # print('IP: {}'.format(host))
    #
    # # Create a raw socket and bind it
    # conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)
    # conn.bind((host, 0))
    #
    # # Include IP headers
    # conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # # Enable promiscuous mode
    # conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    #
    # while True:
    #     # Receive data
    #     raw_data, addr = conn.recvfrom(65536)
    #
    #     # Unpack data
    #     dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
    #
    #     print('\nEthernet Frame:')
    #     print("Destination MAC: {}".format(dest_mac))
    #     print("Source MAC: {}".format(src_mac))
    #     print("Protocol: {}".format(eth_proto))


    HOST = socket.gethostbyname(socket.gethostname())
    print('IP: {}'.format(HOST))


    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)

    conn.bind(('', 80))
    #conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    #conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    print('xxxxxxxxxx')
    print(conn.getsockname()[1])
    conn.connect((HOST, 80))
    while True:
        print('yesy')
        raw_data, addr = conn.recvfrom(65535)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))


# unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# get mac address in a proper format
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

main()
