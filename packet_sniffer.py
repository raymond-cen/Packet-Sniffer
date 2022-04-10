from asyncio import protocols
from socket import *
import struct
import textwrap
from datetime import date, datetime
import re
import threading
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive

gauth = GoogleAuth()
gauth.LocalWebserverAuth()

drive = GoogleDrive(gauth)

def main():
    host_list = socketiplist()
    for ip in host_list:
        thread = threading.Thread(target=recv_data, args=[ip])
        thread.start()
        
def recv_data(host_ip):
    conn = socket(AF_INET, SOCK_RAW, IPPROTO_IP)
    conn.bind((host_ip,0))
    conn.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
    conn.ioctl(SIO_RCVALL, RCVALL_ON)
    print_list = []
    while True:
        if len(print_list) > 20:
            upload_to_drive('\n'.join(print_list)) 
            print_list = []
        raw_data, addr = conn.recvfrom(65536) #max buffer size
        # mac_dest, mac_src, proto, data = ethernet_frame(raw_data)
        # print('\n Ethernet Frame:')
        # print('Destination : {}, Source: {}, Protocol: {}'.format(mac_dest, mac_src, proto))
        current_time, version, header_len, tos, total_len, identification, x_bit, DFF, MFF, frag_offset, TTL, proto, header_checksum, s_ip, d_ip, data = ipv4_frame(raw_data)
        printed_data = """Current Time: {}
    IPv4 Packet:
        -Version : {}, Header Length : {}, TOS : {}, Total Length : {}
        - ID : {}, Flags : {}|{}|{}, Fragment Offset : {}, TTL : {}
        - Protocol : {}, Checksum : {}, Source IP : {}, Destination IP : {}""" .format( str(current_time),str(version), str(header_len), str(tos), str(total_len), str(identification), str(x_bit), str(DFF), str(MFF), str(frag_offset), str(TTL), str(proto), str(header_checksum), s_ip, d_ip )
        print(printed_data)
        print_list.append(printed_data)
        if proto == 6:
            src_port, dest_port, seq_no, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_header(raw_data)
            printed_data = """   TCP Header
        - Source Port: {}, Destination Port: {}
        - Sequence: {}, Acknowledgement: {}
        - Flags:
            URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}
        - Data: {}""".format(src_port, dest_port, seq_no, ack,flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data)
        print(printed_data)
        print_list.append(printed_data)
        if proto == 1:
            icmp_header, code, checksum, data = icmp_header(raw_data)
            printed_data = """   ICMP Packet
    Type {}, Code: {}, Checksum: {}""".format(icmp_header, code, checksum)
            print(printed_data)
            print_list.append(printed_data)

        elif proto == 17:
            src_port, dest_port, size, data = udp_header(raw_data)
            printed_data = """UDP Header
    Source Port: {}, Destination Port: {}, Length: {}""".format(src_port, dest_port, size)
            print(printed_data)
            print_list.append(printed_data)
 
#unpack ethernet frame DOES NOT WORK WITH WINDOWS 
def ethernet_frame(data):
    mac_dest, mac_src, proto = struct.unpack('! 6s 6s H', data[:14]) # 6s = 6bytes H = unsigned int
    return get_mac_addr(mac_dest), get_mac_addr(mac_src), htons(proto), data[14:]

def ipv4_frame(data):
    vihl, tos, total_len, identification, flags_offset, TTL, proto, header_checksum, s_ip, d_ip = struct.unpack('! B B H H H B B H 4s 4s', data[:20])
    version = vihl >> 4
    header_len = (vihl & 15) * 4

    #Extracting x_bit, Do Not Fragment Flag and More Fragments Follow Flag.
    x_bit =  (flags_offset >> 15) & 1 
    DFF   =  (flags_offset >> 14) & 1
    MFF   =  (flags_offset >> 13) & 1

    #Extracting Fragment Offset
    frag_offset = flags_offset & 8191

    # get time when it is extracted
    now = datetime.now()
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")

    return dt_string, version, header_len, tos, total_len, identification, x_bit, DFF, MFF, frag_offset, TTL, proto, header_checksum, inet_ntoa(s_ip), inet_ntoa(d_ip), data[header_len:]

# Extracts TCP Header
def tcp_header(data):
    (src_port, dest_port, seq_no, ack, offset_reserved_flag) = struct.unpack('!H H L L H', data[:14])
    offset = (offset_reserved_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 16) >> 4
    flag_psh = (offset_reserved_flag & 8) >> 3
    flag_rst = (offset_reserved_flag & 4) >> 2
    flag_syn = (offset_reserved_flag & 2) >> 1
    flag_fin = (offset_reserved_flag & 1)
    return src_port, dest_port, seq_no, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
    
# Extracts UDP Header
def udp_header(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

# Extracts ICMP Header
def icmp_header(data):
    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])
    return icmp_type, code, checksum, data[4:]

# Extracts list of IP addresses of Your Computer
def socketiplist():
    listofaddr = list(gethostbyname_ex(gethostname()))
    newlist = []
    for e in listofaddr:
        if isinstance(e, list):
            if e:
                for i in e:
                    newlist.append(i)
            else:
                continue
        else:
            newlist.append(e)
    newnewlist = []
    for e in newlist:
        ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', e)
        if len(ip) > 0:
            for i in ip:
                newnewlist.append(i)
    return newnewlist

# return properly formatted MAC address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def getip(ip_bytes):
    return '.'.join(map(str, ip_bytes))

def upload_to_drive(text):
    file = drive.CreateFile({'title': 'Packet Sniffer.txt', 'id': '1PeNHnlV93QiiwT5xCWlrcbYmiE4qAAGn' })  # Create GoogleDriveFile instance

    file_list = drive.ListFile({'q': "'root' in parents and trashed=false"}).GetList()
    # Iterates through google drive for correct file and uploads new text
    for file in file_list:
        if file['title'] == 'Packet Sniffer.txt':
            new_file = drive.CreateFile({'title': file['title'], 'id': file['id']})
            file_content = new_file.GetContentString()
            file_content = file_content + '\n' + text
            new_file.SetContentString(file_content)
            new_file.Upload()

if __name__ == "__main__":
    main()
    