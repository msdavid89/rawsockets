#!usr/bin/python
import argparse
import sys
from urlparse import urlparse
import socket
import struct
from random import randint
import time


def checksum(msg):
    if len(msg) % 2 == 1:
        msg = msg + struct.pack('B', 0)
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    hostname = s.getsockname()[0]
    s.close()
    return hostname


########################################################################################################
################~~~~~~~~~~~~~~IP (network layer) API~~~~~~~~~~~~~~~~~~~~~~~~~###########################
########################################################################################################

class IPHeader:
    """
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|  IHL  |Type of Service|          Total Length         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Identification        |Flags|      Fragment Offset    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Time to Live |    Protocol   |         Header Checksum       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       Source Address                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Destination Address                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Options                    |    Padding    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    def __init__(self, src_ip='', dst_ip='', payload=''):
        self.version = 4
        self.ihl = 5
        self.tos = 0
        self.length = 20
        self.id = 0
        self.flags = 0
        self.offset = 0
        self.ttl = 255
        self.proto = socket.IPPROTO_TCP
        self.chksum = 0
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.payload = payload
        self.ip_ihl_ver = (self.version << 4) + self.ihl
        self.ip_header = struct.pack('!BBHHHBBH4s4s', self.ip_ihl_ver, self.tos, self.length, self.id, self.offset, self.ttl, self.proto, self.chksum, self.src_ip, self.dst_ip)
        self.bad_packet = 0


    def gen_hdr_to_send(self):
        """Creates an IP header and prepends it to packet to send to server"""
        self.id = randint(0,65535)
        self.length = self.ihl * 4 + len(self.payload)
        src_ip = socket.inet_aton(self.src_ip)
        dst_ip = socket.inet_aton(self.dst_ip)
        self.ip_header = struct.pack('!BBHHHBBH4s4s', self.ip_ihl_ver, self.tos, self.length, self.id, self.offset, self.ttl, self.proto, self.chksum, src_ip, dst_ip)
        self.chksum = checksum(self.ip_header)
        self.ip_header = struct.pack('!BBHHHBB', self.ip_ihl_ver, self.tos, self.length, self.id, self.offset, self.ttl, self.proto) + struct.pack('H', self.chksum) + struct.pack('!4s4s', src_ip, dst_ip)

        return self.ip_header + self.payload

    def parse(self, packet):
        """Parses the packet header passed in, after receiving from the network."""
        header = packet[0:20]
        self.ip_ihl_ver, self.tos, self.length, self.id, flag_off, self.ttl, self.proto = struct.unpack('!BBHHHBB', header[0:10])
        self.chksum = struct.unpack('H', header[10:12])
        src_ip, dst_ip = struct.unpack('!4s4s', header[12:20])
        self.version = self.ip_ihl_ver >> 4
        self.ihl = self.ip_ihl_ver & 0x0f

        #Not sure if flags or offset matter
        self.flags = 0
        self.offset = 0

        self.src_ip = socket.inet_ntoa(src_ip)
        self.dst_ip = socket.inet_ntoa(dst_ip)

        self.payload = packet[20:]

        if checksum(header) != 0:
            self.bad_packet = 1


class IPHandler:
    """Handles all IP layer operations"""

    def __init__(self):
        self.src_addr = ""
        self.dst_addr = ""
        self.src_port = -1
        self.dst_port = -1
        self.sendsock = -1
        self.recvsock = -1


    def update_addr_info(self, dst_ip="", dst_port=80):
        self.dst_addr = dst_ip
        self.dst_port = dst_port
        try:
            print("DST IP/port: " + self.dst_addr + ":" + str(self.dst_port))
            self.sendsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.recvsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.src_addr = get_local_ip()
            self.sendsock.bind((self.src_addr, 0))
            #self.recvsock.bind((self.src_addr, 0))
            self.src_port = self.sendsock.getsockname()[1]
            self.recvsock.setblocking(0)
            print("SRC IP:PORT: " + self.src_addr + ":" + str(self.src_port))
        except socket.error, msg:
            print("Failed to create sockets. Womp womp. " + str(msg[1]))
            sys.exit()


    def send(self, payload):
        packet = IPHeader(self.src_addr, self.dst_addr, payload)
        to_send = packet.gen_hdr_to_send()
        try:
            self.sendsock.sendto(to_send, (self.dst_addr, self.dst_port))
        except:
            print("Error sending over network.")
            sys.exit(1)


    def recv(self):
        begin = time.time()
        while time.time() - begin < 180:
            packet = IPHeader()
            try:
                received, addr = self.recvsock.recvfrom(65535)
            except:
                continue
            if addr[0] == self.dst_addr:
                packet.parse(received)

                if packet.proto == socket.IPPROTO_TCP and packet.src_ip == self.dst_addr and packet.dst_ip == self.src_addr and packet.bad_packet == 0:
                    return packet.payload



    def close(self):
        print("Final close code.")
        self.sendsock.close()
        self.recvsock.close()

########################################################################################################
################~~~~~~~~~~~~~~TCP (transport layer) API~~~~~~~~~~~~~~~~~~~~~~###########################
########################################################################################################


class TCPHeader:
    """
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |           |U|A|P|R|S|F|                               |
| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
|       |           |G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   .... data ....                                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """

    def __init__(self, src_ip="", dst_ip="", src_port=0, dst_port=80, payload=""):
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_no = 0
        self.ack_no = 0
        self.offset = 5
        self.offset_reserved = (self.offset << 4) + 0
        self.urg = 0
        self.psh = 0
        self.ack = 0
        self.rst = 0
        self.syn = 0
        self.fin = 0
        self.wnd = 65535
        self.check = 0
        self.flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + (self.ack << 4) + (self.urg << 5)
        self.urg_ptr = 0
        self.data = payload

        self.tcp_header = struct.pack('!HHLLBBHHH', self.src_port, self.dst_port, self.seq_no, self.ack_no, self.offset_reserved, self.flags, self.wnd, self.check, self.urg_ptr)
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.pseudo = 0
        self.bad_packet = 0




    def gen_hdr_to_send(self, flags, seq_num, ack_num):
        """Update the TCP header that gets passed to IP for sending"""
        self.check = 0
        self.offset = 5
        self.offset_reserved = (self.offset << 4) + 0
        self.urg_ptr = 0
        self.urg = 0
        self.psh = 0
        self.ack = 0
        self.rst = 0
        self.syn = 0
        self.fin = 0
        flag_list = flags.split(",")
        if "syn" in flag_list: self.syn = 1
        if "ack" in flag_list: self.ack = 1
        if "rst" in flag_list:
            self.rst = 1
            self.data = ""
        if "fin" in flag_list:
            self.fin = 1
            self.data = ""
        if "psh" in flag_list: self.psh = 1
        if "urg" in flag_list: self.urg = 1
        self.flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + (self.ack << 4) + (self.urg << 5)
        self.wnd = 65535
        self.seq_no = seq_num
        self.ack_no = ack_num
        self.tcp_header = struct.pack('!HHLLBBHHH', self.src_port, self.dst_port, self.seq_no, self.ack_no, self.offset_reserved, self.flags, self.wnd, self.check, self.urg_ptr)
        self.gen_pseudohdr()
        self.check = checksum(self.pseudo + self.tcp_header + self.data)

        #Assemble final header, finally! Checksum is NOT in network byte order.
        self.tcp_header = struct.pack('!HHLLBBH', self.src_port, self.dst_port, self.seq_no, self.ack_no, self.offset_reserved, self.flags, self.wnd) + struct.pack("H", self.check) + struct.pack("!H", self.urg_ptr)
        return self.tcp_header + self.data


    def gen_pseudohdr(self):
        """Update the TCP 'pseudoheader' to be used in checksum"""
        src_addr = socket.inet_aton(self.src_ip)
        dst_addr = socket.inet_aton(self.dst_ip)
        self.pseudo = struct.pack("!4s4sBBH", src_addr, dst_addr, 0, socket.IPPROTO_TCP, self.offset * 4 + len(self.data))

    def parse(self, packet):
        #Get TCP packet information from incoming packet
        self.src_port, self.dst_port, self.seq_no, self.ack_no, off, flags, self.wnd = struct.unpack("!HHLLBBH", packet[0:16])
        self.check = struct.unpack("H", packet[16:18])
        self.urg_ptr = struct.unpack("!H", packet[18:20])
        self.offset = off >> 4
        self.fin = flags & 0x01
        self.syn = (flags & 0x02) >> 1
        self.rst = (flags & 0x04) >> 2
        self.psh = (flags & 0x08) >> 3
        self.ack = (flags & 0x10) >> 4
        self.urg = (flags & 0x20) >> 5
        self.data = packet[self.offset * 4:]

        #Verify
        self.gen_pseudohdr()
        if checksum(self.pseudo + packet) != 0:
            self.bad_packet = 1


class TCPHandler:
    """Manages all TCP operations"""

    def __init__(self):
        self.sock = IPHandler()
        self.remote_ip = ""
        self.remote_port = -1
        self.local_ip = ""
        self.local_port = -1
        self.seq_num = 0
        self.ack_num = 0
        self.last_acked = 0
        self.received_fin = 0
        self.cwnd = 1
        self.adv_wnd = 1
        self.timed_out = 0 #Set to 1 when an RTO has occurred
        self.max_packs = min(self.cwnd, self.adv_wnd)
        self.webpage = ''

    def tcp_connect(self, dst, port=80):
        """This function establishes the initial TCP connection with the remote server
            and performs the three-way handshake."""
        #Update the IPHandler with our remote IP/Port
        self.remote_ip = socket.gethostbyname(dst)
        self.remote_port = port
        self.sock.update_addr_info(self.remote_ip, self.remote_port)
        self.local_port = self.sock.src_port
        self.local_ip = self.sock.src_addr

        #Three-Way Handshake
        self.seq_num = randint(0,65535)
        packet = TCPHeader(self.local_ip, self.remote_ip, self.local_port, self.remote_port)
        syn_packet = packet.gen_hdr_to_send("syn", self.seq_num, self.ack_num)
        self.pass_to_IP(syn_packet)

        #Receive syn/ack packet, willing to make several attempts
        connection_attempts = 0
        while connection_attempts < 4:
            synack = self.receive_from_IP()
            if self.timed_out == 1 or synack.syn != 1 or synack.ack != 1 or synack.ack_no != (self.seq_num + 1):
                # Handle failure
                connection_attempts = connection_attempts + 1
                self.cwnd = 1
                self.pass_to_IP(syn_packet)
            else:
                break
        if connection_attempts == 4:
            print("Failed to establish connection.")
            sys.exit(1)

        if synack.syn == 1 and synack.ack == 1 and synack.ack_no == (self.seq_num + 1):
            #We've received the correct syn/ack packet for the handshake
            self.seq_num = synack.ack_no
            self.ack_num = synack.seq_no + 1
            self.adv_wnd = synack.wnd
            if self.cwnd < 1000:
                self.cwnd = self.cwnd + 1

        #Respond with ack packet to complete handshake
        ack_packet = packet.gen_hdr_to_send("ack", self.seq_num, self.ack_num)
        self.pass_to_IP(ack_packet)


    def pass_to_IP(self, payload):
        """Wrapper that passes TCP payload data down to IP layer"""
        try:
            self.timed_out = 0
            self.sock.send(payload)
        except:
            print("Error: Failed to send at IP Layer")


    def receive_from_IP(self):
        """Interface for accepting a packet from the network layer and generating a TCP header/data from it."""
        begin = time.time()
        #Allow 1 minute to receive a packet
        while ((time.time() - begin) < 60):
            packet = TCPHeader()
            try:
                received = self.sock.recv()
            except:
                continue
            packet.src_ip = self.remote_ip
            packet.dst_ip = self.local_ip
            packet.parse(received)

            #Only accept packets destined for our application's local port, from the server we expect
            if packet.src_port == self.remote_port and packet.dst_port == self.local_port and packet.bad_packet == 0:
                self.timed_out = 0
                return packet

        #If TCP doesn't receive an ACK within 60 seconds, handle RTO
        self.timed_out = 1
        self.cwnd = 1


    def send(self, payload):
        """Ensures reliable, in-order delivery of all the data to be sent

        TODO: Divide payload into properly sized chunks. Flow control (handle advertised window). Congestion avoidance.
        """

        packet = TCPHeader(self.local_ip, self.remote_ip, self.local_port, self.remote_port, payload)
        to_send = packet.gen_hdr_to_send("ack", self.seq_num, self.ack_num)
        self.pass_to_IP(to_send)

        rcvd_packs = {}        #Dictionary of sequence numbers received and the data associated with them
        to_ack = []            #Stores list of sequence numbers received which we haven't acked yet

        #Wait for ACK of sent packet
        begin = time.time()
        while time.time() - begin < 180:
            ack_packet = self.receive_from_IP()
            if self.timed_out == 1:
                # Handle errors and try again
                self.cwnd = 1
                self.pass_to_IP(to_send)

            # Check if our HTTP GET packet has been acked
            if ack_packet.ack_no == self.seq_num + len(payload):
                self.seq_num = ack_packet.ack_no
                self.last_acked = ack_packet.seq_no
                self.ack_num = ack_packet.seq_no + len(ack_packet.data)
                if self.cwnd < 1000:
                    self.cwnd = self.cwnd + 1
                break
            else:
                #Haven't seen our HTTP packet acked yet, but we've received some legitimate packet out of order
                rcvd_packs[ack_packet.seq_no] = ack_packet.data  # Adds the sequence # and payload data to dictionary
                to_ack.append(ack_packet.seq_no)
                self.pass_to_IP(to_send) # send duplicate ACK


        #This part handles the packets of data we receive from the server, including dealing with duplicates
        #and packets arriving in the wrong order.
        my_packet = TCPHeader(self.local_ip, self.remote_ip, self.local_port, self.remote_port)
        while True:
            ack_packet = self.receive_from_IP()
            if ack_packet is not None:

                #Closes socket if server requests reset
                if ack_packet.rst == 1:
                    self.tcp_close(ack_packet)
                    sys.exit(1)

                if ack_packet.fin == 1:
                    self.received_fin = 1

                # Close the connection if the server requests it.
                # Only closes when all packets have been received [when len(to_ack) == 0]
                if self.received_fin == 1 and len(to_ack) == 0:
                    self.tcp_close(ack_packet)
                    self.reorder_data(rcvd_packs)
                    break


                #print("Last acked: " + str(self.last_acked) + " ACK: " + str(ack_packet.ack_no) + " Seq: " + str(ack_packet.seq_no))
                #print("To_ACK: " + str(to_ack))

                #Received packets that let me advance the sliding window by updating 'last_acked'
                #This could be because we are up to date, or from catching a retransmission from the server.
                if self.last_acked == ack_packet.seq_no:
                    if ack_packet.seq_no in to_ack:
                        #Catching up from retransmissions or out of order arrivals
                        print("Catching up.")
                        to_ack.remove(ack_packet.seq_no)
                    else:
                        #We are caught up and receiving packets in order
                        print("Caught up, receiving in order.")
                        del to_ack[:]
                    self.ack_num = ack_packet.seq_no + len(ack_packet.data)
                    my_ack = my_packet.gen_hdr_to_send("ack", self.seq_num, self.ack_num)
                    self.pass_to_IP(my_ack)
                    self.last_acked = self.ack_num
                #Received duplicate packet from server, drop it
                elif rcvd_packs.has_key(ack_packet.seq_no):
                    print("Drop duplicate packet.")
                    my_ack = my_packet.gen_hdr_to_send("ack", ack_packet.ack_no, ack_packet.seq_no + len(ack_packet.data))
                    self.ack_num = ack_packet.seq_no + len(ack_packet.data)
                    self.pass_to_IP(my_ack)
                    self.last_acked = self.ack_num
                    keys = rcvd_packs.keys()
                    print("Keys: " + str(keys))
                    for k in keys:
                        if k >= ack_packet.seq_no:
                            del rcvd_packs[k]
                #Fallen behind/packets out of order;
                else:
                    to_ack.append(ack_packet.seq_no + len(ack_packet.data))
                    if my_ack:
                        print("Packet out of order.")
                        self.pass_to_IP(my_ack)
                    else:
                        #Still haven't received the first packet of data, but have received a later one
                        self.pass_to_IP(to_send)

                rcvd_packs[ack_packet.seq_no] = ack_packet.data # Adds the sequence # and payload data to dictionary




    def reorder_data(self, packets):
        """After receiving all the packets from the server, we need to put the data received in order for
            easy access for HTTP"""
        packet_list = packets.items()
        packet_list.sort()
        data_list = [x[1] for x in packet_list]
        for d in data_list:
            self.webpage = self.webpage + d


    def tcp_close(self, packet=None):
        """Close the TCP connection. Default fin_packet is used when the client shuts down connection,
            otherwise the server's fin/ack packet is passed in."""
        client_close = 0

        my_packet = TCPHeader(self.local_ip, self.remote_ip, self.local_port, self.remote_port)
        #First, send FIN or FIN/ACK packet
        if packet is None:
            #Client requesting shutdown
            print("client shutdown.")
            client_close = 1
            self.ack_num = self.ack_num + 1
            fin_packet = my_packet.gen_hdr_to_send("fin", self.seq_num, self.ack_num)
        else:
            #Server requesting shutdown
            self.seq_num = packet.ack_no
            self.ack_num = self.ack_num + 1
            fin_packet = my_packet.gen_hdr_to_send("fin,ack", self.seq_num, self.ack_num)
        print("sending fin or fin/ack")
        self.pass_to_IP(fin_packet)

        #Next, wait for ACK
        while True:
            received = self.receive_from_IP()
            if self.timed_out == 1:
                self.cwnd = 1
                self.pass_to_IP(fin_packet)
            elif received.ack == 1 and received.ack_no == (self.seq_num + 1):
                print("final ack received.")
                self.ack_num = received.seq_no + 1
                self.seq_num = received.ack_no
                break

        if client_close == 1:
            #Client still needs to send a final ACK before closing
            last_ack = my_packet.gen_hdr_to_send("ack", self.seq_num, self.ack_num)
            self.pass_to_IP(last_ack)

        #self.sock.close()



########################################################################################################
################~~~~~~~~~~~~~~HTTP (application layer) API~~~~~~~~~~~~~~~~~~~~~~########################
########################################################################################################



class RawGet:
    """This class handles the HTTP protocol"""

    def __init__(self, url):
        self.sock = TCPHandler()
        self.url = url
        self.host = ""
        self.path = ""
        self.request = ""
        self.file_name = "index.html"
        self.local_ip = ""
        self.remote_ip = ""


    def start(self):
        """The entry point for the application."""
        self.host, self.path = self.handle_url()
        self.request = "GET " + self.path + " HTTP/1.1\r\n" + "Host: " + self.host + "\r\n\r\n"
        self.handle_connection()


    def handle_url(self):
        """Parse the URL from the command line into a hostname and path for the remote file we want to
            download with an HTTP GET"""
        if "http://" not in self.url:
            self.url = "http://" + self.url
        host = urlparse(self.url)
        hostname = host[1]
        path = host[2]
        file = path.split('/')[-1:]
        if not (path == "" or path[-1:] == "/"):
            self.file_name = file[0]
        return hostname, path

    def handle_connection(self):
        """This is a handler for our application's interface with the TCP protocol. It establishes the connection,
            sends our HTTP payload, and receives the response."""
        try:
            self.sock.tcp_connect(self.host, 80)
            received = self.pass_to_tcp()
        except:
            sys.exit("Error!")
        if received:
            html = self.parse_http(received)
            html_file = open(self.file_name, "wb+")
            html_file.write(html)


    def pass_to_tcp(self):
        """Wrapper for sending the HTTP GET request down to the TCP layer and retrieving the result"""
        try:
            print("Request: " + self.request)
            self.sock.send(self.request)
            print("Got back from send.")
        except socket.error:
            sys.exit("Error while sending.")
        return self.sock.webpage

    def parse_http(self, data):
        """Receives and unpacks the data returned from the server through the TCP layer, and then
            writes the data to our HTML file."""
        try:
            index = data.index("\r\n\r\n") + 4
        except:
            print("Didn't receive proper HTML data.")
            sys.exit(1)

        header = data[:index]
        body = data[index:]

        if "HTTP/1.1 200" not in header:
            print("HTML didn't return 200 code, error.")
            sys.exit(1)

        if "Transfer-Encoding: chunked" not in header:
            pos = header.find("Content-Length: ") + 17
            slen = ""
            while header.isnum(pos):
                slen = slen + header[pos]
            length = int(slen)
            return body[:length]
        else:
            #Chunked encoding, so return only the odd lines of the body until seeing "0"
            page = ""
            body_lines = body.split("\r\n")
            line_num = 0
            for l in body_lines:
                if l == "0":
                    return page
                if line_num % 2 == 1:
                    page = page + l




if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit("Usage: ./rawhttpget <URL>")
    parser = argparse.ArgumentParser(description='Project 4: Raw Sockets')
    parser.add_argument('url', help='URL to use for raw socket communication.')
    args = parser.parse_args()
    rawget = RawGet(args.url)
    rawget.start()
