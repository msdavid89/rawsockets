import argparse
import sys
from urlparse import urlparse
import socket
import struct
from random import randint
import time


def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    s = ~s & 0xffff
    return s


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

    def __init__(self, src_ip="", dst_ip="", payload=""):
        self.version = 4
        self.ihl = 5
        self.tos = 0
        self.length = 20
        self.id = 0
        self.flags = 0
        self.offset = 0
        self.ttl = 0
        self.proto = socket.IPPROTO_TCP
        self.chksum = 0
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.payload = payload
	    self.ip_ihl_ver = (version << 4) + ihl
	    self.ip_header = struct.pack('!BBHHHBBH4s4s' , self.ip_ihl_ver, self.tos, self.length, self.id, self.offset, self.ttl, self.proto, self.chksum, self.src_ip, self.dst_ip)

    def gen_hdr_to_send(self):

    def gen_pseudohdr(self):

    def parse_hdr(self):

    def verify_ip_hdr(self):




class IPHandler:
    """Handles all IP layer operations"""

    def __init__(self):
        try:
            self.sendsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.recvsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error:
            print("Failed to create socket. Womp womp.")
            sys.exit()


    def send(self, payload):

    def recv(self):

    def close(self):
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
        self.wnd = 4096
        self.check = 0
        self.flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + (self.ack << 4) + (self.urg << 5)
        self.urg_ptr = 0
        self.data = payload

        self.tcp_header = struct.pack('!HHLLBBHHH', self.src_port, self.dst_port, self.seq_no, self.ack_no, self.offset_reserved, self.flags, self.wnd, self.check, self.urg_ptr)
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.pseudo = self.gen_pseudohdr()
        self.bad_packet = 0


    def gen_hdr_to_send(self, flags, seq_num, ack_num):
        """Update the TCP header that gets passed to IP for sending"""
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
        #if "psh" in flag_list: self.psh = 1
        #if "urg" in flag_list: self.urg = 1
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
        self.data = packet[20:]

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
        self.cwnd = 1
        self.adv_wnd = 1
        self.timed_out = 0 #Set to 1 when an RTO has occurred
        self.checksum_failed = 0 #Set to 1 when the incoming packet is misformed

    def tcp_connect(self, dst, port=80):
        """This function establishes the initial TCP connection with the remote server
            and performs the three-way handshake."""

        #Update the IPHandler with our remote/local IP addresses
        self.remote_ip = socket.gethostbyname(dst)
        self.remote_port = port
        self.local_ip = self.sock.recvsock.getsockname()
        self.local_port = self.bind_to_open_port()
        #self.sock = IPHandler(self.local_ip, self.remote_ip)

        #Three-Way Handshake
        self.seq_num = randint(0,65535)
        packet = TCPHeader(self.local_ip, self.remote_ip, self.local_port, self.remote_port)
        syn_packet = packet.gen_hdr_to_send("syn", self.seq_num, self.ack_num)
        self.pass_to_IP(syn_packet)

        #Receive syn/ack packet, willing to make several attempts
        connection_attempts = 0
        while connection_attempts < 4:
            synack = self.receive_from_IP()
            if self.timed_out == 1:
                # Handle failure
                connection_attempts = connection_attempts + 1
                self.cwnd = 1
                self.pass_to_IP(syn_packet)
            else:
                break
        if connection_attempts == 4:
            print("Failed to establish connection.")
            exit(1)

        if synack.syn == 1 and synack.ack == 1 and synack.ack_no == (self.seq_num + 1):
            #We've received the correct syn/ack packet for the handshake
            self.seq_num = synack.ack_no
            self.ack_num = synack.seq_no + 1
            if self.cwnd < 1000:
                self.cwnd = self.cwnd + 1

        #Respond with ack packet to complete handshake
        ack_packet = packet.gen_hdr_to_send("ack", self.seq_num, self.ack_num)
        self.pass_to_IP(ack_packet)


    def bind_to_open_port(self):
        """TCP needs an open port from the OS to bind our 'rawhttpget' application to."""
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.bind(('',0))
        open_port = test_sock.getsockname()[1]
        test_sock.close()
        return open_port

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

        #If TCP doesn't receive an ACK within 1 second, handle RTO
        self.timed_out = 1
        self.cwnd = 1


    def send(self, payload):
        """Ensures reliable, in-order delivery of all the data to be sent

        TODO: Divide payload into properly sized chunks. Flow control (handle advertised window). Congestion avoidance.
        """

        rcvd_packs = [] #Packets that have been sent but not yet acked
        rcvd_msg = {}

        packet = TCPHeader(self.local_ip, self.remote_ip, self.local_port, self.remote_port, payload)
        to_send = packet.gen_hdr_to_send("ack", self.seq_num, self.ack_num)
        self.pass_to_IP(to_send)

        #Wait for ACK of sent packet
        #If the ACK# is equal to current seq_num, ACK that packet and store the data.
        #Else, send a duplicate ACK and store the data somewhere appropriate.
        #TCP must continue listening until it receives every data packet it expects. Might require removing the
        #Connection: keep-alive header from the HTTP GET message.
        while True:
            ack_packet = self.receive_from_IP()
            if self.timed_out == 1:
                # Handle errors and try again
                self.cwnd = 1
                self.pass_to_IP(to_send)

            #Close the connection if the server requests it. Currently closes if server requests reset
            if ack_packet.fin == 1 or ack_packet.rst == 1:
                self.tcp_close(ack_packet)

            # Check if the right packet has been acked
            if ack_packet.ack_no == self.seq_num + len(payload):
                self.seq_num = ack_packet.ack_no
                self.ack_num = ack_packet.seq_no + len(ack_packet.data)
                if self.cwnd < 1000:
                    self.cwnd = self.cwnd + 1
            else:
                self.cwnd = self.cwnd - 1 # ???
                self.pass_to_IP(to_send)





    def tcp_close(self, packet=None):
        """Close the TCP connection. Default fin_packet is used when the client shuts down connection,
            otherwise the server's fin/ack packet is passed in."""
        client_close = 0

        #First, send FIN or FIN/ACK packet
        if packet is None:
            #Client requesting shutdown
            client_close = 1
            packet = TCPHeader(self.local_ip, self.remote_ip, self.local_port, self.remote_port)
            fin_packet = packet.gen_hdr_to_send("fin", self.seq_num, self.ack_num)
        else:
            #Server requesting shutdown
            fin_packet = packet.gen_hdr_to_send("fin,ack", self.seq_num, self.ack_num)
        self.pass_to_IP(fin_packet)

        #Next, wait for ACK
        while True:
            received = self.receive_from_IP()
            if self.timed_out == 1:
                self.cwnd = 1
                self.pass_to_IP(fin_packet)
            elif received.ack == 1 and received.ack_no == (self.seq_num + 1):
                self.ack_num = received.seq_no + 1
                self.seq_num = received.ack_no
                break

        if client_close == 1:
            #Client still needs to send a final ACK before closing
            last_ack = packet.gen_hdr_to_send("ack", self.seq_num, self.ack_num)

        self.sock.close()



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
        self.html_file = -1
        self.local_ip = ""
        self.remote_ip = ""


    def start(self):
        """The entrypoint for the application."""
        self.host, self.path = self.handle_url()
        self.request = "GET " + path + " HTTP/1.1\r\n" + "Host: " + host + "\r\nConnection: keep-alive\r\n\r\n"
        self.html_file = open(self.file_name, "wb+")
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
            received = self.pass_to_tcp(self)
        except:
            sys.exit("Error!")
        if received:
            self.parse_http(received)
            self.html_file.write(received)
        finally:
            self.sock.tcp_close()


    def pass_to_tcp(self):
        """Wrapper for sending the HTTP GET request down to the TCP layer"""
        data = ""
        try:
            data = self.sock.send(self.request)
        except socket.error:
            sys.exit("Error while sending.")
        return data

    def parse_http(self, data):
        """Receives and unpacks the data returned from the server through the TCP layer, and then
            writes the data to our HTML file."""



if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit("Usage: ./rawhttpget <URL>")
    parser = argparse.ArgumentParser(description='Project 4: Raw Sockets')
    parser.add_argument('url', help='URL to use for raw socket communication.', required=True)
    args = parser.parse_args()
    rawget = RawGet(args.url)
    rawget.start()
