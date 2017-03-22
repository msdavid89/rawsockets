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


    def gen_hdr_to_send(self, flags, seq_num, ack_num):
        """Update the TCP header that gets passed to IP for sending"""
        if flags == "syn": self.syn = 1
        if flags == "ack": self.ack = 1
        if flags == "rst": self.rst = 1
        if flags == "fin,ack":
            self.fin = 1
            self.ack = 1
        self.flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + (self.ack << 4) + (self.urg << 5)
        self.seq_no = seq_num
        self.ack_no = ack_num
        self.tcp_header = struct.pack('!HHLLBBHHH', self.src_port, self.dst_port, self.seq_no, self.ack_no, self.offset_reserved, self.flags, self.wnd, self.check, self.urg_ptr)
        self.gen_pseudohdr()
        self.check = checksum(self.pseudo + self.tcp_header + self.data)

        #Assemble final header, finally!
        self.tcp_header = struct.pack('!HHLLBBHHH', self.src_port, self.dst_port, self.seq_no, self.ack_no, self.offset_reserved, self.flags, self.wnd, self.check, self.urg_ptr)
        return self.tcp_header + self.data


    def gen_pseudohdr(self):
        """Update the TCP 'pseudoheader' to be used in checksum"""
        src_addr = socket.inet_aton(self.src_ip)
        dst_addr = socket.inet_aton(self.dst_ip)
        self.pseudo = struct.pack("!4s4sBBH", src_addr, dst_addr, 0, socket.IPPROTO_TCP, self.offset * 4 + len(self.data))

    def parse(self, packet):


    def verify_tcp_hdr(self):




class TCPHandler:
    """Manages all TCP operations"""

    def __init__(self):
        self.sock = IPHandler()
        self.remote_ip = ""
        self.remote_port = ""
        self.local_ip = ""
        self.local_port = ""
        self.seq_num = 0
        self.ack_num = 0
        self.total_acked = 0
        self.cwnd = 1

    def tcp_connect(self, dst, port=80):
        """This function establishes the initial TCP connection with the remote server
            and performs the three-way handshake."""

        #Update the IPHandler with our remote/local IP addresses
        self.remote_ip = self.sock.gethostbyname(dst)
        self.remote_port = port
        self.local_ip = self.sock.getsockname()
        self.local_port = self.bind_to_open_port()
        self.sock = IPHandler(self.local_ip, self.remote_ip)

        #Three-Way Handshake
        self.seq_num = randint(0,65535)
        packet = TCPHeader(self.local_ip, self.remote_ip, self.local_port, self.remote_port)
        syn_packet = packet.gen_hdr_to_send("syn", self.seq_num, self.ack_num)
        self.pass_to_IP(syn_packet)



    def bind_to_open_port(self):
        """TCP needs an open port from the OS to bind our 'rawhttpget' application to."""
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.bind(('',0))
        open_port = test_sock.getsockname()[1]
        test_sock.close()
        return open_port


    def send(self, payload):
        """Ensures reliable, in-order delivery of all the data to be sent"""


    def pass_to_IP(self, payload):
        """Wrapper that passes TCP payload data down to IP layer"""
        try:
            self.sock.send(payload)
        except:
            print("Error: Failed to send at IP Layer")

    def receive(self):

    def receive_from_IP(self):
        """Interface for accepting a packet from the network layer and generating a TCP header/data from it."""
        begin = time.time()

        #Allow 1 second to receive a packet
        while ((time.time() - begin) < 1):
            packet = TCPHeader()
            try:
                received = self.sock.recv()
            except:
                continue
            packet.src_ip = self.dst_ip
            packet.dst_ip = self.src_ip
            packet.parse(received)

            #Only accept packets destined for our application's local port, from the server we expect
            if packet.src_port == self.remote_port and packet.dst_port == self.local_port:
                return packet

        #If TCP doesn't receive an ACK within 1 second, handle RTO
        self.rto_timeout()

    def rto_timeout(self):

    def tcp_close(self):


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
            self.pass_to_tcp(self)
            received = self.recv_from_tcp()
        except:
            sys.exit("Error!")
        if received:
            self.html_file.write(received)
        finally:
            self.sock.tcp_close()


    def pass_to_tcp(self):
        """Wrapper for sending the HTTP GET request down to the TCP layer"""
        try:
            self.sock.send(self.request)
        except socket.error:
            sys.exit("Error while sending.")


    def recv_from_tcp(self):
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
