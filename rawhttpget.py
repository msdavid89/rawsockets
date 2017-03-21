import argparse
import sys
from urlparse import urlparse
import socket
import struct
import random


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




class IPHandler:

    def __init__(self):
        try:
            self.sendsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self.recvsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except socket.error:
            print("Failed to create socket. Womp womp.")
            sys.exit()



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

    def __init__(self, src_port=0, dst_port=80, payload=""):
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_no = 0
        self.ack_no = 0
        self.offset = 5
        self.urg = 0
        self.psh = 0
        self.ack = 0
        self.rst = 0
        self.syn = 0
        self.fin = 0
        self.wnd = 4096
        self.check = 0
        self.urgent = 0
        self.data = payload



class TCPHandler:

    def __init__(self):
        self.sock = IPHandler()
        self.remote_ip = ""
        self.remote_port = ""
        self.local_ip = ""
        self.local_port = ""

    def tcp_connect(self, dst, port=80):
        self.remote_ip = self.sock.gethostbyname(dst)
        self.remote_port = port
        self.local_ip = self.sock.getsockname()
        self.local_port = self.bind_to_open_port()
        self.sock = IPHandler(self.local_ip, self.remote_ip)


    def bind_to_open_port(self):
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.bind(('',0))
        open_port = test_sock.getsockname()[1]
        test_sock.close()
        return open_port


    def send(self):

    def tcp_close(self):


    def tcp_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
            s = s + w
        s = (s >> 16) + (s & 0xffff)
        s = s + (s >> 16)
        s = ~s & 0xffff
        return s




class RawGet:

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
        self.host, self.path = self.handle_url()
        self.request = "GET " + path + " HTTP/1.1\r\n" + "Host: " + host + "\r\nConnection: keep-alive\r\n\r\n"
        self.html_file = open(self.file_name, "wb+")
        self.handle_connection()


    def handle_url(self):
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
        try:
            self.sock.send(self.request)
        except socket.error:
            sys.exit("Error while sending.")


    def recv_from_tcp(self):



if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit("Usage: ./rawhttpget <URL>")
    parser = argparse.ArgumentParser(description='Project 4: Raw Sockets')
    parser.add_argument('url', help='URL to use for raw socket communication.', required=True)
    args = parser.parse_args()
    rawget = RawGet(args.url)
    rawget.start()