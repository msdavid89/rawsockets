class Headers():

        def __init__(self, data=''):
                self.srcip = socket.inet_aton(IP)
                self.destip = socket.inet_aton(hostip)
                self.src_port = random.randint(30489, 65535)
                self.des_port = 80
                self.seq_no = random.randint(1, 567967207)
                self.ack_no = 0
                self.offset = 5
                self.cwr = 0
                self.ece = 0
                self.urg = 0
                self.ack = 0
                self.push = 0
                self.reset = 0
                self.syn = 0
                self.fin = 0
                self.window = 65000
                self.checksum = 0
                self.urgp = 0
                self.data = 0

                if len(data) % 2 == 1:
                        data += "0"

                self.payload = data
    

        def ip_header(self):
                ver = 4
                ipihl = 5
                iptos = 0
                ipt_len = 0
                ipid = 55555
                flg = 0
                offset = 0
                ttl = 255
                protocol = socket.IPPROTO_TCP
                chksum = 0
                self.srcip = socket.inet_aton(IP)
                self.destip = socket.inet_aton(hostip)
                ver_ipihl = (ver << 4) + ihl
                flg_offset = (flg << 13) + offset
                ip_head = struct.pack("!BBHHHBBH4s4s", ver_ipihl, iptos, ipid, flg_offset, ttl, protocol, chksum, self.srcip, self.destip)

                return ip_head

        def tcp_header(self):
                self.src_port
                self.des_port
                self.seq_no
                self.ack_no
                self.offset
                offset_res = (self.offset << 4) + 0
                self.cwr
                self.ece
                self.urg
                self.ack
                self.push
                self.reset
                self.syn
                self.fin
                flags = self.fin + (self.syn << 1) + (self.reset << 2) + (self.push << 3) + (self.ack << 4) + (self.urg << 5) + (self.ece << 6) + (self.cwr << 7)
                self.window
                self.checksum
                self.urgp
                tcp_header = struct.pack('!HHLLBBHHH', self.src_port, self.des_port, self.seq_no, self.ack_no, offset_res, flags, self.window, self.checksum, self.urgp)

"""

 def tcp_checksum(self, msg):

                s = 0
                for i in range(0, len(msg), 2):
                        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
                        s = s + w
                s = (s>>16) + (s & 0xffff);
                s = s + (s >> 16);
                s = ~s & 0xffff
                return s

"""

