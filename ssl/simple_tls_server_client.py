# -*- coding: utf-8 -*-
"""
Trong phần này ta sẽ tìm hiều SSL protocol đây là giao thức khùng điên khủng khiếp
SSL protocol có  tổng cộng 4 protocol con

|---------------------|---------------------|------------------------|
| Change Cipher Spec  | SSL alert protocol  | SSL handshake protocol |
|---------------------|---------------------|------------------------|
|                       SSL Record protocol                          |
|--------------------------------------------------------------------|

là giao thức layer 4 giữa layer 4 và layer 5

- SSL handshake protocol: là protocol quan trọng nhất là giao thức thương lượng và trao đổi khóa key 
- SSL Record protocol: là giao thức xử lý việc phân đoạn, nén, xác thực và mã hóa dữ liệu
- SSL alert protocol: được sử dụng để chuyển các cảnh báo thông qua SSL Record Protocol.
- Change Cipher Spec: được sử dụng để thay đổi giữa một thông số mật mã này và một thông số mật mã khác


Giao thức SSL handshake protocol

[CLIENT]                                                                 [SERVER]

1/           client_hello             ---------------------------->

                                    
                                                                     | server_hello
                                                                     | Certificate*
2/                                     <---------------------------- | [ServerKeyExchange*] optional
                                                                     | [CertificateRequest*] optional
                                                                     | ServerHelloDone

          optional [ Certificate*] |
                ClientKeyExchange  |
3/ optional [ CertificateVerify* ] |    ------------------------->
                  ChangeCipherSpec |
                          Finished | 
                                              
                                              
4/                                       <----------------------------  | [ChangeCipherSpec]
                                                                        | Finished
                                                                        
                                                      
                                                      
5/                Application Data |     <---------------------------->     Application Data


là handshake
Giời tới phần khai phá packet handshake protocol khổ quá mà

1/[client_hello]

        |-----------------------[TLS Record layer]------------------------|
        | content type: handshake(22) | version: TLS 1.0   | length: 512  |
        |-----------------------[handshake protocol]----------------------|
        | handshake type: Client hello | length: 508 | version: TLS 1.2   |
        |-----------------------------------------------------------------|
        |            Random :  GMT unix time, Random byte                 |
        |-----------------------------------------------------------------|
        | Session ID length: 32        | Session ID: dffs9dsfd..          |
        |-----------------------------------------------------------------|
        | Cipher suites length: 28     |  Cipher suites: TLS_EC, TLS_RSA..|
        |-----------------------------------------------------------------|
        | compression methods length:1 | Compression methods              |
        |-----------------------------------------------------------------|
        |  Extendsion: ....                                               |
        |-----------------------------------------------------------------|      

        Khi client yêu cầu kết nối https thì nó sẽ gởi gói tin như vầy có 2 trường quan trong là:
          +version: TLS --> chọn version TLS mà client hỗ trợ
          +Cipher suites: --> Danh sách mật mã các thuật toàn client hỗ trợ

2/[server_hello]          
  Đối với các gói sau thì khi ta bắt gói thì wireshake sẽ gom các gói mà ta tách ở trên thánh 1 gói cho dể coi
  
        |-----------------------[TLS Record layer]------------------------|
        | content type: handshake(22) | version: TLS 1.0   | length: 512  |
        |-----------------------[handshake protocol]----------------------|
        | handshake type: Server hello | length: 77 | version: TLS 1.2    |
        |-----------------------------------------------------------------|
        |            Random :  GMT unix time, Random byte                 |
        |-----------------------------------------------------------------|
        | Session ID length: 32        | Session ID: dffs9dsfd..          |
        |                              | giống session ID của client-hello|
        |-----------------------------------------------------------------|
        | Cipher suites length: 28     |  Cipher suites: TLS_EC.          |
        |                              | chọn 1 Cipher mà client gởi      | 
        |                              | trong list                       | 
        |-----------------------------------------------------------------|
        | compression methods length:1 | Compression methods              |
        |-----------------------------------------------------------------|
        |  Extendsion: ....                                               |
        |-----------------------------------------------------------------|
                         
  ở bước này server sẽ lựa chọn version, thuật toán mà client cung cấp và gởi lại cho client
   server sẽ gởi certifacation của mình cho client
   server gởi gói Hellodone
               
3/ client
   client sẽ gởi ClientKeyExchange là key mã hóa đối xứng do client gen ra ,đồng thời key này sẽ được mã hóa bằng pbulic key trong 
   certificate mà server gởi tới (trước đó sẽ có cơ chế verify certificate bằng CA key) (xem file ssl_tls_simple.py để biết thêm)
   client gởi gói cho server
        |--------------[Change Cipher Spec protocol]----------------------|
        | content type: change cipher| version: TLS 1.2   | length: 1     |
        |-----------------------------------------------------------------|
        | change cipher spec message:  info..                             |
        |-----------------------------------------------------------------|
    client gởi finish

4/ server gởi gói Change Cipher Spec, và Finish


5/ data qua lại sẽ được mã hóa bằng key đối xứng        

"""

## Demo về ssl

# certifi is a pkg whose sole purpose is distributing Mozilla's CA bundle
import certifi

ca_certs = certifi.where()

import time
import threading
import socket
import ssl

port = 2049
host = "localhost"

ssl_keyfile = "mto.zing.vn.key"
ssl_certfile = "mto.zing.vn.pem"

try:
    ipAddr = socket.gethostbyname(host)
    print "IP = " + ipAddr
except socket.gaierror:
    print "Host name could not be resolved"


class TCPBase(threading.Thread):
    def __init__(self):
        self.soc = self.buildSocket()
        super(TCPBase, self).__init__()

    def buildSocket(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print 'Socket created'
        except socket.error, msg:
            print 'Failed to create socket Error code: ' + str(msg[0]) + ', Error message: ' + msg[1]
        return s

    def printErr(self, usrMsg, msg):
        print usrMsg
        print usrMsg


class ClientThread(TCPBase):
    def __init__(self):
        super(ClientThread, self).__init__()

    def run(self):
        '''
        Client thread
        '''
        err = 0
        try:
            self.ssl_sock = ssl.wrap_socket(self.soc,
                                            ciphers="HIGH:-aNULL:-eNULL:-PSK:RC4-SHA:RC4-MD5",
                                            ssl_version=ssl.PROTOCOL_TLSv1,
                                            ca_certs=ca_certs,
                                            cert_reqs=ssl.CERT_REQUIRED)
            print "Wrapped client socket for SSL"
        except socket.error:
            print "SSL socket wrapping failed"
            err = 1

        if not err:
            try:
                self.ssl_sock.connect((host, port))
                print "client socket connected\n"
            except socket.error, msg:
                self.printErr("Socket connection error in client: ", msg);
                err = 1

        if not err:
            print "send message"
            self.ssl_sock.sendall("Twas brillig and the slithy toves")

        self.soc.close()
        self.ssl_sock.close()
        print "exit client"


class ServerThread(TCPBase):
    def __init__(self):
        super(ServerThread, self).__init__()

    def run(self):
        '''
        Server thread
        '''
        err = 0
        msg = None
        try:
            self.soc.bind((host, port))
            print "Bind worked\n"
        except socket.error, msg:
            print "Bind failed in server: " + str(msg[0]) + " Message " + msg[1]
            err = 1
        if not err:
            try:
                self.soc.listen(10)
            except socket.error, msg:
                print "Listen failed: " + str(msg[0]) + " Message " + msg[1]
                err = 1
        if not err:
            self.conn, self.addr = self.soc.accept()
            print "Accepted client connection to address " + str(self.addr) + "\n"
            try:
                self.connstream = ssl.wrap_socket(self.conn,
                                                  server_side=True,
                                                  certfile=ssl_certfile,
                                                  keyfile=ssl_keyfile,
                                                  ssl_version=ssl.PROTOCOL_TLSv1
                                                  )
                print "SSL wrap succeeded for sever"
            except socket.error, msg:
                if (msg != None):
                    print "SSL wrap failed for server: " + str(msg[0]) + " Message " + msg[1]
                err = 1

            while True:
                data = self.connstream.recv(1024)
                if data:
                    print "server: " + data
                else:
                    break
        self.soc.close()
        self.connstream.close()
        print "exit server"


def main():
    print "Hello world"
    client = ClientThread()
    server = ServerThread()
    server.start()
    client.start()
    while client.isAlive() and server.isAlive():
        '''
        Do nothing
        '''
        time.sleep(0.100)
    print "Main: that's all folks"


main()

