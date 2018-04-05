## APPLICATION PROTOCOL

Trong phần này mình sẽ implement các protocol application phổ biến . mọi người có thể xem script của mình để biết cách đọc protocol và implement nó vào code , ở đây mình dùng python.


 ==> Khi đã hiểu , và implement được protocol các bạn có thể tự viết phần Server, Client chạy trên protocol đó. Xa hơn các bạn có thể tự viết script khai thác các lỗi của các service chạy protocol .


 ### DHCP

 Mình sẽ implement dhcp protocol. và viết 1 dhcp server đơn giản bằng python.
 Detail và protocol có thể đọc thẳng trong script


 ### DNS

 Detail protocol 

 ```
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
 ```

Có DNS server đơn gian



### SSL

```
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
```

Tìm hiểu về các certificate trong giao thức SSL

imple ment tls server, https server đơn giản

mục đích hiểu được cơ chế chạy của ssl

