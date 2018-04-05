# -*- coding: utf-8 -*-

"""
Trong phần này ta sẽ tìm hiểu về mã hóa và giải mã cụ thể ở đây dùng Asymmetric(Mã hóa bất đối xứng ) ta có 1 private, và 1 public key.

private giải mã, public mã hóa

Các giải thuật mã hóa: RSA, RSA : 2480



---
Tìm hiều cấu trúc của certificate x509 format

=========================================
Certificate:
   data:
      Version: (0x2)  -->  xác đinh version của ngôn ngữ mô tả x509
      Serial Number: bb:7c:54:9b:75:7b:28:9d   --> Định nghĩa số seri duy nhất cho mỗi chứng chỉ được cấp với Certification Authority
      Signature Algorithm: SHA-256 With RSA Encryption  --> quy định thuật toán mã hóa và hash của chủ ký (hash(SHA256))RSA hash sha256 sau đó mã hóa RSA
      Issuer: CN = Let's Encrypt Authority X 3O = Let's Encrypt C = US  --> DN (Distinguished Name) của cơ quan đã ký kết và do đó đã cấp chứng chỉ
      Validity:  --> xác nhận khoảng thời gian chứng chỉ hợp lệ
        notBefore: December 4, 2017 at 3:02:03 PM --> ngày ký
        notAfter: March 4, 2018 at 3:02:03 PM --> ngày hết hạn
      
      Subject: CN = api.nanghuynh.com  --> Một DN xác định đối tượng được liên kết với chứng chỉ này.
      SubjectPublicKeyInfo
         SubjectPublicKeyAlgorithm: PKCS #1 RSA Encryption  --> xác định thuật toán  mã hóa, giải mã cho public key
         SubjectPublicKey: Modulus (2048 bits):
                            9d 49 3d 19 72 4f 64 34 89 1f f5 43 32 f9 e3 ff 
                            1a ea 66 ec 9f 1e 7a 28 b5 35 20 ea c6 7a ad 9c 
                            dd 65 60 43 40 f7 a6 2c 7c 22 0f d2 99 18 73 2f 
                            63 3f 66 32 59 2f 95 e9 fc 50 1a d6 8e 1e 83 aa 
                            12 80 db 03 1a 21 ce 98 ad 37 b3 16 e2 6f 58 b1 
                            91 91 d5 ad 1f e1 c3 68 cf 4a be 67 2e 1f 78 38 
                            d7 9f 79 cd 71 1b c6 b9 b2 71 3b 84 dc 33 98 1a 
                            13 ee a6 77 1c 85 a9 73 07 2c 31 e9 ca ef 4c 5b 
                            0a e7 97 cf 55 a6 41 41 6a de 8b 17 f7 35 2d 25 
                            3d f9 73 20 39 e1 0c 35 87 26 a5 43 89 7e 94 ab 
                            54 b7 15 2c 45 2e 09 5c a1 16 f1 49 ef d3 56 eb 
                            a7 fa bc 93 df 00 32 9b b4 43 fa 40 8e e3 03 b9 
                            06 b9 68 6f 4c 2a 59 e3 7f ac db f7 13 f1 33 71 
                            44 b2 45 5c 60 37 db b1 75 c5 e9 1c 45 2f 60 ef 
                            cc 71 b3 26 91 bc b1 90 58 e5 a1 c9 51 ad ee a0 
                            65 1c a9 0c 23 fd b3 de 26 fd 95 b7 da 2d 94 61 
                            
                            Exponent (24 bits):
                            65537
                            
                            -->  public key của subject
      IssuerUniqueIdentifier:  -->  Optional. định nghĩa giá trị guy nhất cho tổ chức phát hành
      SubjectUniqueIdentifier: --> Optional. định nghĩa giá trị duy nhất cho chứng thực
      Extensions:
          Certificate Key Usage: Critical
                                 Signing
                                 Key Encipherment
                                 --> mục đích sử dụng key
          
          Extended Key Usage: Not Critical
                               TLS Web Server Authentication (1.3.6.1.5.5.7.3.1)
                               TLS Web Client Authentication (1.3.6.1.5.5.7.3.2)              
                                --> tinh chỉnh các mục đích mà khoá công khai có thể được sử dụng 
                                    và phải tương thích với thuộc tính Key Usage
          
          Certificate Basic Constraints: Critical
                                Is a Certificate Authority
                                Maximum number of intermediate CAs: 0
                                --> xác định chứng  chỉ là CA hoặc là root certificate (TRUE) or not (FALSE)
          
          Certificate Subject Key Identifier: Not Critical
                                                Size: 20 Bytes / 160 Bits
                                                f8 2a f8 b2 f4 4b 71 70 2f f0 bf 15 52 59 6f 7e 
                                                c7 05 e8 49
                                              --> là mã băm của subjectPublicKeyInfo chính nó với hàm băm SHA-1
                                              
          Certificate Authority Key Identifier: Not Critical
                                                Size: 20 Bytes / 160 Bits
                                                c4 a7 b1 a4 7b 2c 71 fa db e1 4b 90 75 ff c4 15 
                                                60 85 89 10
                                              --> là mã băm của subjectPublicKeyInfo của Authority cấp với 160 bit SHA-1
          
          Authority Info Access: Not Critical
                                    OCSP: URI: http://ocsp.int-x3.letsencrypt.org
                                    CA Issuers: URI: http://cert.int-x3.letsencrypt.org/
                                    --> Được sử dụng để chứa thông tin về các dịch vụ CA bao gồm bất kỳ  Online Certificate Status Protocol (OCSP)
          
          Certificate Subject Alt Name: Not Critical
                                        DNS Name: api.nanghuynh.com 
                                        --> 
          
          Certificate Policies: --> Có thể được sử dụng để xác định các chính sách cụ thể của tổ chức phát hành CA
      
      Certificate Signature Algorithm: PKCS #1 SHA-256 With RSA Encryption
                                       --> THuật toán được xác định để ký chứng chỉ, Hash SHA-256 sau đó encode RSA
      
      Certificate Signature value: Size: 256 Bytes / 2048 Bits
                                    dd 33 d7 11 f3 63 58 38 dd 18 15 fb 09 55 be 76 
                                    56 b9 70 48 a5 69 47 27 7b c2 24 08 92 f1 5a 1f 
                                    4a 12 29 37 24 74 51 1c 62 68 b8 cd 95 70 67 e5 
                                    f7 a4 bc 4e 28 51 cd 9b e8 ae 87 9d ea d8 ba 5a 
                                    a1 01 9a dc f0 dd 6a 1d 6a d8 3e 57 23 9e a6 1e 
                                    04 62 9a ff d7 05 ca b7 1f 3f c0 0a 48 bc 94 b0 
                                    b6 65 62 e0 c1 54 e5 a3 2a ad 20 c4 e9 e6 bb dc 
                                    c8 f6 b5 c3 32 a3 98 cc 77 a8 e6 79 65 07 2b cb 
                                    28 fe 3a 16 52 81 ce 52 0c 2e 5f 83 e8 d5 06 33 
                                    fb 77 6c ce 40 ea 32 9e 1f 92 5c 41 c1 74 6c 5b 
                                    5d 0a 5f 33 cc 4d 9f ac 38 f0 2f 7b 2c 62 9d d9 
                                    a3 91 6f 25 1b 2f 90 b1 19 46 3d f6 7e 1b a6 7a 
                                    87 b9 a3 7a 6d 18 fa 25 a5 91 87 15 e0 f2 16 2f 
                                    58 b0 06 2f 2c 68 26 c6 4b 98 cd da 9f 0c f9 7f 
                                    90 ed 43 4a 12 44 4e 6f 73 7a 28 ea a4 aa 6e 7b 
                                    4c 7d 87 dd e0 c9 02 44 a7 87 af c3 34 5b b4 42
                                   --> chứ ký số
============================================================================================

Vậy rút ra cấu tạo của CERT có các phần quan trọng
cert được mã hóa với dạng base64, và được mô tảng bằng ngôn ngữ ASN1

Giải sử ta có bộ key của CA : KA1(public), KA2 (private)
|-------------------------|--------------------------|-------------------------------------------------------------|
| subject public key      | info........             |HASH(field1 + field2) x KA2 => tạo ra  Certificate Signature |
|-------------------------|--------------------------|-------------------------------------------------------------|

Vậy khi ta đăng ký chữ ký số thì [subject public key]  key public mình gởi cho CA
                                 [INFO] thông tin mình điền vào để CA xác nhận
==> Sau đó CA sẽ cấp cho mình 1 chữ ký số được hash ([subject public key] + [INFO]) sau đó được mã hóa bới private key của CA

** vậy khi brower nhận được crt từ web server gởi về làm sao để xác nhận được là key xin và key dỏn
  Khi nhận được crt thì browser sẽ tách ra và check [INFO] thử đúng không, ví dụ ngày giờ, domain..
  nếu [public key] và [info đều đúng] thì nó sẽ tiến hành hash với thuật toán trong crt ra được H1,
  nó sẽ lấy public key của CA được trust trong list đúng với trong info ra decode [field 3] ra được H2 so sánh H1 và H2 nếu giống là key xịn

link: https://security.stackexchange.com/questions/56389/ssl-certificate-framework-101-how-does-the-browser-actually-verify-the-validity
link: http://www.zytrax.com/tech/survival/ssl.html
   để tham khỏa thêm


--> khi ta gen key bằng openSSL thì sẽ ra file  mto.zing.vn.key --> file này gồm private + public key
--> dùng  file này đi đăng ký mua ssl dẽ ra file pem --> file này sẽ chứa public key của file trên   
                                                      
"""

## Demo decode certication, lấy public key trong file key, và pem
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate


def get_public_key_from_file_key(file_key):

    """
    # lấy public key trong file mto.zing.vn.key
    :param file_key: 
    :return: 
    return public key string
    
    """
    with open(file_key, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
        key_file.read(),
        password = None,
        backend = default_backend())

        public_key = private_key.public_key()
        result = public_key.public_bytes(
                                      encoding = serialization.Encoding.PEM,
                                      format = serialization.PublicFormat.SubjectPublicKeyInfo
                                    )
        key_file.close()
    return result

def get_public_key_from_pem(file_key):

    """
    # lay public key in file   mto.zing.vn.pem
    :param file_key: 
    :return: 
    return public key string
    """

    with open(file_key, "rb") as key_file:
        p_key = load_pem_x509_certificate(
            key_file.read(),
            backend=default_backend())

        public_key = p_key.public_key()

        result =  public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_file.close()

    return  result
