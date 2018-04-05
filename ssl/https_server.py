# -*- coding: utf-8 -*-

# demo HTTP server kết hợp tls, có thể dúng wireshake bắt gói
import BaseHTTPServer, SimpleHTTPServer
import ssl

httpd = BaseHTTPServer.HTTPServer(('0.0.0.0', 443),
                                  SimpleHTTPServer.SimpleHTTPRequestHandler)

httpd.socket = ssl.wrap_socket(httpd.socket,
                               keyfile="mto.zing.vn.key",
                               certfile='mto.zing.vn.pem', server_side=True)

httpd.serve_forever()