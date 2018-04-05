# -*- coding: utf-8 -*-
import re, hashlib, binascii


class ASN1Element(object):
    TYPE_UNIVERSAL = 0x00
    TYPE_BIT_STRING = 0x03
    TYPE_OCTET_STRING = 0x04
    TYPE_OBJECT_IDENTIFIER = 0x06

    def __init__(self, data=None):
        self.tag = None
        self.length = None
        self.value = None
        self.hdr_len = None
        self.offset = None  # start offset
        self.value_in_context = None

        self.bitstring_unused_bits = None  # BITSTRING SPECIFIC (extra byte)
        if data:
            self.consume(data)

    def __repr__(self):
        val = "n/A" if self.get_tag_pc() else self.value[:20]
        val_ctx = "n/A"
        if self.tag == self.TYPE_OBJECT_IDENTIFIER:
            val_ctx = self.oid_decode(self.value)
        elif self.tag == self.TYPE_BIT_STRING:
            val_ctx = "unsused_bits: %d" % ord(self.bitstring_unused_bits)
        return "<ASN1 @%d tag=0x%x len=%d hdr_len=%d value=%s context=%s>" % (self.offset, self.tag, self.length, self.hdr_len, repr(val), val_ctx)
        # return str({'@':self.offset,'tag':"0x%x"%(self.tag),'hdr_len':self.hdr_len,'len':self.length,'value':self.value[:5]+"..."})

    def get_tag_class(self):
        return self.tag & 0b11000000

    def get_tag_pc(self):
        return self.tag & 0b00100000  # indicates sub_structure

    def get_tag_type(self):
        return self.tag & 0b00011111

    def get_tag_try_anyway(self):
        # may contain sub-asn1 structures
        if self.tag in (self.TYPE_BIT_STRING, self.TYPE_OCTET_STRING, self.TYPE_UNIVERSAL):
            # encapsulating types
            return self.tag  # inspect this for content
        return False

    def consume(self, data):
        seq = (b for b in data)

        try:
            self.hdr_len = 0
            tag = seq.next()
        except StopIteration:
            return {}

        if ord(tag) & 0x1f == 0x1f:
            tag += seq.next()
            while ord(tag[-1]) & 0x80 == 0x80:
                tag += seq.next()

        self.hdr_len += len(tag)

        real_length = 0
        length = ord(seq.next())
        self.hdr_len += 1

        if length == 0x80:
            # indefinite length.. search for 0x00 0x00
            self.hdr_len += 1
        elif length & 0x80 == 0x80:
            lendata = "".join([seq.next() for i in xrange(length & 0x7f)])
            length = int(binascii.b2a_hex(lendata), 16)
            real_length = length
            self.hdr_len += len(lendata)
        else:
            # short form
            real_length = length

        if ord(tag) == self.TYPE_BIT_STRING:
            # consume bitstring unused bits
            print "consume extra 'unused bits' byte"
            self.bitstring_unused_bits = seq.next()
            self.hdr_len += 1
            real_length -= 1  # reduce payload length since unused_bits is part of header

        if length == 0x80:
            value = ""  ## search for 0x00 0x00 == EOC
            while not value[-2:] == "\x00\x00":
                value += seq.next()
                real_length += 1
        else:
            value = "".join([seq.next() for i in xrange(real_length)])

        self.tag = ord(tag)
        self.value = value
        self.length = length
        self.real_length = real_length
        return self

    def __len__(self):
        return self.length + self.hdr_len

    def oid_decode(self, value):
        # http://msdn.microsoft.com/en-us/library/bb540809%28v=vs.85%29.aspx
        '''
        The first two nodes of the OID are encoded onto a single byte. The first node is multiplied by the decimal 40 and the result is added to the value of the second node.
        Node values less than or equal to 127 are encoded on one byte.
        Node values greater than or equal to 128 are encoded on multiple bytes. Bit 7 of the leftmost byte is set to one. Bits 0 through 6 of each byte contains the encoded value.
        // STILL NOT WORKING CORRECTLY ..
        '''
        rv = ""
        prev_byte = None
        for i, b in enumerate(value):
            b = ord(b)
            if i == 0:
                rv += "%d.%d" % (b / 40, b % 40)
            elif b >= 0x80 or prev_byte != None:
                # multibyte
                if prev_byte != None:
                    # got 2nd byte
                    val = prev_byte & 0b01111111
                    val |= ((b & 0b11111) << 7)
                    rv += ".%d" % (val)
                    prev_byte = None

                else:
                    # this is first byte
                    prev_byte = b
            else:
                rv += ".%d" % b
        return rv


class ASN1Parse(object):
    def __init__(self, data):
        self.data = data
        self.offset = 0
        self.length = len(self.data)

        self.objstream = []

    def _pushad(self):
        self.__backup = (self.data, self.offset, self.length, self.objstream[::])

    def _popad(self):
        self.data, self.offset, self.length, self.objstream = self.__backup
        self._clr()

    def _clr(self):
        self.__backup = None

    def parse(self):
        return self._parse(self.data)

    def _parse(self, data):
        objstream = []
        raw_data = data
        while len(raw_data) > 2 and self.offset < self.length:
            # sequential loop  (ASN1Elem+ASN1Elem)
            e = ASN1Element()
            e.consume(raw_data)
            e.offset = self.offset

            objstream.append(e)
            self.offset += e.hdr_len  # add header len
            print "*  offset: %5d/%-5d  elem:%-70s  tc=%2d pc=%2d type=%2d  elems:%s" % (e.offset, self.length, e, e.get_tag_class(), e.get_tag_pc(), e.get_tag_type(), None)
            if e.get_tag_pc():
                # Dive into ASN1.value
                # there's another sub-asn1 struct
                sub_elems = self._parse(e.value)
                objstream.append(sub_elems)
                # inline offset adjustment
            elif e.get_tag_try_anyway():
                # test if this will work out.. otherwise just store the data
                # save current state
                print "PUSHAD", self.offset, self.offset + e.real_length, self.length
                self._pushad()
                try:
                    sub_elems = self._parse(e.value)
                    objstream.append(sub_elems)
                    self._clr()
                except (StopIteration, OverflowError) as ex:
                    self._popad()
                    print "@%d - well this is not an asn1 strcuture.." % self.offset
                    self.offset += e.real_length
                    # restore current state
            else:
                self.offset += e.real_length  # add data length  // full element length added
            raw_data = self.data[self.offset:]
        return objstream


class Certificate(object):
    REX_PEM = re.compile("\-+BEGIN [\d\w\s\.]+\-+(.*?)\-+END [\d\w\s\.]+\-+", re.MULTILINE | re.DOTALL)

    def __init__(self, file):
        self.load(file)

    def load(self, file):
        with open(file, 'r') as f:
            data = f.read()


        pem = self.REX_PEM.search(data)
        if not pem:
            raise Exception("not in pem format")

        pem = pem.group(1)
        pem = pem.replace("\n", "")
        self.data = pem.decode("base64")

        print hashlib.sha256(self.data).hexdigest()

    def decode(self):
        return ASN1Parse(self.data).parse()

    def to_binary(self):
        return self.data

    def to_pem(self, data=None):
        data = data or self.data
        print hashlib.sha256(data).hexdigest()
        p_type = "CERTIFICATE"
        return '-' * 5 + "BEGIN " + p_type + '-' * 5 + '\n' + data.encode("base64") + '\n' + '-' * 5 + "END " + p_type + '-' * 5


if __name__ == '__main__':
    '''-----BEGIN CERTIFICATE-----
MIIEezCCA2OgAwIBAgIIWh9XGLs8XxUwDQYJKoZIhvcNAQEFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTMxMjExMTIxMjMzWhcNMTQwNDEwMDAwMDAw
WjBlMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEUMBIGA1UEAwwLKi5n
b29nbGUuYXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDBv0qVB+FW
ci5FaHqPPbFlKLUicjF1aW5rPVFTlKa5n4vP6bqUa+/8/fWqo2Zsq9d714N6ndG0
7F5ilGI9eZjZTWMWtDPEvRbHGs2ADETNG9I5LkGw63JafvlkZKvykNUI0YlDGrYZ
OPOECqR6wh63yhbcVUjHiB9tDYG+I6tuYfn4lYLrj8kaUtxK5EOSQqE3HT3ljOm2
cyjVYtv0i66u83c2ACHuZ5du/BXyY/EZEFlZxTkQxDYhGroO1BA8aNQ8/pZ6DjF2
ywIh8Dx9+blHOeNHY32CrpJE81TVa23n5krUD8hUezQ9exWcI/ZbJYgV124ftZeN
q0f1866Rha6BAgMBAAGjggFJMIIBRTAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYB
BQUHAwIwIQYDVR0RBBowGIILKi5nb29nbGUuYXSCCWdvb2dsZS5hdDBoBggrBgEF
BQcBAQRcMFowKwYIKwYBBQUHMAKGH2h0dHA6Ly9wa2kuZ29vZ2xlLmNvbS9HSUFH
Mi5jcnQwKwYIKwYBBQUHMAGGH2h0dHA6Ly9jbGllbnRzMS5nb29nbGUuY29tL29j
c3AwHQYDVR0OBBYEFIMWsVdJifC2GE+LsI8GP+LoQ6BgMAwGA1UdEwEB/wQCMAAw
HwYDVR0jBBgwFoAUSt0GFhu89mi1dvWBtrtiGrpagS8wFwYDVR0gBBAwDjAMBgor
BgEEAdZ5AgUBMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9wa2kuZ29vZ2xlLmNv
bS9HSUFHMi5jcmwwDQYJKoZIhvcNAQEFBQADggEBAErqQ/QF6bYanmHPF8pEbRYS
qtplaYgjsR9SRKd8ZzzMVGvXwlvbwWE2sk0rpbo8xeaBQWgnANtkqhsaKAAK9cNg
mFonol0mSoZbEmFDdumdqN2YYXjaa1GiTvkL9COUJRXu5WdJdISqXo781SGKzoGT
ZkfDgvyooVRi5p+Ji5MxNzjvGOIkGrI9x1hn5ngRE6z0KlH5IGaIrWoudc3jkPFt
3vFZm5HcGodxwaMbT9rTUB0mufbTuq9vqdZ/dwXC7JhrI0XcHEYGl1LAALBda01V
O6nGQ3XC2e062n9uI1bK9+TfAdrP1a06ShhFyZHtRVARS+cgOvfRvWy/kaa4Cu8=
-----END CERTIFICATE-----
    example google.lpem.cer
    '''

    c = Certificate("google.lpem.cer")
    # print c.to_pem()
    # print c.to_binary()
    import pprint

    pprint.pprint(c.decode())
