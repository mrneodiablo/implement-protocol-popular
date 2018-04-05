# -*- coding: utf-8 -*-

"""
        Header structure
        Byte/     0       |       1       |       2       |       3       |
           /              |               |               |               |
          |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
          +---------------+---------------+---------------+---------------+
         0| Magic         | Opcode        | Key length                    |
          +---------------+---------------+---------------+---------------+
         4| Extras length | Data type     | vbucket id                    |
          +---------------+---------------+---------------+---------------+
         8| Total body length                                             |
          +---------------+---------------+---------------+---------------+
        12| Opaque                                                        |
          +---------------+---------------+---------------+---------------+
        16| CAS                                                           |
          |                                                               |
          +---------------+---------------+---------------+---------------+
          Total 24 bytes
          

+ Magic: 1 byte
      - request: '0x80'
      - respone: '0x81'
"""