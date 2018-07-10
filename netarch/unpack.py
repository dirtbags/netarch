#! /usr/bin/python3

ENDIAN_LITTLE = 1
ENDIAN_BIG = 2
ENDIAN_MIDDLE = 3
ENDIAN_NETWORK = ENDIAN_BIG

class Unpacker:
    """Class that lets you peel values off
    
    >>> u = Unpacker(bytes((1, 0,2, 0,0,0,3, 0,0,0,0,0,0,0,4)))
    >>> u.uint8()
    1
    >>> u.uint16()
    2
    >>> u.uint32()
    3
    >>> u.uint64()
    4
    
    >>> u = Unpacker(bytes((1,0, 104,105)), ENDIAN_LITTLE)
    >>> u.uint16()
    1
    >>> u.buf
    b'hi'

    >>> u = Unpacker(bytes((1,0, 0,2)))
    >>> u.uint16(ENDIAN_LITTLE)
    1
    >>> u.uint(16, ENDIAN_BIG)
    2
    
    >>> u = Unpacker(bytes((0,1,2,3)), ENDIAN_MIDDLE)
    >>> '%08x' % u.uint32()
    '01000302'
    """
    
    def __init__(self, buf, endian=ENDIAN_NETWORK):
        self.endian = endian
        self.buf = buf

    def uint(self, size, endian=None):
        endian = endian or self.endian
        if size not in (8, 16, 32, 64):
            # XXX: I'm pretty sure this can be done, but I don't want to code it up right now.
            raise ValueError("Can't do weird sizes")
        noctets = size // 8
        if endian == ENDIAN_BIG:
            r = range(0, noctets)
        elif endian == ENDIAN_LITTLE:
            r = range(noctets-1, -1, -1)
        elif endian == ENDIAN_MIDDLE:
            r = (1, 0, 3, 2,   5, 4, 7, 6)[:noctets]
        else:
            raise ValueError("Unsupported byte order")
        pull, self.buf = self.buf[:noctets], self.buf[noctets:]
        acc = 0
        for i in r:
            acc = (acc << 8) | pull[i]
        return acc
        
    def uint8(self):
        return self.uint(8)
    def uint16(self, endian=None):
        return self.uint(16, endian)
    def uint32(self, endian=None):
        return self.uint(32, endian)
    def uint64(self, endian=None):
        return self.uint(64, endian)

if __name__ == "__main__":
    import doctest
    doctest.testmod()
