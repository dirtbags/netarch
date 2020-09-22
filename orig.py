#! /usr/bin/python3

import binascii
import sys
import struct
from . import ip



def cstring(buf):
    "Return buf if buf were a C-style (NULL-terminate) string"

    i = buf.index('\0')
    return buf[:i]


def assert_equal(a, b):
    assert a == b, ('%r != %r' % (a, b))


def assert_in(a, *b):
    assert a in b, ('%r not in %r' % (a, b))


##
## Binary and other base conversions
##

class BitVector:
    def __init__(self, i=0, length=None):
        try:
            self._val = 0
            for c in i:
                self._val <<= 8
                self._val += ord(c)
            if length is not None:
                self._len = length
            else:
                self._len = len(i) * 8
        except TypeError:
            self._val = i
            if length is not None:
                self._len = length
            else:
                self._len = 0
                while i > 0:
                    i >>= 1
                    self._len += 1

    def __len__(self):
        return self._len

    def __getitem__(self, idx):
        if idx > self._len:
            raise IndexError()
        idx = self._len - idx
        return int((self._val >> idx) & 1)

    def __getslice__(self, a, b):
        if b > self._len:
            b = self._len
        i = self._val >> (self._len - b)
        l = b - a
        mask = (1 << l) - 1
        return BitVector(i & mask, length=l)

    def __iter__(self):
        """Iterate from LSB to MSB"""

        v = self._val
        for _ in range(self._len):
            yield int(v & 1)
            v >>= 1

    def __str__(self):
        r = ''
        v = self._val
        i = self._len
        while i > 8:
            o = ((v >> (i - 8)) & 0xFF)
            r += chr(o)
            i -= 8
        if i > 0:
            o = v & ((1 << i) - 1)
            r += chr(o)
        return r

    def __int__(self):
        return self._val

    def __repr__(self):
        l = list(self)
        l.reverse()
        return '<BitVector ' + ''.join(str(x) for x in l) + '>'

    def __add__(self, i):
        if isinstance(i, BitVector):
            l = len(self) + len(i)
            v = (int(self) << len(i)) + int(i)
            return BitVector(v, l)
        else:
            raise ValueError("Can't extend with this type yet")

    def bitstr(self):
        bits = [str(x) for x in self]
        bits.reverse()
        return ''.join(bits)


def bin(i, bits=None):
    """Return the binary representation of i"""

    return BitVector(i, bits).bitstr()


def unhex(s):
    """Decode a string as hex, stripping whitespace first"""

    return binascii.unhexlify(s.replace(' ', ''))


def pp(value, bits=16):
    hexfmt = '%%0%dx' % (bits / 4)
    return '%6d  0x%s  %s' % (value, (hexfmt % value), bin(value, bits))

##
## Codecs
##
import codecs
import string

b64alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

def from_b64(s, alphabet, codec='base64'):
    tr = alphabet.maketrans(b64alpha)
    t = s.translate(tr)
    return t.decode(codec)

class Esab64Codec(codecs.Codec):
    """Little-endian version of base64."""

    ## This could be made nicer by better conforming to the codecs.Codec
    ## spec.  For instance, raising the appropriate exceptions.
    ##
    ## Using BitVector makes the code very readable, but it is probably
    ## slow.

    b64_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    def decode(self, input, errors='strict'):
        r = []
        for i in range(0, len(input), 4):
            v = BitVector()
            for c in input[i:i+4]:
                if c in ('=', ' ', '\n'):
                    break
                v += BitVector(self.b64_chars.index(c), 6)

            # Normal base64 would start at the beginning
            b = (v[10:12] + v[ 0: 6] +
                 v[14:18] + v[ 6:10] +
                 v[18:24] + v[12:14])

            r.append(str(b))
        return ''.join(r), len(input)

    def encode(self, input, errors='strict'):
        raise NotImplementedError()


class Esab64StreamWriter(Esab64Codec, codecs.StreamWriter):
    pass

class Esab64StreamReader(Esab64Codec, codecs.StreamReader):
    pass

def _registry(encoding):
    if encoding == 'esab64':
        c = Esab64Codec()
        return (c.encode, c.decode,
                Esab64StreamReader, Esab64StreamWriter)

codecs.register(_registry)

def main(session):
    s = None
    reseq = ip.Dispatch(*sys.argv[1:])
    for _, d in reseq:
        srv, first, chunk = d
        if not s:
            s = session(first)
        s.handle(srv, first, chunk, reseq.last)

Session = ip.Session
Packet = ip.Packet
