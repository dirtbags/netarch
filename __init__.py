#! /usr/bin/python
# -*- coding: utf-8 -*-

import sys
import struct

printable = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()[]{}`~/=-\\?+|\',."<> '

def unpack(fmt, buf):
    """Unpack buf based on fmt, return the rest as a string."""

    size = struct.calcsize(fmt)
    vals = struct.unpack(fmt, buf[:size])
    return vals + (buf[size:],)


def to_printable(c):
    if c in printable:
        return c
    elif c == '\0':
        return '␀'
    elif c == '\r':
        return '␍'
    elif c == '\n':
        return '␤'
    else:
        return '·'


def hexdump(buf, f=sys.stdout):
    "Print a hex dump of buf"

    offset = 0

    while buf:
        s = buf[:16]
        o = [('%02x' % ord(c)) for c in s] + (['  '] * (16 - len(s)))
        p = [to_printable(c) for c in s]

        f.write('%08x  ' % offset)

        f.write(' '.join(o[:8]))
        f.write('  ')
        f.write(' '.join(o[8:]))

        f.write('  ║')

        f.write(''.join(p))

        f.write('║\n')

        buf = buf[16:]
        offset += 16


def cstring(buf):
    "Return buf if buf were a C-style (NULL-terminate) string"

    i = buf.index('\0')
    return buf[:i]


def md5sum(txt):
    return md5.new(txt).hexdigest()


def assert_equal(a, b):
    assert a == b, ('%r != %r' % (a, b))


def assert_in(a, *b):
    assert a in b, ('%r not in %r' % (a, b))


##
## Binary stuff
##

def bin(i):
    """Return the binary representation of i"""

    r = []
    while i > 0:
        r.append(i % 2)
        i = i >> 1
    r.reverse()
    s = ''.join(str(x) for x in r)
    return s

class bitvector:
    def __init__(self, i=0, length=None):
        if type(i) == type(''):
            self._val = 0
            for c in i:
                self._val <<= 8
                self._val += ord(c)
            if length is not None:
                self._len = length
            else:
                self._len = len(i) * 8
        else:
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
        return bitvector(i & mask, length=l)

    def __iter__(self):
        v = self._val
        for i in xrange(self._len):
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
        return '<bitvector ' + ''.join(str(x) for x in l) + '>'

    def __add__(self, i):
        if isinstance(i, bitvector):
            l = len(self) + len(i)
            v = (int(self) << len(i)) + int(i)
            return bitvector(v, l)
        else:
            raise ValueError("Can't extend with this type yet")


b64_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
def esab64_decode(s):
    """Little-endian version of base64"""

    r = []
    for i in range(0, len(s), 4):
        v = bitvector()
        for c in s[i:i+4]:
            if c == '=':
                break
            v += bitvector(b64_chars.index(c), 6)

        # Normal base64 would start at the beginning
        b = (v[10:12] + v[ 0: 6] +
             v[14:18] + v[ 6:10] +
             v[18:24] + v[12:14])

        r.append(str(b))
    return ''.join(r)
