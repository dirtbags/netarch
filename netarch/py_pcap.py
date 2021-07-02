#! /usr/bin/python3

import struct

_MAGIC = 0xA1B2C3D4

builtin_open = open

class PcapFile:
    def __init__(self, stream, mode='r', snaplen=65535, linktype=1):
        if 'b' not in mode:
            mode += 'b'
        try:
            self.stream = builtin_open(stream, mode)
        except TypeError:
            self.stream = stream
        try:
            # Try reading
            hdr = self.stream.read(24)
        except IOError:
            hdr = None

        if 'r' in mode:
            # We're in read mode
            self._endian = None
            for endian in '<>':
                (self.magic,) = struct.unpack(endian + 'I', hdr[:4])
                if self.magic == _MAGIC:
                    self._endian = endian
                    break
            if not self._endian:
                raise IOError('Not a pcap file')
            (self.magic, version_major, version_minor,
             self.thiszone, self.sigfigs,
             self.snaplen, self.linktype) = struct.unpack(self._endian + 'IHHIIII', hdr)
            if (version_major, version_minor) != (2, 4):
                raise IOError('Cannot handle file version %d.%d' % (version_major,
                                                                    version_minor))
        else:
            # We're in write mode
            self._endian = '='
            self.magic = _MAGIC
            version_major = 2
            version_minor = 4
            self.thiszone = 0
            self.sigfigs = 0
            self.snaplen = snaplen
            self.linktype = linktype
            hdr = struct.pack(self._endian + 'IHHIIII',
                              self.magic, version_major, version_minor,
                              self.thiszone, self.sigfigs,
                              self.snaplen, self.linktype)
            self.stream.write(hdr)
        self.version = (version_major, version_minor)

    def read(self):
        hdr = self.stream.read(16)
        if not hdr:
            return
        (tv_sec, tv_usec, caplen, length) = struct.unpack(self._endian + 'IIII', hdr)
        datum = self.stream.read(caplen)
        return ((tv_sec, tv_usec, length), datum)

    def write(self, packet):
        (header, datum) = packet
        (tv_sec, tv_usec, length) = header
        hdr = struct.pack(self._endian + 'IIII', tv_sec, tv_usec, length, len(datum))
        self.stream.write(hdr)
        self.stream.write(datum)

    def __iter__(self):
        while True:
            r = self.read()
            if not r:
                break
            yield r

open = PcapFile
pcap = PcapFile
open_offline = PcapFile


if __name__ == '__main__':
    import io
    
    f = io.BytesIO()
    p = PcapFile(f, 'w')
    p.write(((0, 0, 3), b'foo')) # Add a packet
    p.write(((0, 0, 3), b'bar'))
    del p
    
    f.seek(0)
    p = PcapFile(f)
    assert ((p.version, p.thiszone, p.sigfigs, p.snaplen, p.linktype) ==
            ((2, 4), 0, 0, 65535, 1))
    assert ([i for i in p] == [((0, 0, 3), b'foo'), ((0, 0, 3), b'bar')])
