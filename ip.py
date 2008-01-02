#! /usr/bin/python

import StringIO
import struct
import socket
import warnings

def unpack(fmt, buf):
    """Unpack buf based on fmt, assuming the rest is a string."""

    size = struct.calcsize(fmt)
    vals = struct.unpack(fmt, buf[:size])
    return vals + (buf[size:],)

def unpack_nybbles(byte):
    return (byte >> 4, byte & 0x0F)

ICMP = 1
TCP  = 6
UDP  = 17

class Frame:
    """Turn an ethernet frame into relevant TCP parts"""

    def __init__(self, pkt):
        ((self.time, _, _), frame) = pkt

        # Ethernet
        (self.eth_dhost,
         self.eth_shost,
         self.eth_type,
         p) = unpack('!6s6sH', frame)
        if self.eth_type != 0x0800:
            raise ValueError('Not IP %04x' % self.eth_type)

        # IP
        (self.ihlvers,
         self.tos,
         self.tot_len,
         self.id,
         self.frag_off,
         self.ttl,
         self.protocol,
         self.check,
         self.saddr,
         self.daddr,
         p) = unpack("!BBHHHBBHii", p)

        if self.protocol == TCP:
            self.name = 'TCP'
            (self.sport,
             self.dport,
             self.seq,
             self.ack,
             x2off,
             self.flags,
             self.win,
             self.sum,
             self.urp,
             p) = unpack("!HHLLBBHHH", p)
            (self.off, th_x2) = unpack_nybbles(x2off)
            opt_length = self.off * 4
            self.options, p = p[:opt_length - 20], p[opt_length - 20:]
            self.payload = p[:self.tot_len - opt_length - 20]
        elif self.protocol == UDP:
            self.name = 'UDP'
            (self.sport,
             self.dport,
             self.ulen,
             self.sum,
             p) = unpack("!HHHH", p)
            self.payload = p[:self.ulen - 8]
        elif self.protocol == ICMP:
            self.name = 'ICMP'
            self.sport = self.dport = -1
            (self.type,
             self.code,
             self.cheksum,
             self.id,
             self.seq,
             p) = unpack('!BBHHH', p)
            self.payload = p[:self.tot_len - 8]
        else:
            raise ValueError('Unknown protocol')

        # Nice formatting
        self.src = (self.saddr, self.sport)
        self.dst = (self.daddr, self.dport)

        # This hash is the same for both sides of the transaction
        self.hash = (self.saddr ^ self.sport ^ self.daddr ^ self.dport)

    def get_src_addr(self):
        saddr = struct.pack('!i', self.saddr)
        self.src_addr = socket.inet_ntoa(saddr)
        return self.src_addr
    src_addr = property(get_src_addr)

    def get_dst_addr(self):
        daddr = struct.pack('!i', self.daddr)
        self.dst_addr = socket.inet_ntoa(daddr)
        return self.dst_addr
    dst_addr = property(get_dst_addr)

    def __repr__(self):
        return '<Frame %s %s:%d -> %s:%d length %d>' % (self.name,
                                                        self.src_addr, self.sport,
                                                        self.dst_addr, self.dport,
                                                        len(self.payload))


class Chunk:
    """Chunk of frames, possibly with gaps.

    Currently, gaps show up as a string of 0x33, ascii '3'.

    """

    def __init__(self, seq, drop='3'):
        # chr(0x33) == '3'.  If you see a bunch of 3s, in the ascii or
        # the hex view, suspect a drop.
        assert len(drop) == 1, "Don't yet support len(drop) > 1"
        self.drop = drop
        self.collection = {}
        self.length = 0
        self.seq = seq
        self.first = None

    def add(self, frame):
        assert frame.seq >= self.seq, (frame.seq, self.seq)
        if not self.first:
            self.first = frame
        self.collection[frame.seq] = frame
        end = frame.seq - self.seq + len(frame.payload)
        self.length = max(self.length, long(end))

    def __len__(self):
        return int(self.length)

    def __repr__(self):
        if self.first:
            return '<Chunk %s:%d -> %s:%d length %d>' % (self.first.src_addr,
                                                         self.first.sport,
                                                         self.first.dst_addr,
                                                         self.first.dport,
                                                         len(self))
        else:
            return '<Chunk (no frames)>'

    def __str__(self):
        s = ''
        while len(s) < self.length:
            f = self.collection.get(self.seq + len(s))
            if f:
                s += f.payload
            else:
                # This is where to fix it for len(drop) > 1.
                # This is also where to fix big inefficiency for dropped packets.
                s += self.drop
        return s

    def __add__(self, next):
        seq = min(self.seq, next.seq)
        new = Chunk(seq, self.drop)
        for frame in self.collection.itervalues():
            new.add(frame)
        for frame in next.collection.itervalues():
            new.add(frame)
        return new


FIN = 1
SYN = 2
RST = 4
PSH = 8
ACK = 16

class TCP_Session:
    """TCP session resequencer.

    >>> p = pcap.open('whatever.pcap')
    >>> s = TCP_Session()
    >>> while True:
    ...     pkt = p.read()
    ...     if not pkt:
    ...         break
    ...     f = Frame(pkt)
    ...     r = s.handle(f)
    ...     if r:
    ...         print ('chunk', r)

    This returns things in sequence.  So you get both sides of the
    conversation in the order that they happened.

    Doesn't (yet) handle fragments or dropped packets.  Does handle out
    of order packets.

    """

    def __init__(self):
        self.cli = None
        self.srv = None
        self.seq = [None, None]
        self.first = None
        self.pending = [{}, {}]
        self.frames = 0
        self.closed = 0

        self.handle = self.handle_handshake


    def handle(self, pkt):
        """Stub.

        This function will never be called, it is immediately overridden
        by __init__.  The current value of this function is the state.
        """

        pass

    def handle_handshake(self, pkt):
        self.frames += 1

        if not self.first:
            self.first = pkt

        if pkt.flags == SYN:
            self.cli, self.srv = pkt.src, pkt.dst
        elif pkt.flags == (SYN | ACK):
            assert (pkt.src == (self.srv or pkt.src))
            self.cli, self.srv = pkt.dst, pkt.src
            self.seq = [pkt.ack, pkt.seq + 1]
        elif pkt.flags == ACK:
            assert (pkt.src == (self.cli or pkt.src))
            self.cli, self.srv = pkt.src, pkt.dst
            self.seq = [pkt.seq, pkt.ack]
            self.handle = self.handle_packet
        else:
            # In the middle of a session, do the best we can
            self.cli, self.srv = pkt.src, pkt.dst
            self.seq = [pkt.seq, pkt.ack]
            self.handle = self.handle_packet
            self.handle(pkt)

    def handle_packet(self, pkt):
        ret = None
        self.frames += 1

        # Which way is this going?  0 == from client
        idx = int(pkt.src == self.srv)
        xdi = 1 - idx

        # Does this ACK after the last output sequence number?
        seq = self.seq[xdi]
        if pkt.ack > seq:
            ret = Chunk(seq)
            pending = self.pending[xdi]
            for key in pending.keys():
                if key >= pkt.ack:
                    continue
                if key >= seq:
                    ret.add(pending[key])
                else:
                    warnings.warn('Dropping %r from mid-stream session' % pending[key])
                del pending[key]
            self.seq[xdi] = pkt.ack

        # If it has a payload, stick it into pending
        if pkt.payload:
            self.pending[idx][pkt.seq] = pkt

        # Is it a FIN or RST?
        if pkt.flags & (FIN | RST):
            self.closed += 1
            if self.closed == 2:
                # Warn about any unhandled packets
                if self.pending[0] or self.pending[1]:
                    warnings.warn('Dropping unhandled frames after shutdown' % pkt)
                self.handle = self.handle_drop

        return ret

    def handle_drop(self, pkt):
        """Warn about any unhandled packets"""

        if pkt.payload:
            warnings.warn('Spurious frame after shutdown: %r %d' % (pkt, pkt.flags))


class HTTP_side:
    """One side of an HTTP transaction."""

    def __init__(self):
        self.buf = ''
        self.first = ''
        self.in_headers = True
        self.headers = {}
        self.pending_data = 0
        self.data = ''
        self.complete = False

    def __repr__(self):
        return '<HTTP_side %r>' % self.first

    def process(self, chunk):
        """Returns any unprocessed part of the chunk, parts which go to
        the next utterance."""

        chunk = chunk + self.buf
        while self.in_headers and chunk:
            try:
                line, chunk = chunk.split('\n', 1)
            except ValueError:
                self.buf = chunk
                return ''
            self.process_header_line(line)
        self.buf = ''
        if self.pending_data:
            d = chunk[:self.pending_data]
            chunk = chunk[self.pending_data:]
            self.data += d
            self.pending_data -= len(d) # May set to 0
        if not self.pending_data:
            self.complete = True
        return chunk

    def process_header_line(self, line):
        if not line.strip():
            self.in_headers = False
            return
        try:
            k,v = line.split(':', 1)
        except ValueError:
            if self.first:
                raise ValueError(('Not a header', line))
            else:
                self.first += line
                return
        self.headers[k] = v
        if k.lower() == 'content-length':
            self.pending_data = int(v)


def resequence(pc):
    """Re-sequence from a pcap stream.

    >>> p = pcap.open('whatever.pcap')
    >>> for chunk in resequence(p):
    ...    print `chunk`

    """

    sessions = {}
    for pkt in pc:
        f = Frame(pkt)
        if f.protocol == TCP:
            # compute TCP session hash
            s = sessions.get(f.hash)
            if not s:
                s = TCP_Session()
                sessions[f.hash] = s
            chunk = s.handle(f)
            if chunk:
                yield chunk


def process_http(filename):
    import pcap

    pc = pcap.open(filename)
    sess = TCP_Session(pc)

    packets = []
    current = [HTTP_side(), HTTP_side()]
    for idx, chunk in sess:
        c = current[idx]
        while chunk:
            chunk = c.process(chunk)
            if c.complete:
                packets.append((idx, c))

                c = HTTP_side()
                current[idx] = c

    return packets





