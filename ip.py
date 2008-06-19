#! /usr/bin/python

import StringIO
import struct
import socket
import warnings
import heapq
import gapstr
import time
import UserDict

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

    """

    def __init__(self, seq=None):
        self.collection = {}
        self.length = 0
        self.seq = seq
        self.first = None

    def add(self, frame):
        if not self.first:
            self.first = frame
        if self.seq is None:
            self.seq = frame.seq
        assert frame.seq >= self.seq, (frame.seq, self.seq)
        self.collection[frame.seq] = frame
        end = frame.seq - self.seq + len(frame.payload)
        self.length = max(self.length, long(end))

    def __len__(self):
        return int(self.length)

    def __repr__(self):
        if self.first:
            return '<Chunk %s:%d -> %s:%d length %d (0x%x)>' % (self.first.src_addr,
                                                                self.first.sport,
                                                                self.first.dst_addr,
                                                                self.first.dport,
                                                                len(self),
                                                                len(self))
        else:
            return '<Chunk (no frames)>'

    def gapstr(self, drop='?'):
        """Return contents as a GapString"""

        ret = gapstr.GapString(drop=drop)
        while len(ret) < self.length:
            f = self.collection.get(self.seq + len(ret))
            if f:
                ret.append(f.payload)
            else:
                # This is where to fix big inefficiency for dropped packets.
                l = 1
                while ((len(ret) + l < self.length) and
                       (not (self.seq + len(ret) + l) in self.collection)):
                    l += 1
                ret.append(l)
        return ret

    def __str__(self):
        return str(self.gapstr())

    def extend(self, other):
        self.seq = min(self.seq or other.seq, other.seq)
        self.length = self.length + other.length
        if not self.first:
            self.first = other.first
        self.collection.update(other.collection)

    def __add__(self, next):
        new = self.__class__(self.seq)
        new.extend(self)
        new.extend(next)
        return new


FIN = 1
SYN = 2
RST = 4
PSH = 8
ACK = 16

class TCP_Resequence:
    """TCP session resequencer.

    >>> p = pcap.open('whatever.pcap')
    >>> s = TCP_Resequence()
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
                s = TCP_Resequence()
                sessions[f.hash] = s
            chunk = s.handle(f)
            if chunk:
                yield chunk

def demux(*pcs):
    """Demultiplex pcap objects based on time.

    This is iterable just like a pcap object, so you could for instance do:

    >>> resequence(demux(pcap1, pcap2, pcap3))

    """

    tops = []
    for pc in pcs:
        frame = pc.read()
        if frame:
            heapq.heappush(tops, (frame, pc))

    while tops:
        frame, pc = heapq.heappop(tops)
        yield frame
        frame = pc.read()
        if frame:
            heapq.heappush(tops, (frame, pc))



##
## Binary protocol stuff
##

class Packet(UserDict.DictMixin):
    """Base class for a packet from a binary protocol.

    This is a base class for making protocol reverse-engineering easier.

    """

    opcodes = {}

    def __init__(self, firstframe=None):
        self.firstframe = firstframe
        self.opcode = None
        self.opcode_desc = None
        self.parts = []
        self.params = {}
        self.payload = None

    def __repr__(self):
        r = '<%s packet opcode=%s' % (self.__class__.__name__, self.opcode)
        if self.opcode_desc:
            r += '(%s)' % self.opcode_desc
        keys = self.params.keys()
        keys.sort()
        for k in keys:
            r += ' %s=%s' % (k, self.params[k])
        r += '>'
        return r


    ## Dict methods
    def __setitem__(self, k, v):
        self.params[k] = v

    def __getitem__(self, k):
        return self.params[k]

    def __contains__(self, k):
        return k in self.params

    def __iter__(self):
        return self.params.__iter__()

    def has_key(self, k):
        return self.params.has_key(k)

    def keys(self):
        return self.params.keys()

    ##

    def assert_in(self, a, *b):
        if len(b) == 1:
            assert a == b[0], ('%r != %r' % (a, b[0]))
        else:
            assert a in b, ('%r not in %r' % (a, b))

    def show(self):
        print '%s %3s: %s' % (self.__class__.__name__,
                              self.opcode,
                              self.opcode_desc)
        if self.firstframe:
            print '    %s:%d -> %s:%d (%s)' % (self.firstframe.src_addr,
                                               self.firstframe.sport,
                                               self.firstframe.dst_addr,
                                               self.firstframe.dport,
                                               time.ctime(self.firstframe.time))

        if self.parts:
            dl = len(self.parts[-1])
            p = []
            for x in self.parts[:-1]:
                if x == dl:
                    p.append('%3d!' % x)
                else:
                    p.append('%3d' % x)
            print '           parts: (%s) +%d bytes' % (','.join(p), dl)

        keys = self.params.keys()
        keys.sort()
        for k in keys:
            print '    %12s: %s' % (k, self.params[k])

        if self.payload:
            try:
                self.payload.hexdump()
            except AttributeError:
                print '         payload: %r' % self.payload

    def parse(self, data):
        """Parse a chunk of data (possibly a GapString).

        Anything returned is not part of this packet and will be passed
        in to a subsequent packet.

        """

        self.parts = [data]
        return None

    def handle(self, data):
        """Handle data from a Session class."""

        data = self.parse(data)
        if self.opcode <> None:
            f = getattr(self, 'opcode_%s' % self.opcode)
            if not self.opcode_desc and f.__doc__:
                self.opcode_desc = f.__doc__.split('\n')[0]
            f()
        return data


class Session:
    """Base class for a binary protocol session."""

    # Override this, duh
    Packet = Packet

    def handle(self, chunk):
        """Handle a data burst.

        Pass in a chunk.

        """

        data = chunk.gapstr()
        while data:
            p = self.Packet(chunk.first)
            data = p.handle(data)
            self.process(p)

    def process(self, packet):
        """Process a packet.

        When you first start out, this probably does exactly what you
        want: print out packets as they come in.  As you progress you'll
        probably want to override it with something more sophisticated.
        That will of course vary wildly between protocols.

        """

        packet.show()

