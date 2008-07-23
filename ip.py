#! /usr/bin/python

## IP resequencing + protocol reversing skeleton
## 2008 Massive Blowout

import StringIO
import struct
import socket
import warnings
import heapq
import gapstr
import time
import pcap
import os
import cgi
import urllib
import UserDict
from __init__ import *

def unpack_nybbles(byte):
    return (byte >> 4, byte & 0x0F)


IP = 0x0800
ARP = 0x0806

ICMP = 1
TCP  = 6
UDP  = 17

def str_of_eth(d):
    return ':'.join([('%02x' % ord(x)) for x in d])

class Frame:
    """Turn an ethernet frame into relevant parts"""

    def __init__(self, pkt):
        ((self.time, self.time_usec, _), frame) = pkt

        # Ethernet
        (self.eth_dhost,
         self.eth_shost,
         self.eth_type,
         p) = unpack('!6s6sH', frame)
        if self.eth_type == ARP:
            # ARP
            self.name, self.protocol = ('ARP', ARP)
            (self.ar_hrd,
             self.ar_pro,
             self.ar_hln,
             self.ar_pln,
             self.ar_op,
             self.ar_sha,
             self.ar_sip,
             self.ar_tha,
             self.ar_tip,
             p) = unpack('!HHBBH6si6si', p)
            self.saddr = self.ar_sip
            self.daddr = self.ar_tip
            self.__repr__ = self.__arp_repr__
        elif self.eth_type == IP:
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
                self.name = 'TCP/IP'
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
                self.name = 'UDP/IP'
                (self.sport,
                 self.dport,
                 self.ulen,
                 self.sum,
                 p) = unpack("!HHHH", p)
                self.payload = p[:self.ulen - 8]
            elif self.protocol == ICMP:
                self.name = 'ICMP/IP'
                self.sport = self.dport = None
                (self.type,
                 self.code,
                 self.cheksum,
                 self.id,
                 self.seq,
                 p) = unpack('!BBHHH', p)
                self.payload = p[:self.tot_len - 8]
            else:
                self.name = 'IP Protocol %d' % self.protocol
                self.sport = self.dport = None
                self.payload = p

            # Nice formatting
            self.src = (self.saddr, self.sport)
            self.dst = (self.daddr, self.dport)

            # This hash is the same for both sides of the transaction
            self.hash = (self.saddr ^ (self.sport or 0)
                         ^ self.daddr ^ (self.dport or 0))
        else:
            self.name = 'Ethernet type %d' % self.eth_type
            self.protocol = None


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
        return '<Frame %s %s:%r -> %s:%r length %d>' % (self.name,
                                                        self.src_addr, self.sport,
                                                        self.dst_addr, self.dport,
                                                        len(self.payload))

    def __arp_repr__(self):
        return '<Frame %s %s(%s) -> %s(%s)>' % (self.name,
                                                str_of_eth(self.ar_sha),
                                                self.src_addr,
                                                str_of_eth(self.ar_tha),
                                                self.dst_addr)


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
        self.midstream = False
        self.hash = 0

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
            self.hash = pkt.hash

        if pkt.flags == SYN:
            self.cli, self.srv = pkt.src, pkt.dst
        elif pkt.flags == (SYN | ACK):
            #assert (pkt.src == (self.srv or pkt.src))
            self.cli, self.srv = pkt.dst, pkt.src
            self.lastack = [pkt.seq + 1, pkt.ack]
            self.handle_packet(pkt)
        elif pkt.flags == ACK:
            #assert (pkt.src == (self.cli or pkt.src))
            self.cli, self.srv = pkt.src, pkt.dst
            self.lastack = [pkt.ack, pkt.seq]
            self.handle = self.handle_packet
            self.handle(pkt)
        else:
            # In the middle of a session, do the best we can
            warnings.warn('Starting mid-stream')
            self.midstream = True
            self.cli, self.srv = pkt.src, pkt.dst
            self.lastack = [pkt.ack, pkt.seq]
            self.handle = self.handle_packet
            self.handle(pkt)

    def handle_packet(self, pkt):
        ret = None
        self.frames += 1

        # Which way is this going?  0 == from client
        idx = int(pkt.src == self.srv)
        xdi = 1 - idx

        # Does this ACK after the last output sequence number?
        seq = self.lastack[idx]
        if pkt.ack > seq:
            pending = self.pending[xdi]

            # Get a sorted list of sequence numbers
            keys = pending.keys()
            keys.sort()

            # Build up return value
            gs = gapstr.GapString()
            if keys:
                f = pending[keys[0]]
                ret = (xdi, f, gs)
            else:
                ret = (xdi, None, gs)

            # Fill in gs with our frames
            for key in keys:
                if key >= pkt.ack:
                    break
                if key < seq:
                    warnings.warn('Dropping %r from mid-stream session' % pending[key])
                elif key > seq:
                    gs.append(key - seq)
                    seq = key
                frame = pending[key]
                gs.append(frame.payload)
                seq += len(frame.payload)
                del pending[key]
            if seq != pkt.ack:
                gs.append(pkt.ack - seq)
            self.lastack[idx] = pkt.ack

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


class Dispatch:
    def __init__(self, *filenames):
        self.pcs = {}

        self.sessions = {}
        self.tops = []

        self.last = None

        for fn in filenames:
            self.open(fn)

    def open(self, filename, literal=False):
        if not literal:
            parts = filename.split(':::')
            fn = parts[0]
            fd = file(fn)
            pc = pcap.open(fd)
            if len(parts) > 1:
                pos = int(parts[1])
                fd.seek(pos)
            self._read(pc, fn, fd)
        else:
            fd = file(filename)
            pc = pcap.open(fd)
            self._read(pc, filename, fd)

    def _read(self, pc, filename, fd):
        pos = fd.tell()
        pkt = pc.read()
        if pkt:
            heapq.heappush(self.tops, (pkt, pc, filename, fd, pos))

    def __iter__(self):
        while self.tops:
            pkt, pc, filename, fd, pos = heapq.heappop(self.tops)
            if not self.last:
                self.last = (filename, pos)
            frame = Frame(pkt)
            if frame.protocol == TCP:
                # compute TCP session hash
                tcp_sess = self.sessions.get(frame.hash)
                if not tcp_sess:
                    tcp_sess = TCP_Resequence()
                    self.sessions[frame.hash] = tcp_sess
                ret = tcp_sess.handle(frame)
                if ret:
                    yield frame.hash, ret
                    self.last = None
            self._read(pc, filename, fd)


##
## Binary protocol stuff
##

class NeedMoreData(Exception):
    pass

class Packet(UserDict.DictMixin):
    """Base class for a packet from a binary protocol.

    This is a base class for making protocol reverse-engineering easier.

    """

    opcodes = {}

    def __init__(self, session, firstframe=None):
        self.session = session
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
        self.payload = data
        return None

    def handle(self, data):
        """Handle data from a Session class."""

        data = self.parse(data)
        if self.opcode <> None:
            try:
                f = getattr(self, 'opcode_%s' % self.opcode)
            except AttributeError:
                f = self.opcode_unknown
            if not self.opcode_desc and f.__doc__:
                self.opcode_desc = f.__doc__.split('\n')[0]
            f()
        return data

    def opcode_unknown(self):
        """Unknown opcode"""

        raise AttributeError('Opcode %d unknown' % self.opcode)


class Session:
    """Base class for a binary protocol session."""

    # Override this, duh
    Packet = Packet

    def __init__(self, frame):
        self.firstframe = frame
        self.lastframe = [None, None]
        self.basename = 'transfers/%s' % (frame.src_addr,)
        self.pending = {}
        self.count = 0
        self.setup()

    def setup(self):
        """Set things up."""

        pass

    def handle(self, is_srv, frame, gs, lastpos):
        """Handle a data burst.

        @param is_srv   Is this from the server?
        @param frame    A frame associated with this packet, or None if it's all drops
        @param gs       A gapstring of the data
        @param lastpos  Last position in the source file, for debugging

        """

        if frame:
            self.lastframe[is_srv] = frame
        frame = self.lastframe[is_srv]
        self.lastpos = lastpos
        try:
            saddr = frame.saddr
            try:
                (f, data) = self.pending.pop(saddr)
            except KeyError:
                f = frame
                data = gapstr.GapString()
            data.extend(gs)
            try:
                while data:
                    p = self.Packet(self, f)
                    data = p.handle(data)
                    self.process(p)
            except NeedMoreData:
                self.pending[saddr] = (f, data)
            self.count += 1
        except:
            print 'Lastpos: %s:::%d' % lastpos
            raise

    def process(self, packet):
        """Process a packet.

        When you first start out, this probably does exactly what you
        want: print out packets as they come in.  As you progress you'll
        probably want to override it with something more sophisticated.
        That will of course vary wildly between protocols.

        """

        print 'Lastpos: %s:::%d' % self.lastpos
        packet.show()

    def done(self):
        """Called when all packets have been handled"""

        return

    def make_filename(self, fn):
        try:
            os.makedirs(self.basename)
        except OSError:
            pass
        frame = self.firstframe
        fn = '%s:%d-%s:%d---%s' % (frame.src_addr, frame.sport,
                                   frame.dst_addr, frame.dport,
                                   urllib.quote(fn, '\:'))
        return os.path.join(self.basename, fn)

    def handle_packets(self, collection):
        """Handle a collection of packets"""

        for chunk in resequence(collection):
            self.handle(chunk)
        self.done()


class HtmlSession(Session):
    def __init__(self, frame):
        Session.__init__(self, frame)
        self.sessfn = self.make_filename('session.html')
        self.sessfd = file(self.sessfn, 'w')
        self.sessfd.write('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html
  PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
  <title>%s</title>
  <style type="text/css">
    .server { background-color: white; color: black; }
    .client { background-color: #884; color: white; }
  </style>
</head>
<body>
''' % self.__class__.__name__)
        self.sessfd.write('<h1>%s</h1>\n' % self.__class__.__name__)
        self.sessfd.write('<pre>')
        self.srv = None

    def __del__(self):
        self.sessfd.write('</pre></body></html>')

    def log(self, frame, payload, escape=True):
        if escape:
            p = cgi.escape(payload)
        else:
            p = payload
        if not self.srv:
            self.srv = frame.saddr
        if frame.saddr == self.srv:
            cls = 'server'
        else:
            cls = 'client'
        self.sessfd.write('<span class="%s" title="%s(%s)">' % (cls, time.ctime(frame.time), frame.time))
        self.sessfd.write(p.replace('\r\n', '\n'))
        self.sessfd.write('</span>')
