#! /usr/bin/python3

## IP resequencing + protocol reversing skeleton
## 2008, 2018 Neale Pickett

import struct
import socket
import warnings
import heapq
import time
import io
try:
    import pcap
except ImportError:
    warnings.warn("Using slow pure-python pcap library")
    from . import py_pcap as pcap
import os
import cgi
import urllib.parse
from .hexdump import hexdump
from .trilobytes import TriloBytes

def unpack(fmt, buf):
    """Unpack buf based on fmt, return the remainder."""

    size = struct.calcsize(fmt)
    vals = struct.unpack(fmt, bytes(buf[:size]))
    return vals + (buf[size:],)


def unpack_nybbles(byte):
    return (byte >> 4, byte & 0x0F)

transfers = os.environ.get('TRANSFERS', 'transfers')

IP = 0x0800
ARP = 0x0806
VLAN = 0x8100

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
        if self.eth_type == VLAN:
            _, self.eth_type, p = unpack('!HH', p)
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
        if not hasattr(self, "_src_addr"):
            saddr = struct.pack('!i', self.saddr)
            self._src_addr = socket.inet_ntoa(saddr)
        return self._src_addr
    src_addr = property(get_src_addr)

    def get_dst_addr(self):
        if not hasattr(self, "_dst_addr"):
            daddr = struct.pack('!i', self.daddr)
            self._dst_addr = socket.inet_ntoa(daddr)
        return self._dst_addr
    dst_addr = property(get_dst_addr)

    def __repr__(self):
        if self.eth_type == ARP:
            return '<Frame %s %s(%s) -> %s(%s)>' % (self.name,
                                                    str_of_eth(self.ar_sha),
                                                    self.src_addr,
                                                    str_of_eth(self.ar_tha),
                                                    self.dst_addr)
        else:
            return ('<Frame %s %s:%r(%08x) -> %s:%r(%08x) length %d>' %
                    (self.name,
                    self.src_addr, self.sport, self.seq,
                    self.dst_addr, self.dport, self.ack,
                    len(self.payload)))

class TCP_Recreate:
    closed = True

    def __init__(self, pcap, src, dst, timestamp):
        self.pcap = pcap
        self.src = (socket.inet_aton(src[0]), src[1])
        self.dst = (socket.inet_aton(dst[0]), dst[1])
        self.sid = self.did = 0
        self.sseq = self.dseq = 1
        self.lastts = 0
        self.write_header()
        self.handshake(timestamp)

    def write_header(self):
        p = '\0\0\0\0\0\0\0\0\0\0\0\0\xfe\xed'
        self.pcap.write(((0,0,len(p)), p))

    def packet(self, cli, payload, flags=0):
        if cli:
            sip, sport = self.src
            dip, dport = self.dst
            id = self.sid
            self.sid += 1
            seq = self.sseq
            self.sseq += len(payload)
            if flags & (SYN|FIN):
                self.sseq += 1
            ack = self.dseq
        else:
            sip, sport = self.dst
            dip, dport = self.src
            id = self.did
            self.did += 1
            seq = self.dseq
            self.dseq += len(payload)
            if flags & (SYN|FIN):
                self.dseq += 1
            ack = self.sseq
        if not (flags & ACK):
            ack = 0
        ethhdr = struct.pack('!6s6sH',
                             '\x11\x11\x11\x11\x11\x11',
                             '\x22\x22\x22\x22\x22\x22',
                             IP)

        iphdr = struct.pack('!BBHHHBBH4s4s',
                            0x45, # Version, Header length/32
                            0,    # Differentiated services / ECN
                            40+len(payload), # total size
                            id,
                            0x4000, # Don't fragment, no fragment offset
                            6,      # TTL
                            TCP,    # Protocol
                            0,      # Header checksum
                            sip,
                            dip)
        shorts = struct.unpack('!HHHHHHHHHH', iphdr)
        shsum = sum(shorts)
        ipsum = struct.pack('!H', ((shsum + (shsum >> 16)) & 0xffff) ^ 0xffff)
        iphdr = iphdr[:10] + ipsum + iphdr[12:]

        tcphdr = struct.pack('!HHLLBBHHH',
                             sport,
                             dport,
                             seq,    # Sequence number
                             ack,    # Acknowledgement number
                             0x50,   # Data offset
                             flags,  # Flags
                             0xff00, # Window size
                             0,      # Checksum
                             0)      # Urgent pointer



        return ethhdr + iphdr + tcphdr + bytes(payload)

    def write_pkt(self, timestamp, cli, payload, flags=0):
        p = self.packet(cli, payload, flags)
        frame = (timestamp + (len(p),), p)
        self.pcap.write(frame)
        self.lastts = timestamp

    def write(self, timestamp, cli, data):
        while data:
            d, data = data[:0xff00], data[0xff00:]
            self.write_pkt(timestamp, cli, d, ACK)

    def handshake(self, timestamp):
        self.write_pkt(timestamp, True, '', SYN)
        self.write_pkt(timestamp, False, '', SYN|ACK)
        #self.write_pkt(timestamp, True, '', ACK)

    def close(self):
        self.write_pkt(self.lastts, True, '', FIN|ACK)
        self.write_pkt(self.lastts, False, '', FIN|ACK)
        self.write_pkt(self.lastts, True, '', ACK)

    def __del__(self):
        if not self.closed:
            self.close()

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
        self.lastack = [None, None]
        self.first = None
        self.pending = [{}, {}]
        self.closed = [False, False]
        self.midstream = False
        self.hash = 0

        self.handle = self.handle_handshake


    def bundle_pending(self, xdi, pkt, seq):
        """Bundle up any pending packets.

        Called when a packet comes from a new direction, this is the thing responsible for
        replaying TCP as a back-and-forth conversation.

        """

        pending = self.pending[xdi]
        # Get a sorted list of sequence numbers
        keys = sorted(pending)

        # Build up return value
        gs = TriloBytes()
        if keys:
            first = pending[keys[0]]
        else:
            first = None

        # Fill in gs with our frames
        for key in keys:
            if key >= pkt.ack:
                # In the future
                break
            frame = pending[key]
            if key > seq:
                # Dropped frame(s)
                dropped = key - seq
                if dropped > 6000:
                    print("Gosh, %d dropped octets sure is a lot!" % (dropped))
                gs += [None] * dropped
                seq = key
            if key == seq:
                # Default
                gs += frame.payload
                seq += len(frame.payload)
                del pending[key]
            elif key < seq:
                # Hopefully just a retransmit.  Anyway we've already
                # claimed to have data (or a drop) for this packet.
                del pending[key]
            if frame.flags & (FIN):
                seq += 1
            if frame.flags & (FIN | ACK) == FIN | ACK:
                self.closed[xdi] = True
                if self.closed == [True, True]:
                    self.handle = self.handle_drop
        if seq != pkt.ack:
            # Drop at the end
            dropped = pkt.ack - seq
            if dropped > 6000:
                print('Large drop at end of session!')
                print('    %s' % ((pkt, pkt.time),))
                print('    %x  %x' % (pkt.ack, seq))
            gs += [None] * dropped

        return (xdi, first, gs)


    def handle_handshake(self, pkt):
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
        # Which way is this going?  0 == from client
        idx = int(pkt.src == self.srv)
        xdi = 1 - idx

        if pkt.flags & RST:
            # Handle RST before wonky sequence numbers screw up algorithm
            self.closed = [True, True]
            self.handle = self.handle_drop

            return self.bundle_pending(xdi, pkt, self.lastack[idx])
        else:
            # Stick it into pending
            self.pending[idx][pkt.seq] = pkt

            # Does this ACK after the last output sequence number?
            seq = self.lastack[idx]
            self.lastack[idx] = pkt.ack
            if pkt.ack > seq:
                return self.bundle_pending(xdi, pkt, seq)


    def handle_drop(self, pkt):
        """Warn about any unhandled packets"""

        if pkt.flags & SYN:
            # Re-using ports!
            self.__init__()
            return self.handle(pkt)

        if pkt.payload:
            warnings.warn('Spurious frame after shutdown: %r %d' % (pkt, pkt.flags))
            hexdump(pkt.payload)


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
            fd = open(fn, "rb")
            pc = pcap.open(fd)
            if len(parts) > 1:
                pos = int(parts[1])
                fd.seek(pos)
            self._read(pc, fn, fd)
        else:
            fd = open(filename, "rb")
            pc = pcap.open(fd)
            self._read(pc, filename, fd)

    def _read(self, pc, filename, fd):
        pos = fd.tell()
        f = pc.read()
        if f:
            heapq.heappush(self.tops, (f, pc, filename, fd, pos))

    def __iter__(self):
        while self.tops:
            f, pc, filename, fd, pos = heapq.heappop(self.tops)
            if not self.last:
                self.last = (filename, pos)
            frame = Frame(f)
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

class Packet:
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
        self.subpackets = []

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
        print('%s %3s: %s' % (self.__class__.__name__,
                              self.opcode,
                              self.opcode_desc))
        if self.firstframe:
            print('    %s:%d -> %s:%d (%s.%06dZ)' % (self.firstframe.src_addr,
                                                     self.firstframe.sport,
                                                     self.firstframe.dst_addr,
                                                     self.firstframe.dport,
                                                     time.strftime('%Y-%m-%dT%T', time.gmtime(self.firstframe.time)),
                                                     self.firstframe.time_usec))

        if self.parts:
            dl = len(self.parts[-1])
            p = []
            xp = []
            for x in self.parts[:-1]:
                if x == dl:
                    p.append('%3d!' % x)
                    xp.append('%3x!' % x)
                else:
                    p.append('%3d' % x)
                    xp.append('%3x' % x)
            print('           parts: (%s) +%d octets' % (','.join(p), dl))
            print('         0xparts: (%s) +%x octets' % (','.join(xp), dl))

        keys = sorted(self.params)
        for k in keys:
            print('    %12s: %s' % (k, self.params[k]))

        if self.subpackets:
            for p in self.subpackets:
                p.show()
        elif self.payload:
            try:
                hexdump(self.payload)
            except AttributeError:
                print('         payload: %r' % self.payload)

    def parse(self, data):
        """Parse a chunk of data (possibly a TriloBytes).

        Anything returned is not part of this packet and will be passed
        in to a subsequent packet.

        """

        self.parts = [data]
        self.payload = data
        return None

    def handle(self, data):
        """Handle data from a Session class."""

        data = self.parse(data)
        if self.opcode != None:
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

        raise AttributeError('Opcode %s unknown' % self.opcode)


class Session:
    """Base class for a binary protocol session."""

    # Override this, duh
    Packet = Packet

    def __init__(self, frame):
        self.firstframe = frame
        self.lastframe = [None, None]
        self.basename = os.path.join(transfers, frame.src_addr)
        self.basename2 = os.path.join(transfers, frame.dst_addr)
        self.pending = {}
        self.count = 0
        for d in (self.basename, self.basename2):
            try:
                os.makedirs(d)
            except OSError:
                pass

        self.setup()

    def setup(self):
        """Set things up."""

        pass

    def handle(self, is_srv, frame, data, lastpos):
        """Handle a data burst.

        @param is_srv   Is this from the server?
        @param frame    A frame associated with this packet, or None if it's all drops
        @param data     A TriloBytes of the data
        @param lastpos  Last position in the source file, for debugging

        """

        if frame:
            self.lastframe[is_srv] = frame
        frame = self.lastframe[is_srv]
        self.lastpos = lastpos
        try:
            saddr = frame.saddr
            try:
                (f, buf) = self.pending.pop(saddr)
            except KeyError:
                f = frame
                buf = TriloBytes()
            buf += data
            try:
                while buf:
                    p = self.Packet(self, f)
                    buf = p.handle(buf)
                    self.process(p)
            except NeedMoreData:
                self.pending[saddr] = (f, buf)
            self.count += 1
        except:
            print('Lastpos: %r' % (lastpos,))
            raise

    def process(self, packet):
        """Process a packet.

        When you first start out, this probably does exactly what you
        want: print out packets as they come in.  As you progress you'll
        probably want to override it with something more sophisticated.
        That will of course vary wildly between protocols.

        """

        packet.show()

    def done(self):
        """Called when all packets have been handled"""

        return

    def open_out(self, fn):
        frame = self.firstframe
        fn = '%d-%s~%d-%s~%d---%s' % (frame.time,
                                      frame.src_addr, frame.sport,
                                      frame.dst_addr, frame.dport,
                                      urllib.parse.quote(fn, ''))
        fullfn = os.path.join(self.basename, fn)
        fullfn2 = os.path.join(self.basename2, fn)
        print('  writing %s' % (fn,))
        fd = open(fullfn, 'wb')
        try:
            os.unlink(fullfn2)
        except OSError:
            pass
        os.link(fullfn, fullfn2)
        return fd

    def handle_packets(self, collection):
        """Handle a collection of packets"""

        for chunk in resequence(collection):
            self.handle(chunk)
        self.done()


class HtmlSession(Session):
    def __init__(self, frame):
        Session.__init__(self, frame)
        fd = self.open_out('session.html')
        fbuf = io.BufferedWriter(fd, 1024)
        self.sessfd = io.TextIOWrapper(fbuf, encoding="utf-8")
        self.sessfd.write('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE html
  PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
  <title>%s</title>
  <style type="text/css">
    .time { float: right; margin-left: 1em; font-size: 75%%; }
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
            p = cgi.escape(str(payload))
        else:
            p = payload
        if not self.srv:
            self.srv = frame.saddr
        if frame.saddr == self.srv:
            cls = 'server'
        else:
            cls = 'client'

        if False:
            self.sessfd.write('<span class="%s" title="%s(%s)">' % (cls, time.ctime(frame.time), frame.time))
        else:
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(frame.time))
            self.sessfd.write('<span class="time %s">%s</span><span class="%s">' % (cls, ts, cls))
        self.sessfd.write(p.replace('\r\n', '\n'))
        self.sessfd.write('</span>')
            
