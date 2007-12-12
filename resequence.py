#! /usr/bin/python

import StringIO
import struct
import socket

def unpack(fmt, buf):
    """Unpack buf based on fmt, assuming the rest is a string."""

    size = struct.calcsize(fmt)
    vals = struct.unpack(fmt, buf[:size])
    return vals + (buf[size:],)

def unpack_nybbles(byte):
    return (byte >> 4, byte & 0x0F)

class Frame:
    def __init__(self, frame):
        (self.eth_dhost,
         self.eth_shost,
         self.eth_type,
         p) = unpack('!6s6sH', frame)
        if self.eth_type != 0x0800:
            raise ValueError('Not IP %04x' % self.eth_type)

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
         p) = unpack("!BBHHHBBH4s4s", p)
        if self.protocol != 6:
            raise ValueError('Not TCP')

        (self.th_sport,
         self.th_dport,
         self.th_seq,
         self.th_ack,
         x2off,
         self.th_flags,
         self.th_win,
         self.th_sum,
         self.th_urp,
         p) = unpack("!HHLLBBHHH", p)
        (th_off, th_x2) = unpack_nybbles(x2off)
        opt_length = th_off * 4

        self.th_options = p[20:opt_length]
        payload = p[opt_length:self.tot_len - 40]

        self.src = (self.saddr, self.th_sport)
        self.dst = (self.daddr, self.th_dport)
        self.seq = self.th_seq
        self.ack = self.th_ack
        self.payload = payload

        self.saddr = socket.inet_ntoa(self.saddr)
        self.daddr = socket.inet_ntoa(self.daddr)

    def __repr__(self):
        return '<Frame %s:%d -> %s:%d len %d>' % (self.saddr, self.th_sport,
                                                  self.daddr, self.th_dport,
                                                  len(self.payload))


class DropStringIO(StringIO.StringIO):
    """StringIO with different padding.

    If you write beyond the length of the current string, this pads with
    the string 'Drop', and not NULs.  This should make it more obvious
    that you've had a drop.  I hope.

    """

    padstr = 'Drop'

    def write(self, s):
        if self.pos > self.len:
            bytes = self.pos - self.len
            pad = self.padstr * ((bytes / len(self.padstr)) + 1)
            self.buflist.append(pad[:bytes])
            self.len = self.pos
        return StringIO.StringIO.write(self, s)


class TCP_Session:
    """Iterable TCP session resequencer.

    You initialize it with something with a read() method that returns a
    new ethernet frame.  For instance, an object from my py-pcap module.

    The read() method returns (srv, chunk), where srv is 1 if this came
    from the server, and chunk is a chunk of data.

    This returns things in sequence.  So you get both sides of the
    conversation in the order that they happened.

    Doesn't (yet) handle fragments or dropped packets.  Does handle out
    of order packets.

    """

    def __init__(self, pc):
        self.pc = pc

        self.cli = None
        self.srv = None
        self.seq = [None, None]
        self.pending = [{}, {}]
        self.frames = 0

        self.read_handshake()

    def read_packet(self):
        while True:
            p = self.pc.read()
            if not p:
                return
            try:
                return Frame(p[1])
            except ValueError:
                raise

    def read_handshake(self):
        # Read SYN
        pkt = self.read_packet()
        assert (pkt.th_flags == 2) # XXX: There's got to be a better way
        self.cli = pkt.src
        self.srv = pkt.dst
        self.seq[0] = pkt.seq + 1

        # Read SYN-ACK
        while True:
            pkt = self.read_packet()
            if ((pkt.src == self.srv) and
                (pkt.th_flags == 18)):
                self.seq[1] = pkt.th_seq + 1
                break

        # Read ACK
        while True:
            pkt = self.read_packet()
            if ((pkt.src == self.cli) and
                (pkt.th_flags == 16)):
                assert (self.seq[0] == pkt.th_seq)
                break

        self.frames = 3

    def __iter__(self):
        while True:
            pkt = self.read_packet()
            if not pkt:
                return
            self.frames += 1

            # Which way is this going?
            idx = int(pkt.src == self.srv)
            xdi = 1 - idx

            # Does this ACK after the last output sequence number?
            if pkt.th_ack > self.seq[xdi]:
                pending = self.pending[xdi]
                seq = self.seq[xdi]
                ret = DropStringIO()
                keys = pending.keys()
                for key in keys:
                    if key >= pkt.th_ack:
                        continue

                    pkt2 = pending[key]
                    del pending[key]

                    ret.seek(pkt2.th_seq - seq)
                    ret.write(pkt2.payload)
                self.seq[xdi] = pkt.th_ack

                yield (xdi, ret.getvalue())

            # If it has a payload, stick it into pending
            if pkt.payload:
                self.pending[idx][pkt.seq] = pkt
        self.done()

    def done(self):
        """Warn about any unhandled packets"""

        for p in self.pending:
            k = p.keys()
            if k:
                k.sort()
                print 'unused packets:', k
        return



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

