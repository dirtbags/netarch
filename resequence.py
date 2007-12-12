#! /usr/bin/python

import scapy
import StringIO

IP = scapy.IP
TCP = scapy.TCP
Raw = scapy.Raw


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
        p = self.pc.read()
        if not p:
            return
        return scapy.Ether(p[1])

    def read_handshake(self):
        # Read SYN
        pkt = self.read_packet()
        assert (pkt[TCP].flags == 2) # XXX: There's got to be a better way
        self.cli = (pkt[IP].src, pkt.sport)
        self.srv = (pkt[IP].dst, pkt.dport)
        self.seq[0] = pkt.seq + 1

        # Read SYN-ACK
        while True:
            pkt = self.read_packet()
            if ((pkt[IP].src == self.srv[0]) and
                (pkt[TCP].flags == 18)):
                self.seq[1] = pkt.seq + 1
                break

        # Read ACK
        while True:
            pkt = self.read_packet()
            if ((pkt[IP].src == self.cli[0]) and
                (pkt[TCP].flags == 16)):
                assert (self.seq[0] == pkt.seq)
                break

        self.frames = 3

    def __iter__(self):
        while True:
            pkt = self.read_packet()
            if not pkt:
                return
            self.frames += 1

            # Which way is this going?
            idx = int(pkt[IP].src == self.srv[0])
            xdi = 1 - idx

            # Does this ACK after the last output sequence number?
            if pkt.ack > self.seq[xdi]:
                pending = self.pending[xdi]
                seq = self.seq[xdi]
                ret = DropStringIO()
                keys = pending.keys()
                for key in keys:
                    if key >= pkt.ack:
                        continue

                    pkt2 = pending[key]
                    del pending[key]

                    ret.seek(pkt2.seq - seq)
                    ret.write(pkt2[TCP][Raw].load)
                self.seq[xdi] = pkt.ack

                yield (xdi, ret.getvalue())

            # If it has a payload, stick it into pending
            if hasattr(pkt[TCP][Raw], 'load'):
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

