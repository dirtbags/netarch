#!/usr/bin/python
'''Example use of the netarch.ip framework

Searching and replacing "StinkyPinky" with your protocol's name would be a good
start.

'''


import sys

from netarch import ip
from netarch import unpack


class StinkyPinkyPacket(ip.Packet):
    ''' StinkyPinky Protocol '''

    def parse(self, data):
        '''Parse Packet Data

        This method deals with data on a packet level. Its job in life is to
        set parts, payload, and opcode.  If any data is passed to this method
        is deemed to not be part of the packet's data, it should be returned.
        Likewise, if the Packet needs more data, raise ip.NeedsMoreData

        self.parts   - a magic bag of values; (!) when the value matches len(self.payload)
        self.payload - non-header packet data
        self.opcode  - an integer that triggers additional parsing
        self.text    - text to be displayed without prep (i.e. shell output)
        self.html    - html information for logging

        return:

            If you need more data, raise ip.NeedMoreData()
            If you have excess data, return it from this function

        '''
        self.parts = unpack("<BBBB", data)  # example 4-byte header
        self.payload = self.parts[-1]

        return None

    def opcode_0(self):     # example - delete me
        '''Example opcode parser

        Each identified opcode will need to have a method defined for it. They
        should be named opcode_ followed by the integer decimal opcode and
        retain the same method signature.

        It is also important that each opcode method defines a docstring.  It
        will be used in the packet display.

        '''
        pass

    def opcode_1(self):     # example - delete me
        ''' NOP Command '''
        pass


class StinkyPinkySession(ip.HtmlSession):
    ''' A StinkyPinky Session '''

    def __init__(self, frame, packetClass=StinkyPinkyPacket, debug=True):
        ip.HtmlSession.__init__(self, frame, packetClass, debug)

    def process(self, packet):
        '''Process packet data

        This method might be a good spot for special data handling at a session
        level. One example would be carving embedded data to a separate file.

        This default action, copied from ip.HtmlSession, writes any packet.html
        and packet.text (URL escaped) to the session log

        '''
        if self.debug:
            packet.show()
        if hasattr(packet, "html") and packet.html is not None:
            self.log(packet.firstframe, packet.html, False)
        if hasattr(packet, "text") and packet.text is not None:
            if self.debug:
                sys.stdout.write(self.text)
            self.log(packet.firstframe, packet.text, True)


# execution harness
if __name__ == '__main__':
    if len(sys.argv) > 1:
        s = None
        reseq = ip.Dispatch(*sys.argv[1:])
        for h, d in reseq:
            srv, first, chunk = d
            if not s:
                s = StinkyPinkySession(first)
            s.handle(srv, first, chunk, reseq.last)
