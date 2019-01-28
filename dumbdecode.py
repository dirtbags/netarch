#! /usr/bin/python3

import sys
from netarch import ip
from netarch import *

class DumbPacket(ip.Packet):
    def parse(self, data):
        self.payload = data

class DumbSession(ip.Session):
    Packet = DumbPacket

s = None
reseq = ip.Dispatch(*sys.argv[1:])
for h, d in reseq:
    srv, first, chunk = d
    if not s:
        s = DumbSession(first)
    s.handle(srv, first, chunk, reseq.last)
