#! /usr/bin/python3

import sys
from netarch import ip
from netarch import *

s = None
reseq = ip.Dispatch(*sys.argv[1:])
for h, d in reseq:
    srv, first, chunk = d
    if not s:
        s = ip.Session(first)
    s.handle(srv, first, chunk, reseq.last)
