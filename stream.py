import typing
from . import trilobytes

class NamedFile(typing.NamedTuple):
    """A file object and the path where it lives"""
    File: typing.BinaryIO
    Name: string

class Utterance(typing.NamedTuple):
    """An atomic communication within a Stream.

    Streams consist of a string of Utterances.
    Each utterance has associated data, and a time stamp.
        
    Typically these line up with what crosses the network,
    but bear in mind that TCP is a streaming protocol,
    so don't rely on Utterances alone to separate Application-layer packets.
    """

    When: float
    Data: trilobytes.TriloBytes

class Stream:
    """A Stream is one half of a two-way conversation"""

    def __init__(self, net, transport):
        self.net = net
        self.transport = transport

    def reassembled(rs):
        """Called by the TCP assembler when an Utterance can be built"""
        data = trilobytes.TriloBytes()
        for r in rs:
            if r.Skip > 0:
                data += [None] * r.Skip
            data + r.Bytes
        if len(data) > 0