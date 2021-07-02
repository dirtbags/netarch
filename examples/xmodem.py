#! /usr/bin/python3

import netarch

class XmodemPacket(netarch.Packet):
    def parse(self, data):
        datastream = netarch.Unpacker(data)
        self.opcode = datastream.uint8()
        self.payload = datastream.buf

    def opcode_1(self):
        "Xfer"
        datastream = netarch.Unpacker(self.payload)
        self["seq"] = datastream.uint8()
        self["~seq"] = datastream.uint8()

        assert self["seq"] == 255 - self["~seq"]
        assert len(datastream.buf) == 0x81

        self["checksum"] = datastream.uint8(pos=-1)
        self.payload = datastream.buf

    def opcode_4(self):
        "EOT"

    def opcode_6(self):
        "ACK"

    def opcode_21(self):
        "Begin transmission?"

class XmodemSession(netarch.Session):
    Packet = XmodemPacket

    def process(self, packet):
        packet.show()

        if packet.opcode == 21:
            # Open a new file for output
            self.out = self.open_out("data.bin")
        elif packet.opcode == 1:
            self.out.write(bytes(packet.payload))


netarch.main(XmodemSession)
