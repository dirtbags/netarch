
import typing
import io
from . import binary

class Error(Exception):
    """Base class for netshovel exceptions"""
    pass


class ShortError(Error):
    """Exception raised when not enough data is available.

    Attributes:
        wanted -- how much data we wanted
        available -- how much data we had
    """
    
    def __init__(self, wanted:int, available:int):
        self.wanted = wanted
        self.available = available

    def __str__(self):
        return "Not enough data available: wanted %d, got %d" % (self.wanted, self.got)


class MissingError(Error):
    """Exception raised when gaps were present for code that can't handle gaps.
    """

    def __init__(self):
        pass

    def __str__(self):
        return "Operation on missing bytes"


class namedField(typing.NamedTuple):
    key: str
    value: str

class headerField(typing.NamedTuple):
    name: str
    bits: int
    value: typing.Any
    order: binary.ByteOrder

class Packet:
    def __init__(self, when, payload):
        self.opcode = -1
        self.description = "Undefined"
        self.when = when
        self.payload = payload
        self.header = []
        self.fields = []

    def describeType(self) -> str:
        """Returns a string with timestamp, opcode, and description of this packet"""
        return "%s Opcode %d: %s"  % (self.when, self.opcode, self.description)
    
    def describeFields(self) -> str:
        """Returns a multi-line string describing fields in this packet"""
        lines = []
        for k, v in self.fields:
            lines.append("    %s: %s\n", k, v)
        return "".join(lines)

    def describeHeader(self) -> str:
        """Returns a multi-line string describing this packet's header structure"""
        out = io.StringIO()
        out.write(" 0                               1                            \n")
        out.write(" 0 1 2 3 4 5 6 7 8 9 a b c d e f 0 1 2 3 4 5 6 7 8 9 a b c d e f\n")
        
        bitOffset = 0
        for f in self.header:
            bits = f.bits
            while bits > 0:
                if bitOffset == 0:
                    out.write("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n")
                linebits = bits
                if linebits+bitOffset > 0x20:
                    linebits = 0x20 - bitOffset

                nameval = "%s (0x%x)" % (f.name, f.value)
                out.write("|" + nameval.center(linebits*2-1))

                bitOffset += linebits
                bits -= linebits
                if linebits == 0x20:
                    out.write("|\n")
                    bitOffset = 0
        out.write("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n")
        return out.getvalue()

    def describe(self) -> str:
        """Return a multi-line string describing this packet

        This shows the timestamp, opcode, description, and hex dump.
        If you set any values, those are displayed in the order they were set.

        This will quickly get unweildy, especially for large conversations.
        You are encouraged to implement your own describe() method.
        """
        out = io.StringIO()
        out.write(self.describeType())
        out.write("\n")
        out.write(self.describeFields())
        out.write(self.describeHeader())
        out.write(self.payload.hexdump())
        return out.getvalue()

    def setValue(self, key:str, value:str):
        """Set a value

        This is intended to be used to note debugging information
        that you'd like to see on each packet.
        """
        self.fields.append(namedField(key, value))

    def setString(self, key:str, value:str):
        """Set a string value, displaying its Python string representation"""
        self.setValue(key, repr(value))

    def setInt(self, key:str, value:int):
        """Set an int value, displaying its decimal and hexadecimal representations"""
        self.setValue(key, "%d == 0x%x" % (value, value))
    setUInt = setInt

    def setUInt32(self, key:str, value:int):
        """Set a Uint32 value, dispalying its decimal and 0-padded hexadecimal representations"""
        self.setValue(key, "%d == %04x" % (value, value))

    def setBytes(self, key:str, value:str):
        """Set a bytes value, displaying the hex encoding of the bytes"""
        self.setValue(key, binascii.hexlify(value).encode("ascii"))

    def peel(self, octets:int) -> bytes:
        """Peel octets bytes off the Payload, returning those bytes"""
        pllen = len(self.payload)
        if octets > pllen:
            raise ShortError(octets, pllen)
        buf = self.payload[:octets]
        if buf.missing() > 0:
            raise MissingError()
        self.payload = self.payload[octets:]
        return buf.bytes()

    def addHeaderField(self, order:binary.ByteOrder, name:str, bits:int, value:typing.Any):
        """Add a field to the header field description."""
        h = headerField(name, bits, value, order)
        self.header.append(h)

    def readUint(self, order:binary.ByteOrder, bits:int, name:str):
        """Peel an unsigned integer of size bits, adding it to the header field"""
        if bits not in (8, 16, 32, 64):
            raise RuntimeError("Weird number of bits: %d" % bits)
        octets = bits >> 3
        b = self.peel(octets)
        if bits == 8:
            value = b[0]
        elif bits == 16:
            value = order.Uint16(b)
        elif bits == 32:
            value = order.Uint32(b)
        elif bits == 64:
            value = order.Uint64(b)
        self.addHeaderField(order, name, bits, value)

        return value

    def uint8(self, name:str) -> int:
        "Peel off a uint8 (aka byte)"
        return self.readUint(binary.LittleEndian, 8, name)
    
    def uint16le(self, name:str) -> int:
        "Peel off a uint16, little-endian"
        return self.readUint(binary.LittleEndian, 16, name)

    def uint32le(self, name:str) -> int:
        "Peel off a uint32, little-endian"
        return self.readUint(binary.LittleEndian, 32, name)

    def uint64le(self, name:str) -> int:
        "Peel off a uint64, little-endian"
        return self.readUint(binary.LittleEndian, 64, name)

    def uint16be(self, name:str) -> int:
        "Peel off a uint64, big-endian"
        return self.readUint(binary.BigEndian, 16, name)

    def uint32be(self, name:str) -> int:
        "Peel off a uint32, big-endian"
        return self.readUint(binary.BigEndian, 32, name)

    def uint64be(self, name:str) -> int:
        "Peel off a uint44, big-endian"
        return self.readUint(binary.BigEndian, 64, name)
