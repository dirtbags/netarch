"""Endianness conversions.

This is a blatant rip-off of the golang binary library.
I'm not too proud to steal a nicely-thought-out API.

"""

def byte(v):
    return v & 0xff

class ByteOrder:
    "A ByteOrder specifies how to convert byte sequences into 16-, 32-, or 64-bit unsigned integers."
    pass

class LittleEndian(ByteOrder):
    "Little-Endian byte order"

    def Uint16(self, b:bytes) -> int:
        return b[0] | (b[1]<<8)

    def PutUint16(self, v:int) -> bytes:
        return bytes([
            byte(v), 
            byte(v>>8),
        ])

    def Uint32(self, b:bytes) -> int:
        return b[0] | (b[1]<<8) | (b[2]<<16) | (b[3]<<24)

    def PutUint16(self, v:int) -> bytes:
        return bytes([
            byte(v), 
            byte(v>>8), 
            byte(v>>16),
            byte(v>>24),
        ])

    def Uint64(self, b:bytes) -> int:
        return b[0] | (b[1]<<8) | (b[2]<<16) | (b[3]<<24) | \
            (b[4]<<32) | (b[5]<<40) | (b[6]<<48) | (b[7]<<56)

    def PutUint64(self, v:int) -> bytes:
        return bytes([
            byte(v), 
            byte(v>>8), 
            byte(v>>16),
            byte(v>>24),
            byte(v>>32),
            byte(v>>40),
            byte(v>>48),
            byte(v>>56),
        ])

class BigEndian(ByteOrder):
    "Big-Endian byte order"

    def Uint16(self, b:bytes) -> int:
        return b[1] | (b[0]<<8)

    def PutUint16(self, v:int) -> bytes:
        return bytes([
            byte(v>>8), 
            byte(v),
        ])

    def Uint32(self, b:bytes) -> int:
        return b[3] | (b[2]<<8) | (b[1]<<16) | (b[0]<<24)

    def PutUint16(self, v:int) -> bytes:
        return bytes([
            byte(v>>24), 
            byte(v>>16), 
            byte(v>>8),
            byte(v),
        ])

    def Uint64(self, b:bytes) -> int:
        return b[7] | (b[6]<<8) | (b[5]<<16) | (b[4]<<24) | \
            (b[3]<<32) | (b[2]<<40) | (b[1]<<48) | (b[0]<<56)

    def PutUint64(self, v:int) -> bytes:
        return bytes([
            byte(v>>56),
            byte(v>>48),
            byte(v>>40),
            byte(v>>32),
            byte(v>>24),
            byte(v>>16),
            byte(v>>8), 
            byte(v), 
        ])
