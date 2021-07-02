#! /usr/bin/python3

## 2008, 2018 Neale Pickett

import itertools

class TriloBytes:
    """Three-level byte array (0, 1, Missing).

    This allows you to represent on-wire transactions with holes in the middle,
    due to eg. dropped packets.
    
    >>> tb = TriloBytes(b'hi')
    >>> bytes(tb)
    b'hi'
    >>> bytes(tb[:40])
    b'hi'
    
    >>> tb = TriloBytes(b'hi') + [None] * 3
    >>> bytes(tb)
    b'hi???'
    >>> bytes(tb[:40])
    b'hi???'
    >>> bytes(tb[:3])
    b'hi?'
    >>> bytes(tb[-4:])
    b'i???'
    >>> bytes(tb + tb)
    b'hi???hi???'
    >>> bytes(tb ^ 1)
    b'ih???'
    >>> bytes(tb ^ [32, 1])
    b'Hh???'
    
    >>> tb = TriloBytes(b'hi', drop=b'DROP')
    >>> bytes(tb)
    b'hi'
    >>> tb += [None] * 7
    >>> bytes(tb)
    b'hiOPDROPD'

    >>> tb = TriloBytes(b'00')^1
    >>> tb[0]
    1
    
    >>> bytes(TriloBytes(b'00'))
    b'\x00'
"""

    def __init__(self, initializer=(), drop=b'?'):
        self._drop = drop
        self._contents = tuple(initializer)

    @classmethod
    def fromhex(cls, string):
        """
        >>> bytes(TriloBytes.fromhex("616263"))
        b'abc'
        """
        
        return cls(bytes.fromhex(string))

    def __len__(self):
        """
        >>> len(TriloBytes(b'abc'))
        3
        """
        
        return len(self._contents)

    def __nonzero__(self):
        """
        >>> 10 if TriloBytes() else -10
        -10
        >>> 10 if TriloBytes(b'a') else -10
        10
        """
        
        return len(self) > 0

    def __getitem__(self, key):
        ret = self._contents[key]
        try:
            return TriloBytes(ret, self._drop)
        except:
            return ret

    def __iter__(self):
        for val in self._contents:
            yield val

    def __bytes__(self):
        return bytes((d if v is None else v for v,d in zip(self,itertools.cycle(self._drop))))

    def __add__(self, other):
        try:
            contents = self._contents + other._contents
        except AttributeError:
            contents = self._contents + tuple(other)
        return TriloBytes(contents, self._drop)

    def __eq__(self, other):
        try:
            return self._contents == other._contents
        except:
            return False

    def __hash__(self):
        return hash(self._contents)
        
    def __xor__(self, mask):
        try:
            mask[0]
        except TypeError:
            mask = [mask]
        return TriloBytes(((None if x is None or y is None else x^y) for x,y in zip(self._contents, itertools.cycle(mask))), drop=self._drop)

    def __repr__(self):
        """
        >>> TriloBytes(b'abc')
        <TriloBytes missing 0 of 3>
        >>> TriloBytes(b'abc') + [None]
        <TriloBytes missing 1 of 4>
        """
        
        return '<TriloBytes missing %d of %d>' % (self.missing(), len(self))

    def decode(self, codec):
        return bytes(self).decode(codec)
    
    def missing(self):
        """
        >>> TriloBytes(b'abc').missing()
        0
        >>> (TriloBytes(b'abc') + [None, None]).missing()
        2
        """
        return self._contents.count(None)

    def map(self, func, *args):
        return (v if v is not None else func(v, *args) for v in self)


if __name__ == '__main__':
    import doctest
    doctest.testmod()
