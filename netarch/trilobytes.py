#! /usr/bin/python3

## 2008, 2018 Neale Pickett

import itertools

class TriloBytes:
    """Three-level byte array (0, 1, Missing).

This allows you to represent on-wire transactions with holes in the middle,
due to eg. dropped packets.
"""

    def __init__(self, initializer=(), drop=b'?'):
        self._drop = drop
        self._contents = tuple(initializer)

    @classmethod
    def fromhex(cls, string):
        return cls(bytes.fromhex(string))

    @classmethod
    def join(cls, *objects):
        contents = []
        for o in objects:
            # print(o)
            contents.extend(o._contents)

        new = cls()
        new._contents = tuple(contents)
        return new

    def __len__(self):
        return len(self._contents)

    def __nonzero__(self):
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
        return bytes((v or d for v,d in zip(self,itertools.cycle(self._drop))))

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
        return TriloBytes(((x^y if x else None) for x,y in zip(self._contents, itertools.cycle(mask))), drop=self._drop)

    def __repr__(self):
        return '<TriloBytes missing %d of %d>' % (self.missing(), len(self))

    def missing(self):
        return self._contents.count(None)

    def map(self, func, *args):
        return (v if v is not None else func(v, *args) for v in self)


if __name__ == '__main__':
    gs = TriloBytes(b'hi')
    assert bytes(gs) == b'hi'
    assert bytes(gs[:40]) == b'hi'

    gs = gs + [None] * 3
    assert bytes(gs) == b'hi???'
    assert bytes(gs[:40]) == b'hi???'
    assert bytes(gs[:3]) == b'hi?'
    assert bytes(gs[-4:]) == b'i???'
    assert bytes(gs + gs) == b'hi???hi???'
    assert bytes(gs ^ 1) == b'ih???'
    assert bytes(gs ^ [32, 1]) == b'Hh???'
    
    gs = TriloBytes(b'hi', drop=b'DROP')
    assert bytes(gs) == b'hi'
    
    gs = gs + [None] * 7
    assert bytes(gs) == b'hiOPDROPD'
