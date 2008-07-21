#! /usr/bin/python

## 2008 Massive Blowout

"""Functions to treat a list as a string with gaps.

Lists should have only string and integer items.

"""

import __init__
import sys

class GapString:
    def __init__(self, init=None, drop='?'):
        self.contents = []
        self.length = 0
        self.drop = drop
        if init:
            self.append(init)

    def __len__(self):
        return self.length

    def __repr__(self):
        return '<GapString of length %d>' % self.length

    def append(self, i):
        self.contents.append(i)
        if isinstance(i, int):
            self.length += i
        else:
            self.length += len(i)

    def __str__(self):
        ret = []
        for i in self.contents:
            if isinstance(i, int):
                ret.append(self.drop * i)
            else:
                ret.append(i)
        return ''.join(ret)

    def __iter__(self):
        for i in self.contents:
            if isinstance(i, int):
                for j in range(i):
                    yield self.drop
            else:
                for c in i:
                    yield c

    def hasgaps(self):
        for i in self.contents:
            if isinstance(i, int):
                return True
        return False

    def hexdump(self, fd=sys.stdout):
        offset = 0

        d = __init__.HexDumper(fd)
        for i in self.contents:
            if isinstance(i, int):
                for j in range(i):
                    d.dump_drop()
            else:
                for c in i:
                    d.dump_chr(c)
        d.finish()

    def extend(self, other):
        self.contents += other.contents
        self.length += other.length

    def __getslice__(self, start, end):
        end = min(self.length, end)
        start = min(self.length, start)

        new = self.__class__(drop=self.drop)
        new.length = max(end - start, 0)
        if new.length == 0:
            new.contents = []
            return new
        new.contents = self.contents[:]

        l = self.length - new.length - start

        # Trim off the beginning
        while start >= 0:
            i = new.contents.pop(0)
            if isinstance(i, int):
                start -= i
                if start < 0:
                    new.contents.insert(0, -start)
            else:
                start -= len(i)
                if start < 0:
                    new.contents.insert(0, i[start:])

        # Trim off the end
        while l >= 0:
            i = new.contents.pop()
            if isinstance(i, int):
                l -= i
                if l < 0:
                    new.contents.append(-l)
            else:
                l -= len(i)
                if l < 0:
                    new.contents.append(i[:-l])

        return new

    def __getitem__(self, idx):
        # XXX: speed up
        return str(self)[idx]

    def __add__(self, other):
        if isinstance(other, str):
            self.append(other)
        else:
            new = self.__class__(drop=self.drop)
            new.extend(self)
            new.extend(other)
            return new

    def __xor__(self, mask):
        if isinstance(mask, int):
            mask = [mask]
        if isinstance(mask, str) or isinstance(mask, GapString):
            mask = [ord(c) for c in mask]
        masklen = len(mask)

        new = self.__class__(drop=self.drop)
        for i in self.contents:
            if isinstance(i, int):
                new.append(i)
            else:
                r = []
                offset = len(new) % masklen
                for c in i:
                    o = ord(c)
                    r.append(chr(o ^ mask[offset]))
                    offset = (offset + 1) % masklen
                new.append(''.join(r))
        return new



if __name__ == '__main__':
    gs = GapString()
    gs.append('hi')
    assert str(gs) == 'hi'
    assert str(gs[:40]) == 'hi'
    gs.append(3)
    assert str(gs) == 'hi???'
    assert str(gs[:40]) == 'hi???'
    assert str(gs[:3]) == 'hi?'
    assert str(gs[-4:]) == 'i???'
    assert str(gs + gs) == 'hi???hi???'
    assert str(gs ^ 1) == 'ih???'

    gs = GapString()
    gs.append('123456789A')
    assert str(gs[:4]) == '1234'
    assert len(gs[:4]) == 4
    assert len(gs[6:]) == 4
    assert str(gs[:0]) == ''

