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
        return int(self.length)

    def __repr__(self):
        return '<GapString of length %d>' % self.length

    def append(self, i):
        try:
            self.length += len(i)
            self.contents.append(i)
        except TypeError:
            self.length += i
            self.contents.append(i)

    def __str__(self):
        ret = []
        for i in self.contents:
            try:
                ret.append(self.drop * i)
            except TypeError:
                ret.append(i)
        return ''.join(ret)

    def __iter__(self):
        for i in self.contents:
            try:
                for c in i:
                    yield c
            except TypeError:
                for j in range(i):
                    yield self.drop

    def __nonzero__(self):
        return self.length > 0

    def hasgaps(self):
        for i in self.contents:
            if isinstance(i, int):
                return True
        return False

    def hexdump(self, fd=sys.stdout):
        offset = 0

        d = __init__.HexDumper(fd)
        for i in self.contents:
            try:
                for j in range(i):
                    d.dump_drop()
            except TypeError:
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
            try:
                start -= i
                if start < 0:
                    new.contents.insert(0, -start)
            except TypeError:
                start -= len(i)
                if start < 0:
                    new.contents.insert(0, i[start:])

        # Trim off the end
        while l >= 0:
            i = new.contents.pop()
            try:
                l -= i
                if l < 0:
                    new.contents.append(-l)
            except TypeError:
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
        try:
            mask = [ord(c) for c in mask]
        except TypeError:
            mask = [mask]
        masklen = len(mask)

        new = self.__class__(drop=self.drop)
        for i in self.contents:
            try:
                r = []
                offset = len(new) % masklen
                for c in i:
                    o = ord(c)
                    r.append(chr(o ^ mask[offset]))
                    offset = (offset + 1) % masklen
                new.append(''.join(r))
            except TypeError:
                new.append(i)
        return new

    def index(self, needle):
        pos = 0
        for i in self.contents:
            try:
                return pos + i.index(needle)
            except AttributeError:
                pos += i
            except ValueError:
                pos += len(i)
        raise ValueError('substring not found')

    def split(self, pivot=' ', times=None):
        ret = []
        n = 0
        cur = self
        while (not times) or (n < times):
            try:
                pos = cur.index(pivot)
            except ValueError:
                break
            ret.append(cur[:pos])
            cur = cur[pos+len(pivot):]
        ret.append(cur)
        return ret

    def startswith(self, what):
        return (what == str(self[:len(what)]))


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

