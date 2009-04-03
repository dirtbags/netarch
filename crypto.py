#! /usr/bin/python

## Codebreaking tools
## 2007  Massive Blowout
## I should get an LAUR for this so we can share it.

from sets import Set
from pprint import pprint

# From Wikipedia article "Letter Frequencies"
english_frequency = {'A': .08167,
                     'B': .01492,
                     'C': .02782,
                     'D': .04253,
                     'E': .12702,
                     'F': .02228,
                     'G': .02015,
                     'H': .06094,
                     'I': .06966,
                     'J': .00153,
                     'K': .00772,
                     'L': .04025,
                     'M': .02406,
                     'N': .06749,
                     'O': .07507,
                     'P': .01929,
                     'Q': .00095,
                     'R': .05987,
                     'S': .06327,
                     'T': .09056,
                     'U': .02758,
                     'V': .00978,
                     'W': .02360,
                     'X': .00150,
                     'Y': .01974,
                     'Z': .00074}

##
## Statistical stuff
##


def basedist(l):
    """Return a string of length l, with standard distribution of letters"""

    out = ""
    for c, n in english_frequency.iteritems():
        out += c * int(n * l)
    return out


##
## Factoring stuff
##


def isPrime(number):
    for x in range(2, number):
        if number % x == 0:
            return True
        else:
            if number - 1 == x:
                return False

def smallestFactor(number):
    for x in range(2, number):
        if number % x == 0:
            return x

def factor(number):
    """Return prime factors for number"""

    factors = []
    while isPrime(number):
        newFactor = smallestFactor(number)
        factors.append(newFactor)
        number = number / newFactor
    factors.append(number)
    return factors


##
## Statistical analysis
##

def where(haystack, needle):
    ret = []
    while True:
        pos = haystack.find(needle)
        if pos == -1:
            break
        ret.append(pos)
        haystack = haystack[pos + 1:]
    return ret


def ngrams(n, haystack, min=2, repeats=False):
    acc = {}
    for i in range(len(haystack)):
        rtxt = haystack[i:]
        needle = rtxt[:n]
        if repeats:
            c = needle[0]
            for d in needle:
                if d != c:
                    break
            if d != c:
                continue
        if not acc.has_key(needle):
            found = where(rtxt, needle)
            if len(found) >= min:
                acc[needle] = found
    return acc


def freq(txt):
    return ngrams(1, txt, min=0)

def bigrams(txt):
    return ngrams(2, txt)

def trigrams(txt):
    return ngrams(3, txt)


def freqgraph(f):
    def cmp2(x, y):
        a = x[1]
        b = y[1]
        if a > b:
            return -1
        elif a < b:
            return 1
        else:
            return 0
    items = []
    for c,n in f.iteritems():
        if type(n) != type(0):
            n = len(n)
        items.append((c,n))
    items.sort(cmp2)

    for c,n in items:
        print '%s: %s' % (c, '#' * n)

def neighbors(txt):
    out = {}
    for dg, w in bigrams(txt).iteritems():
        count = len(w)

        n = out.get(dg[0], Set())
        n.add(dg[1])
        out[dg[0]] = n

        n = out.get(dg[1], Set())
        n.add(dg[0])
        out[dg[1]] = n
    return out


##
## Brute force tools
##

def rot(n, txt):
    """Caesar cipher only across letters"""

    out = ""
    for c in txt:
        if c.isalpha():
            o = ord(c) + n
            if ((c.islower() and o > ord('z')) or
                (c.isupper() and o > ord('Z'))):
                o -= 26
            out += chr(o)
        else:
            out += c
    return out


def caesar(n, txt):
    return [chr((ord(c) + n) % 256) for c in txt]

def caesars(txt):
    return [caesar(i, txt) for i in range(256)]

# Tabula recta
tabula_recta = caesars('ABCDEFGHIJKLMNOPQRSTUVWXYZ')


def xor(n, txt):
    if n == 0:
        return txt
    out = [(chr(ord(c) ^ n)) for c in txt]
    return ''.join(out)

def xors(txt):
    ret = []
    for n in range(256):
        ret.append(xor(n, txt))
    return ret


def add(n, txt):
    out = ''
    for c in txt:
        o = (ord(c) + 256 + n) % 256    # Add 256 in case n < 0
        out += chr(o)
    return out

def adds(txt):
    ret = []
    for n in range(256):
        ret.append(add(n, txt))
    return ret


class XorMask:
    def __init__(self, mask, stick=False):
        self.offset = 0
        if type(mask) == type(''):
            self._mask = tuple(ord(m) for m in mask)
        else:
            self._mask = tuple(mask)
        self.stick = stick

    def __call__(self, s):
        r = []
        offset = self.offset
        for c in s:
            o = ord(c)
            r.append(chr(o ^ self._mask[offset]))
            offset = (offset + 1) % len(self._mask)
        if self.stick:
            self.offset = offset
        return ''.join(r)


##
## Grep-like things within dictionary
##
def matches(str, tgt):
    if len(str) != len(tgt):
        return False
    map = {}
    rmap = {}
    for i in range(len(str)):
        s = str[i]
        t = tgt[i]
        m = map.get(s)
        if m and m != t:
            return False
        map[s] = t

        r = rmap.get(t)
        if r and r != s:
            return False
        rmap[t] = s

    return True

def guess(pattern):
    ret = []

    pattern = pattern.lower()
    words = file('/usr/share/dict/words')
    for word in words:
        word = word.strip()
        word = word.lower()
        if matches(word, pattern):
            print word
    return ret

##
## Overview tools
##

def summary(txt):
    print "Length", len(txt)
    print "Factors", factor(len(txt))
    print
    print "Frequency (etaoin shrdlcu)"
    freqgraph(freq(txt))
    print

    print "Bigrams (th er on an re he in ed nd ha at en es of or"
    print "         nt ea ti to it st io le is ou ar as de rt ve)"
    freqgraph(bigrams(txt))
    print

    print "Trigrams (the and tha ent ion tio for nde has nce edt"
    print "          tis oft sth men)"
    freqgraph(trigrams(txt))
    print

    # 4-letter words: that with have this will your from they know
    #                 want been good much some time

    print "Repeats (ss ee tt ff ll mm oo)"
    freqgraph(ngrams(2, txt, min=1, repeats=True))
    print

    print "Unique neighbors"
    pprint(neighbors(txt))
    print


def replace(txt, orig, repl):
    for o, r in zip(orig, repl):
        txt = txt.replace(o, r)
    return txt
