import sys

stdch = (
    '␀·········␊··␍··'
    '················'
    ' !"#$%&\'()*+,-./'
    '0123456789:;<=>?'
    '@ABCDEFGHIJKLMNO'
    'PQRSTUVWXYZ[\\]^_'
    '`abcdefghijklmno'
    'pqrstuvwxyz{|}~·'
    '················'
    '················'
    '················'
    '················'
    '················'
    '················'
    '················'
    '················'
)

decch = (
    '␀␁␂␃␄␅␆␇␈␉␊␋␌␍␎␏'
    '␐␑␒␓␔␕␖␗␘␙␚·····'
    '␠!"#$%&\'()*+,-./'
    '0123456789:;<=>?'
    '@ABCDEFGHIJKLMNO'
    'PQRSTUVWXYZ[\\]^_'
    '`abcdefghijklmno'
    'pqrstuvwxyz{|}~␡'
    '················'
    '················'
    '················'
    '················'
    '················'
    '················'
    '················'
    '················'
)

cgach = (
    '□☺☻♥♦♣♠•◘○◙♂♀♪♫☼'
	'►◄↕‼¶§▬↨↑↓→←∟↔▲▼'
	' !"#$%&\'()*+,-./'
	'0123456789:;<=>?'
	'@ABCDEFGHIJKLMNO'
	'PQRSTUVWXYZ[\\]^_'
	'`abcdefghijklmno'
	'pqrstuvwxyz{|}~⌂'
	'ÇüéâäàåçêëèïîìÄÅ'
	'ÉæÆôöòûùÿÖÜ¢£¥₧ƒ'
	'áíóúñÑªº¿⌐¬½¼¡«»'
	'░▒▓│┤╡╢╖╕╣║╗╝╜╛┐'
	'└┴┬├─┼╞╟╚╔╩╦╠═╬╧'
	'╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀'
	'αßΓπΣσµτΦΘΩδ∞φε∩'
	'≡±≥≤⌠⌡÷≈°∙·√ⁿ²■¤'
)

fluffych = (
    '·☺☻♥♦♣♠•◘○◙♂♀♪♫☼'
	'►◄↕‼¶§▬↨↑↓→←∟↔▲▼'
	' !"#$%&\'()*+,-./'
	'0123456789:;<=>?'
	'@ABCDEFGHIJKLMNO'
	'PQRSTUVWXYZ[\\]^_'
	'`abcdefghijklmno'
	'pqrstuvwxyz{|}~⌂'
	'ÇüéâäàåçêëèïîìÄÅ'
	'ÉæÆôöòûùÿÖÜ¢£¥₧ƒ'
	'áíóúñÑªº¿⌐¬½¼¡«»'
	'░▒▓│┤╡╢╖╕╣║╗╝╜╛┐'
	'└┴┬├─┼╞╟╚╔╩╦╠═╬╧'
	'╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀'
	'αßΓπΣσµτΦΘΩδ∞φε∩'
	'≡±≥≤⌠⌡÷≈°∀∃√ⁿ²■¤'
)

class HexDumper:
    def __init__(self, output, charset=fluffych):
        self.offset = 0
        self.last = None
        self.elided = False
        self.hexes = []
        self.chars = []
        self.charset = charset
        self.output = output

    def _spit(self):
        if self.chars == self.last:
            if not self.elided:
                self.output.write('*\n')
                self.elided = True
            self.hexes = []
            self.chars = []
            return
        self.last = self.chars[:]
        self.elided = False

        pad = 16 - len(self.chars)
        self.hexes += ['  '] * pad

        self.output.write('{:08x}  '.format(self.offset - len(self.chars)))
        self.output.write(' '.join(self.hexes[:8]))
        self.output.write('  ')
        self.output.write(' '.join(self.hexes[8:]))
        self.output.write('  ')
        self.output.write(''.join(self.chars))
        self.output.write('\n')

        self.hexes = []
        self.chars = []

    def add(self, b):
        if self.offset and self.offset % 16 == 0:
            self._spit()

        if b is None:
            h = '⬜'
            c = '�'
        else:
            h = '{:02x}'.format(b)
            c = self.charset[b]
        self.chars.append(c)
        self.hexes.append(h)

        self.offset += 1

    def done(self):
        self._spit()
        self.output.write('{:08x}\n'.format(self.offset))


def hexdump(buf, f=sys.stdout, charset=fluffych):
    "Print a hex dump of buf"

    h = HexDumper(output=f, charset=charset)
    for b in buf:
        h.add(b)
    h.done()
