from StringIO import StringIO

class bitvector:
    def __init__(self, txt):
        self.txt = txt

    def __getitem__(self, idx):
        base, offset = divmod(idx, 8)
        o = ord(self.txt[base])
        return (o >> offset) & 1
