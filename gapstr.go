package netshovel

import (
)

type GapString []int

func (g GapString) Missing() int {
	var n int = 0
	for _, b := range g {
		if b == -1 {
			n += 1
		}
	}
	return n
}

func (g GapString) Append(h GapString) GapString {
	return append(g, h...)
}

func (g GapString) Xor(mask ...int) GapString {
	ret := make(GapString, len(g))
	for i := range g {
		b := mask[i%len(mask)]
		if g[i] == -1 || b == -1 {
			ret[i] = -1
		} else {
			ret[i] = g[i] ^ b
		}
	}
	return ret
}

func (g GapString) Bytes(gap ...byte) []byte {
	ret := make([]byte, len(g))
	length := 0
	for i, v := range g {
		if g[i] == -1 {
			if len(gap) > 0 {
				ret[length] = gap[i % len(gap)]
				length += 1
			}
		} else {
			ret[length] = byte(v)
			length += 1
		}
	}
	return ret[:length]
}

func (g GapString) String(gap string) string {
	return string(g.Bytes([]byte(gap)...))
}

func (g GapString) Apppend(other ...GapString) GapString {
	var out []byte
	for _, o := range other {
		out = append(out, o.Bytes(0)...)
	}
	return GapStringOfBytes(out)
}

func GapStringOfBytes(b []byte) GapString {
	ret := make(GapString, len(b))
	for i, v := range b {
		ret[i] = int(v)
	}
	return ret
}

func GapStringOfString(s string) GapString {
	return GapStringOfBytes([]byte(s))
}

func GapStringOfGap(n int) GapString {
	ret := make(GapString, n)
	for i := 0; i < n; i  += 1 {
		ret[i] = -1
	}
	return ret
}