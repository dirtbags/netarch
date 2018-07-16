package netshovel

import (
	"testing"
)

func TestAll(t *testing.T) {
	str := "Hello World"
	g := GapStringOfString(str)
	var h GapString

	if g.String("") != str {
		t.Error("String conversion")
	}
	if g.String("") != string(g.Bytes()) {
		t.Error("String() != string(Bytes())")
	}
	
	if g.Xor(0x20).String("") != "hELLO\x00wORLD" {
		t.Error("xor failed")
	}
	
	if g.Append(GapStringOfString("!")).String("") != "Hello World!" {
		t.Error("Appending")
	}
	
	mt := GapStringOfGap(10)
	if mt.Missing() != 10 {
		t.Error("Missing count")
	}
	if mt.Missing() != len(mt) {
		t.Error("All gaps len != missing")
	}
	
	h = g.Append(mt).Append(GapStringOfString("!!!!"))
	if len(h) != len(g) + len(mt) + 4 {
		t.Error("Append length")
	}
	
	if h.String("DROP") != "Hello WorldPDROPDROPD!!!!" {
		t.Error("Gap fill with DROP")
	}
	
	if h.String("") != "Hello World!!!!" {
		t.Error("Gap fill with empty string")
	}
}
