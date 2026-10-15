package main

import (
	"bytes"
	"testing"
)

func TestFFFFIsTwoBytes(t *testing.T) {
	vals := BoundaryValues(2)
	var found bool
	for _, v := range vals {
		if bytes.Equal(v, []byte{0xFF, 0xFF}) {
			found = true
		}
		if len(v) != 2 {
			t.Fatalf("ширина 2, получено %d байт: %X", len(v), v)
		}
	}
	if !found {
		t.Fatalf("среди граничных нет FF FF: %X", vals)
	}
}

func TestBoundaryWidths(t *testing.T) {
	for width := 1; width <= 4; width++ {
		for _, v := range BoundaryValues(width) {
			if len(v) != width {
				t.Fatalf("width %d value %X", width, v)
			}
		}
	}
	one := BoundaryValues(1)
	if !bytes.Equal(one[0], []byte{0x00}) || !bytes.Equal(one[1], []byte{0xFF}) {
		t.Fatalf("однобайтовые границы: %X", one)
	}
}

func TestFindSeparators(t *testing.T) {
	hits := FindSeparators([]byte("a,b:c=d;e"))
	checks := map[byte]int{',': 1, ':': 3, '=': 5, ';': 7}
	for sep, want := range checks {
		got := hits[sep]
		if len(got) != 1 || got[0] != want {
			t.Fatalf("разделитель %q: %#v", sep, got)
		}
	}
}

func TestFindSeparatorsAbsent(t *testing.T) {
	hits := FindSeparators([]byte("/startabc"))
	for _, sep := range []byte{',', ':', '=', ';'} {
		if len(hits[sep]) != 0 {
			t.Fatalf("ложное срабатывание %q", sep)
		}
	}
}

func TestExpandFieldAfterStart(t *testing.T) {
	got, change, err := ExpandField([]byte("hdr/startHELLO"), []byte("AA"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("hdr/startAAHELLO")) {
		t.Fatalf("got %q, change %s", got, change.Text)
	}
}

func TestExpandFieldInsideSeparator(t *testing.T) {
	got, _, err := ExpandField([]byte("hdr/start,VAL;"), []byte("XX"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("hdr/start,XXVAL;")) {
		t.Fatalf("got %q", got)
	}
}
