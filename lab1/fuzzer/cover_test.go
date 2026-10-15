package main

import (
	"strings"
	"testing"
)

func TestParseDrcovKeepsOnlyTarget(t *testing.T) {
	log := `
Module Table: version 5, count 2
Columns: id, containing_id, start, end, entry, offset, preferred_base, checksum, timestamp, path
  0,   0, 0x00060000, 0x00073000, 0x000612a0, 0000000000000000, 0x00060000, 0x0000c4a7, 0x56e72fd6,  C:\lab\vuln3.exe
  1,   1, 0x62500000, 0x6250b000, 0x62501060, 0000000000000000, 0x62500000, 0x00002c75, 0x56e72fd2,  C:\lab\func.dll
BB Table: 3 bbs
module id, start, size:
module[  0]: 0x00001000,   4
module[  1]: 0x00002000,   8
module[  0]: 0x00001010,   2
`
	blocks, err := ParseDrcov(strings.NewReader(log), "vuln3.exe")
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 2 {
		t.Fatalf("блоков цели %d, хотели 2", len(blocks))
	}
	if _, ok := blocks[Block{Start: 0x1000}]; !ok {
		t.Fatal("нет блока 0x1000")
	}
	if _, ok := blocks[Block{Start: 0x2000}]; ok {
		t.Fatal("блок чужого модуля попал в покрытие цели")
	}
}
