package main

import (
	"fmt"
	"os"
	"path/filepath"
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
	if _, ok := blocks[Block{Module: "vuln3.exe", Start: 0x1000}]; !ok {
		t.Fatal("нет блока 0x1000")
	}
	if _, ok := blocks[Block{Module: "func.dll", Start: 0x2000}]; ok {
		t.Fatal("блок чужого модуля попал в покрытие цели")
	}
}

func TestParseDrcovSeparatesModules(t *testing.T) {
	log := `
  0,   0, 0x00060000, 0x00073000, 0x000612a0, 0000000000000000, 0x00060000, 0x0000c4a7, 0x56e72fd6,  C:\lab\vuln3.exe
  1,   1, 0x62500000, 0x6250b000, 0x62501060, 0000000000000000, 0x62500000, 0x00002c75, 0x56e72fd2,  C:\lab\func.dll
BB Table: 2 bbs
module[  0]: 0x00001000,   4
module[  1]: 0x00001000,   8
`
	blocks, err := ParseDrcov(strings.NewReader(log), "vuln3.exe", "func.dll")
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 2 {
		t.Fatalf("блоков %d, хотели 2", len(blocks))
	}
}

func TestBlocksFromRunKeepsLogOnNonZeroExit(t *testing.T) {
	dir := t.TempDir()
	log := `
  0,   0, 0x00060000, 0x00073000, 0x000612a0, 0000000000000000, 0x00060000, 0x0000c4a7, 0x56e72fd6,  C:\lab\vuln3.exe
  1,   1, 0x62500000, 0x6250b000, 0x62501060, 0000000000000000, 0x62500000, 0x00002c75, 0x56e72fd2,  C:\lab\func.dll
BB Table: 2 bbs
module[  0]: 0x00001000,   4
module[  1]: 0x00001000,   8
`
	if err := os.WriteFile(filepath.Join(dir, "drcov.vuln3.exe.1.proc.log"), []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	blocks, err := blocksFromRun(fmt.Errorf("exit status 0xffffffff"), []byte("variant does not match"), dir, "vuln3.exe", "func.dll")
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 2 {
		t.Fatalf("блоков %d", len(blocks))
	}
	_, err = blocksFromRun(fmt.Errorf("drrun failed"), nil, t.TempDir(), "vuln3.exe")
	if err == nil {
		t.Fatal("без лога ошибка drrun должна всплыть")
	}
}
