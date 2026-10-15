package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"
)

func TestDebugEventMatchesWin32(t *testing.T) {
	if unsafe.Sizeof(debugEvent{}) != debugEventSize {
		t.Fatalf("DEBUG_EVENT %d, у Win32 это 96", unsafe.Sizeof(debugEvent{}))
	}
}

func TestLiveOriginalAndCrash(t *testing.T) {
	if os.Getenv("FUZZER_LIVE") == "" {
		t.Skip("живой прогон включается FUZZER_LIVE=1")
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(root, targetName)
	cfg := filepath.Join(root, configName)
	original, err := loadFile(filepath.Join(root, "..", "source", configName))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFile(cfg, original); err != nil {
		t.Fatal(err)
	}
	crash, err := RunDebug(exe, root, runTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if crash != nil {
		t.Fatalf("исходный конфиг уронил цель: %08X", crash.Code)
	}
	blocks, err := measureCoverage(exe, root, filepath.Join(root, "cov"))
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) == 0 {
		t.Fatal("покрытие vuln3.exe пустое")
	}
	t.Logf("блоков на исходном конфиге: %d", len(blocks))

	at := indexOf(original, []byte("/start"))
	if at < 0 {
		t.Fatal("нет /start")
	}
	insert := append([]byte(nil), original[:at+len("/start")]...)
	insert = append(insert, bytes.Repeat([]byte{'A'}, 2000)...)
	insert = append(insert, original[at+len("/start"):]...)
	wide := append([]byte(nil), original...)
	copy(wide[4:8], []byte{0xFF, 0xFF, 0x00, 0x00})
	tries := []struct {
		name string
		data []byte
	}{
		{"длина 0xFFFF", wide},
		{"вставка 2000 байт после /start", insert},
	}
	store := NewStore(root)
	var found *Crash
	var foundChange string
	var foundData []byte
	for _, try := range tries {
		change := Change{Text: try.name}
		if err := writeFile(cfg, try.data); err != nil {
			t.Fatal(err)
		}
		crash, err = RunDebug(exe, root, runTimeout)
		if err != nil {
			t.Fatal(err)
		}
		if crash == nil {
			t.Logf("%s: без исключения", try.name)
			continue
		}
		t.Logf("%s: %08X", try.name, crash.Code)
		found = crash
		foundChange = change.Text
		foundData = try.data
		break
	}
	if err := writeFile(cfg, original); err != nil {
		t.Fatal(err)
	}
	if found == nil {
		t.Fatal("пробные входы не дали исключения")
	}
	path, err := store.SaveCrash(foundData, found, foundChange)
	if err != nil {
		t.Fatal(err)
	}
	text, err := os.ReadFile(path + ".log")
	if err != nil {
		t.Fatal(err)
	}
	body := string(text)
	if !strings.Contains(body, "Exception code:") || !strings.Contains(body, "Eip:") || !strings.Contains(body, "Stack") {
		t.Fatalf("лог неполный:\n%s", body)
	}
	t.Logf("лог %s.log", path)
}
