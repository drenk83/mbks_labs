package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Block — один базовый блок модуля цели.
// Module отличает одинаковые смещения vuln3.exe и func.dll.
type Block struct {
	Module string
	Start  uint32
}

var (
	moduleLine = regexp.MustCompile(`^\s*(\d+)\s*,`)
	bbLine     = regexp.MustCompile(`^module\[\s*(\d+)\]:\s*0x([0-9a-fA-F]+)`)
)

// matchedModule узнаёт строку таблицы модулей по имени файла в пути.
func matchedModule(line string, moduleNames []string) string {
	lower := strings.ToLower(line)
	for _, name := range moduleNames {
		if name != "" && strings.Contains(lower, strings.ToLower(name)) {
			return name
		}
	}
	return ""
}

// ParseDrcov собирает базовые блоки модулей, в пути которых есть одно из имён.
func ParseDrcov(r io.Reader, moduleNames ...string) (map[Block]struct{}, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	ids := map[int]string{}
	inBB := false
	blocks := map[Block]struct{}{}
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "BB Table:") {
			// Выше этой строки — модули и их id, ниже — выполненные блоки.
			inBB = true
			continue
		}
		if !inBB {
			name := matchedModule(line, moduleNames)
			if name == "" {
				continue
			}
			m := moduleLine.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			id, err := strconv.Atoi(m[1])
			if err != nil {
				return nil, err
			}
			ids[id] = name
			continue
		}
		m := bbLine.FindStringSubmatch(line)
		if m == nil || len(ids) == 0 {
			continue
		}
		id, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, err
		}
		name, ok := ids[id]
		if !ok {
			continue
		}
		start, err := strconv.ParseUint(m[2], 16, 32)
		if err != nil {
			return nil, err
		}
		blocks[Block{Module: name, Start: uint32(start)}] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("в логе drcov нет модуля %s", strings.Join(moduleNames, ", "))
	}
	return blocks, nil
}

// measureCoverage гоняет цель под drcov и забирает блоки vuln3.exe и func.dll.
// Каталог лога очищается, чтобы не прочитать журнал прошлого запуска.
func measureCoverage(exe, workDir, logDir string) (map[Block]struct{}, error) {
	if err := os.RemoveAll(logDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, err
	}
	cmd := exec.Command(drRun, "-root", drRoot, "-t", "drcov", "-dump_text", "-logdir", logDir, "--", exe)
	cmd.Dir = workDir
	out, runErr := cmd.CombinedOutput()
	return blocksFromRun(runErr, out, logDir, filepath.Base(exe), "func.dll")
}

// blocksFromRun читает лог drcov, даже если цель вышла с ненулевым кодом.
// Код выхода мешает только когда лога нет: падение до записи или сбой drrun.
func blocksFromRun(runErr error, runOut []byte, logDir string, modules ...string) (map[Block]struct{}, error) {
	blocks, err := readDrcovDir(logDir, modules...)
	if err == nil {
		return blocks, nil
	}
	if runErr != nil {
		return nil, fmt.Errorf("drrun: %w: %s", runErr, runOut)
	}
	return nil, err
}

// readDrcovDir открывает последний drcov.*.proc.log в каталоге этого запуска.
func readDrcovDir(logDir string, modules ...string) (map[Block]struct{}, error) {
	matches, err := filepath.Glob(filepath.Join(logDir, "drcov.*.proc.log"))
	if err != nil {
		return nil, err
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("drrun не создал лог покрытия")
	}
	f, err := os.Open(matches[len(matches)-1])
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseDrcov(f, modules...)
}

// newBlocks оставляет блоки, которых ещё не было. Пустой результат — покрытие не выросло.
func newBlocks(seen, got map[Block]struct{}) []Block {
	var fresh []Block
	for b := range got {
		if _, ok := seen[b]; !ok {
			fresh = append(fresh, b)
		}
	}
	return fresh
}
