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
type Block struct {
	Start uint32
}

var (
	moduleLine = regexp.MustCompile(`^\s*(\d+)\s*,`)
	bbLine     = regexp.MustCompile(`^module\[\s*(\d+)\]:\s*0x([0-9a-fA-F]+)`)
)

// ParseDrcov собирает базовые блоки модуля, в пути которого есть moduleName.
func ParseDrcov(r io.Reader, moduleName string) (map[Block]struct{}, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	targetID := -1
	inBB := false
	blocks := map[Block]struct{}{}
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "BB Table:") {
			inBB = true
			continue
		}
		if !inBB {
			if !strings.Contains(strings.ToLower(line), strings.ToLower(moduleName)) {
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
			targetID = id
			continue
		}
		m := bbLine.FindStringSubmatch(line)
		if m == nil || targetID < 0 {
			continue
		}
		id, err := strconv.Atoi(m[1])
		if err != nil {
			return nil, err
		}
		if id != targetID {
			continue
		}
		start, err := strconv.ParseUint(m[2], 16, 32)
		if err != nil {
			return nil, err
		}
		blocks[Block{Start: uint32(start)}] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if targetID < 0 {
		return nil, fmt.Errorf("в логе drcov нет модуля %s", moduleName)
	}
	return blocks, nil
}

func measureCoverage(exe, workDir, logDir string) (map[Block]struct{}, error) {
	if err := os.RemoveAll(logDir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, err
	}
	cmd := exec.Command(drRun, "-root", drRoot, "-t", "drcov", "-dump_text", "-logdir", logDir, "--", exe)
	cmd.Dir = workDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("drrun: %w: %s", err, out)
	}
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
	return ParseDrcov(f, filepath.Base(exe))
}

func newBlocks(seen, got map[Block]struct{}) []Block {
	var fresh []Block
	for b := range got {
		if _, ok := seen[b]; !ok {
			fresh = append(fresh, b)
		}
	}
	return fresh
}
