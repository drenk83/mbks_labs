package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Store помнит уже виденные блоки и следующий номер краша, чтобы не затереть старые файлы.
type Store struct {
	Root   string
	seen   map[Block]struct{}
	crashN int
}

// NewStore продолжает нумерацию с крашей, которые уже лежат в каталоге.
func NewStore(root string) *Store {
	return &Store{Root: root, seen: map[Block]struct{}{}, crashN: nextCrashIndex(root)}
}

// nextCrashIndex смотрит crash0, crash1, … и возвращает следующий свободный номер.
func nextCrashIndex(root string) int {
	matches, err := filepath.Glob(filepath.Join(root, "crashes", "crash*"))
	if err != nil {
		return 0
	}
	max := -1
	for _, m := range matches {
		name := strings.TrimSuffix(filepath.Base(m), ".log")
		if !strings.HasPrefix(name, "crash") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(name, "crash"))
		if err != nil || n < 0 {
			continue
		}
		if n > max {
			max = n
		}
	}
	if max < 0 {
		return 0
	}
	return max + 1
}

// Remember добавляет блоки в общую базу и возвращает только новые.
func (s *Store) Remember(blocks map[Block]struct{}) []Block {
	fresh := newBlocks(s.seen, blocks)
	for _, b := range fresh {
		s.seen[b] = struct{}{}
	}
	return fresh
}

func (s *Store) SeenCount() int { return len(s.seen) }

// Log дописывает текст мутации в fuzz.log, по одному запуску на строку.
func (s *Store) Log(line string) error {
	f, err := os.OpenFile(filepath.Join(s.Root, "fuzz.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, line)
	return err
}

// SaveSeed кладёт вход с новым покрытием в corpus.
// В имени файла — сколько блоков уже видно и сколько добавил этот сид.
func (s *Store) SaveSeed(data []byte, added int) (string, error) {
	dir := filepath.Join(s.Root, "corpus")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	name := filepath.Join(dir, fmt.Sprintf("seed_%04d_bb%d", len(s.seen), added))
	return name, os.WriteFile(name, data, 0o644)
}

// SaveCrash пишет байты, которые уронили цель, и рядом crashN.log со снимком.
func (s *Store) SaveCrash(data []byte, crash *Crash, change string) (string, error) {
	dir := filepath.Join(s.Root, "crashes")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	base := filepath.Join(dir, fmt.Sprintf("crash%d", s.crashN))
	s.crashN++
	if err := os.WriteFile(base, data, 0o644); err != nil {
		return "", err
	}
	if err := os.WriteFile(base+".log", []byte(crash.LogText(change)), 0o644); err != nil {
		return "", err
	}
	return base, nil
}

func loadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o644)
}

// cloneBytes отделяет копию от буфера, от которого считаются следующие мутации.
func cloneBytes(b []byte) []byte {
	out := make([]byte, len(b))
	copy(out, b)
	return out
}
